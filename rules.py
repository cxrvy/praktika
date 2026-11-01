"""Правила обнаружения. Каждое правило получает список событий и возвращает инциденты.

Инцидент - словарь:
    rule, title, severity, entity, ip, user, first_seen, last_seen,
    event_count, description, samples (несколько событий для контекста)
"""
from collections import defaultdict, deque
from datetime import timedelta

WINDOW = timedelta(minutes=10)  # скользящее временное окно (по заданию: 5 неудачных входов за 10 минут)
BRUTE_FORCE_THRESHOLD = 5       # неудачных входов с одного IP за окно
SPRAY_USERS_THRESHOLD = 3       # разных учётных записей с одного IP за окно
PRIVILEGED_GROUPS = {"administrators", "администраторы",
                     "remote desktop users", "пользователи удаленного рабочего стола"}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Суть каждого правила простыми словами. Передаётся модели, чтобы она понимала,
# о какой атаке идёт речь, и не придумывала своё толкование.
RULE_ABOUT = {
    "brute_force": "Подбор пароля: злоумышленник многократно пробует пароли к одной "
                   "или нескольким учётным записям, надеясь угадать верный.",
    "password_spray": "Перебор учётных записей: злоумышленник пробует один-два "
                      "распространённых пароля на многих учётных записях, чтобы не вызвать блокировку "
                      "какой-то одной из них.",
    "success_after_bruteforce": "Успешный вход сразу после серии неудачных с того же адреса: возможно, "
                                "подбор пароля удался и злоумышленник получил доступ.",
    "account_locked": "Блокировка учётной записи: Windows блокирует её после превышения числа неверных "
                      "паролей. Причиной бывает как подбор пароля, так и старый сохранённый пароль "
                      "на устройстве пользователя.",
    "user_created": "Создание учётной записи: злоумышленники создают свои учётные записи, чтобы "
                    "сохранить доступ к системе. Часто это обычная работа администратора.",
    "added_to_group": "Добавление в группу: выдача прав. Добавление в «Администраторы» даёт полный "
                      "контроль над компьютером и типично для повышения привилегий злоумышленником.",
    "log_cleared": "Очистка журнала Security: удаляет историю событий безопасности. Злоумышленники "
                   "делают это, чтобы скрыть следы. Плановая очистка встречается редко.",
}

# Фиксированные проверки для аналитика первой линии по каждому правилу.
# Выводятся всегда, даже если AI недоступен или ошибся.
PLAYBOOKS = {
    "brute_force": [
        "Найти все события 4625 с этого IP за последние сутки и оценить масштаб попыток.",
        "Посмотреть Status/SubStatus в 4625: 0xC000006A — неверный пароль (учётная запись "
        "существует), 0xC0000064 — такой учётной записи нет.",
        "Определить источник IP: внутренний узел — найти владельца по DHCP/инвентаризации; "
        "внешний — выяснить, почему RDP/SMB доступен из интернета.",
        "Проверить, был ли после серии успешный вход 4624 с этого же IP.",
        "Связаться с владельцем учётной записи: не он ли ошибался паролем.",
    ],
    "password_spray": [
        "Составить список атакуемых учётных записей и проверить по SubStatus в 4625, "
        "какие из них существуют (0xC0000064 — не существует).",
        "Проверить успешные входы 4624 с этого IP под любой учётной записью.",
        "Проверить, атакуются ли те же учётные записи с других IP.",
        "Определить источник IP (внутренний узел или внешний адрес).",
        "Передать на вторую линию список существующих атакованных учётных записей "
        "для решения о смене паролей.",
    ],
    "success_after_bruteforce": [
        "Немедленно эскалировать на вторую линию / дежурному специалисту.",
        "Связаться с владельцем учётной записи и подтвердить, входил ли он сам в это время.",
        "Проверить действия в этом сеансе: 4672 (особые привилегии), 4688 (запуск процессов), "
        "4720/4732 (создание учётных записей, выдача прав).",
        "Проверить, активен ли сеанс сейчас (query user / qwinsta на узле).",
        "Смену пароля и отключение учётной записи согласовать с ответственным — "
        "помощник ничего не блокирует сам.",
    ],
    "account_locked": [
        "Найти источник блокировки: поле Caller Computer Name в 4740 и события 4625 на этом узле.",
        "Уточнить у пользователя, не менял ли он недавно пароль (старый пароль в телефоне, "
        "сохранённых сеансах, службах, подключённых дисках).",
        "Проверить, нет ли одновременно блокировок других учётных записей (признак перебора).",
        "Разблокировать учётную запись только после выяснения причины.",
    ],
    "user_created": [
        "Найти заявку/тикет на создание этой учётной записи.",
        "Подтвердить у создавшего пользователя, что действие выполнял он.",
        "Проверить, что произошло после создания: 4732 (добавление в группы), "
        "4624 (входы под новой учётной записью).",
        "Проверить входы создавшего пользователя перед этим событием (IP, тип входа) "
        "на признаки компрометации.",
    ],
    "added_to_group": [
        "Найти заявку на выдачу прав.",
        "Подтвердить у пользователя, выполнившего добавление, что действие выполнял он.",
        "Проверить текущий состав группы: net localgroup <имя группы>.",
        "Проверить действия добавленного пользователя после получения прав: 4624, 4672, 4688.",
    ],
    "log_cleared": [
        "Сразу эскалировать: очистка журнала аудита почти никогда не бывает плановой.",
        "Уточнить у пользователя, очистившего журнал, причину и сверить с регламентом обслуживания.",
        "Проверить другие источники за этот период: журналы System, PowerShell, копии в SIEM.",
        "Проверить входы этого пользователя перед очисткой (4624: IP, тип входа).",
    ],
}


def _incident(rule, title, severity, entity, events, description, ip=None, user=None):
    return {
        "rule": rule,
        "title": title,
        "checks": PLAYBOOKS[rule],
        "severity": severity,
        "entity": entity,
        "ip": ip,
        "user": user,
        "first_seen": events[0]["time"],
        "last_seen": events[-1]["time"],
        "event_count": len(events),
        "description": description,
        "samples": events[:3] + (events[-2:] if len(events) > 5 else []),
    }


def _group_by(events, key, event_name):
    groups = defaultdict(list)
    for e in events:
        if e["event"] == event_name and e.get(key):
            groups[e[key]].append(e)
    for items in groups.values():
        items.sort(key=lambda e: e["time"])
    return groups


def _bursts(events, triggered):
    """Делит отсортированные по времени события на «всплески».

    Всплеск начинается, когда события внутри скользящего окна удовлетворяют
    условию triggered(окно), и продолжается, пока следующие события идут
    с паузой не больше WINDOW. Так одна атака даёт один инцидент, а не десяток.
    """
    window = deque()
    burst = None
    for e in events:
        if burst is not None:
            if e["time"] - burst[-1]["time"] <= WINDOW:
                burst.append(e)
                continue
            yield burst
            burst = None
            window.clear()
        window.append(e)
        while e["time"] - window[0]["time"] > WINDOW:
            window.popleft()
        if triggered(window):
            burst = list(window)
    if burst is not None:
        yield burst


def rule_brute_force(events):
    """Много неудачных входов с одного IP за короткое время (подбор пароля)."""
    minutes = int(WINDOW.total_seconds() // 60)
    for ip, items in _group_by(events, "ip", "failed_login").items():
        for burst in _bursts(items, lambda w: len(w) >= BRUTE_FORCE_THRESHOLD):
            users = sorted({e["user"] for e in burst if e["user"]})
            yield _incident(
                "brute_force", "Подбор пароля", "HIGH", ip, burst,
                f"{len(burst)} неудачных входов с IP {ip} (порог: {BRUTE_FORCE_THRESHOLD} "
                f"за {minutes} мин). Учётные записи: {', '.join(users) or 'не указаны'}.",
                ip=ip, user=users[0] if len(users) == 1 else None)


def rule_password_spray(events):
    """С одного IP перебираются разные учётные записи (password spraying)."""
    def many_users(window):
        return len({e["user"] for e in window if e["user"]}) >= SPRAY_USERS_THRESHOLD

    for ip, items in _group_by(events, "ip", "failed_login").items():
        for burst in _bursts(items, many_users):
            users = sorted({e["user"] for e in burst if e["user"]})
            yield _incident(
                "password_spray", "Перебор учётных записей", "HIGH", ip, burst,
                f"С IP {ip} были неудачные попытки входа в {len(users)} разных учётных "
                f"записей: {', '.join(users)}.",
                ip=ip)


def rule_success_after_failures(events):
    """Успешный вход с IP, с которого только что шёл подбор пароля."""
    failures = _group_by(events, "ip", "failed_login")
    for ip, successes in _group_by(events, "ip", "success_login").items():
        for s in successes:
            before = [f for f in failures.get(ip, []) if s["time"] - WINDOW <= f["time"] <= s["time"]]
            if len(before) >= BRUTE_FORCE_THRESHOLD:
                yield _incident(
                    "success_after_bruteforce", "Успешный вход после подбора пароля", "CRITICAL",
                    f"{ip}|{s['user']}", before + [s],
                    f"После {len(before)} неудачных попыток с IP {ip} выполнен успешный вход "
                    f"под учётной записью {s['user']} (тип входа {s['logon_type'] or '?'}). "
                    f"Возможно, пароль подобран.",
                    ip=ip, user=s["user"])


def rule_single_events(events):
    """События, важные сами по себе: блокировка, новая учётка, группа, очистка журнала."""
    for e in events:
        if e["event"] == "account_locked":
            yield _incident("account_locked", "Учётная запись заблокирована", "MEDIUM",
                            e["user"] or "?", [e],
                            f"Учётная запись {e['user']} заблокирована после неудачных входов "
                            f"(источник: {e['host'] or 'не указан'}).", user=e["user"])
        elif e["event"] == "user_created":
            yield _incident("user_created", "Создана учётная запись", "MEDIUM",
                            e["user"] or "?", [e],
                            f"Пользователь {e['subject_user'] or '?'} создал учётную запись "
                            f"{e['user']}. Проверьте, была ли это плановая операция.", user=e["user"])
        elif e["event"] == "added_to_group":
            group = e.get("group") or "?"
            privileged = group.lower() in PRIVILEGED_GROUPS
            yield _incident("added_to_group", "Добавление в группу",
                            "HIGH" if privileged else "MEDIUM",
                            f"{e['user'] or '?'}|{group}", [e],
                            f"Пользователь {e['subject_user'] or '?'} добавил {e['user'] or '?'} "
                            f"в группу «{group}»" + (" (привилегированная группа)." if privileged else "."),
                            user=e["user"])
        elif e["event"] == "log_cleared":
            yield _incident("log_cleared", "Очищен журнал аудита", "HIGH",
                            e["subject_user"] or e["host"] or "?", [e],
                            f"Журнал Security очищен пользователем {e['subject_user'] or '?'}. "
                            f"Злоумышленники так скрывают следы.", user=e["subject_user"])


RULES = [rule_brute_force, rule_password_spray, rule_success_after_failures, rule_single_events]


def detect(events):
    events = sorted(events, key=lambda e: e["time"])
    incidents = [inc for rule in RULES for inc in rule(events)]
    incidents.sort(key=lambda i: (i["first_seen"], -SEVERITY_ORDER.index(i["severity"])))
    return incidents
