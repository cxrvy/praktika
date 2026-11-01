"""Дополнительные пояснения к инцидентам от локальной модели Ollama.

Основной результат для аналитика - правило и фиксированный список проверок (rules.PLAYBOOKS).
Модель только поясняет инцидент простыми словами и не заменяет проверки.

Как повышается качество ответа маленькой модели:
1. модели объясняется суть правила (rules.RULE_ABOUT);
2. в запрос включён образец хорошего ответа (few-shot);
3. ответ строго по JSON-схеме - три обязательных поля;
4. ответ проверяется автоматически; при ошибках - одна повторная попытка
   с указанием ошибок, затем плохой ответ отбрасывается.
"""
import json
import os
import re

import requests

from rules import RULE_ABOUT

OLLAMA_URL = "http://localhost:11434"
# Выбрана по сравнению на тестовых инцидентах (llama3.2:3b, qwen3:4b, qwen2.5:7b, gemma3:4b):
# лучший русский язык и меньше всего ошибок в фактах; помещается в видеокарту на 4 ГБ.
MODEL = "gemma3:4b"
MAX_ATTEMPTS = 2
MAX_WORDS = 90
# Сколько слоёв модели держать в видеокарте. Если видеопамять занята другими программами
# (браузер, мессенджеры), Ollama грузит слишком много слоёв и работает в разы медленнее.
# Пусто - решает Ollama; SOC_NUM_GPU=20 - стабильно для GTX 970 4 ГБ; 0 - только процессор.
NUM_GPU = os.environ.get("SOC_NUM_GPU")

FIELDS = {
    "explanation": "Пояснение",
    "not_proven": "Что не доказано",
    "attention": "На что обратить внимание",
}

SCHEMA = {
    "type": "object",
    "properties": {name: {"type": "string"} for name in FIELDS},
    "required": list(FIELDS),
}

SYSTEM_PROMPT = """Ты помощник аналитика SOC первой линии. Пишешь ТОЛЬКО на русском языке,
без английских слов (кроме названий: IP, RDP, Windows, Event ID, SOC и имён из фактов).
Аналитик уже получил готовый список проверок - НЕ повторяй его.
Твоя задача - коротко и конкретно пояснить инцидент. Ответ - JSON с полями:
  explanation - 2 предложения: что произошло (с конкретными IP, учётными записями, числами
                из фактов) и чем это может быть опасно;
  not_proven  - 1 предложение: что из фактов НЕ следует;
  attention   - 1 предложение: деталь из фактов, которую легко упустить и которой нет в проверках.
Правила: опирайся только на переданные факты, ничего не выдумывай, не пиши общих фраз.
Внимательно различай, КТО выполнил действие и НАД КЕМ (поля «Описание» и «учётная запись»).
Не упоминай коды ошибок и номера событий, которых нет в примерах событий.
Первый ответ в диалоге - образец стиля для другого инцидента: не копируй его формулировки.
Используй осторожные формулировки («возможно», «может указывать»).
Не утверждай, что атака доказана или пароль подобран. Не предлагай автоматическую блокировку.
Всего не больше 70 слов."""

# Образец: вымышленный инцидент другого типа, чтобы модель переняла стиль, а не текст
EXAMPLE_FACTS = """Правило: Вход в нерабочее время
Суть правила: Успешный вход ночью может означать, что учётной записью пользуется посторонний.
Критичность по правилу: MEDIUM
Описание: Учётная запись kassir2 вошла по RDP в 03:12 с IP 203.0.113.44.
Период: 2026-03-14 03:12:05 — 03:12:05
Количество событий: 1
Примеры событий:
- 03:12:05 Event ID 4624, IP: 203.0.113.44, учётная запись: kassir2, тип входа: 10, узел: -
Проверки, которые аналитик уже получил (не повторяй их):
- Уточнить у владельца учётной записи, входил ли он ночью.
- Проверить, с каких IP эта учётная запись входила раньше."""

EXAMPLE_ANSWER = {
    "explanation": "Учётная запись kassir2 в 03:12 вошла по RDP (тип входа 10) с IP 203.0.113.44. "
                   "Для кассира ночной удалённый вход нетипичен и может указывать на использование "
                   "учётной записи посторонним.",
    "not_proven": "Из одного события не следует, что вход выполнил не сам владелец — он мог "
                  "работать удалённо.",
    "attention": "Тип входа 10 означает удалённый рабочий стол, то есть RDP на этом компьютере "
                 "доступен с адреса 203.0.113.44.",
}

ALLOWED_LATIN = {"ip", "rdp", "smb", "windows", "event", "id", "soc", "siem", "dhcp", "powershell", "json"}
HEDGES = r"возможн|может|вероятн|не доказ|не следует|не подтвержд|нет данных|неизвестн|не известн|не исключ"
CATEGORICAL = r"доказан|подобрал|подобран|взлома[лн]|\bточно\b"


def check_available():
    """Возвращает None, если Ollama запущена и модель скачана, иначе текст причины."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        r.raise_for_status()
    except requests.RequestException as exc:
        return f"Ollama не отвечает ({exc.__class__.__name__}). Запустите Ollama."
    models = {m.get("name") for m in r.json().get("models", [])}
    if MODEL not in models:
        return f"Модель {MODEL} не скачана. Выполните: ollama pull {MODEL}"
    return None


def _facts_only(inc):
    """Факты об инциденте без списка проверок."""
    lines = [
        f"Правило: {inc['title']}",
        f"Суть правила: {RULE_ABOUT[inc['rule']]}",
        f"Критичность по правилу: {inc['severity']}",
        f"Описание: {inc['description']}",
        f"Период: {inc['first_seen']:%Y-%m-%d %H:%M:%S} — {inc['last_seen']:%H:%M:%S}",
        f"Количество событий: {inc['event_count']}",
        "Примеры событий:",
    ]
    for e in inc["samples"]:
        lines.append(
            f"- {e['time']:%H:%M:%S} Event ID {e['event_id']}, "
            f"IP: {e['ip'] or '-'}, учётная запись: {e['user'] or '-'}, "
            f"тип входа: {e['logon_type'] or '-'}, узел: {e['host'] or '-'}"
            + (f", действие выполнил: {e['subject_user']}" if e["subject_user"] else "")
            + (f", группа: {e['group']}" if e.get("group") else ""))
    return "\n".join(lines)


def _facts(inc):
    """Факты и готовые проверки - то, что отправляется модели.

    Из проверок берётся только суть (до двоеточия): коды ошибок и номера событий
    оттуда модель иначе выдаёт за произошедшее.
    """
    checks = [f"- {c.split(':')[0].strip()}" for c in inc["checks"]]
    return "\n".join([_facts_only(inc), "Проверки, которые аналитик уже получил (не повторяй их):", *checks])


def _chat(messages):
    payload = {
        "model": MODEL,
        "stream": False,
        "format": SCHEMA,
        "options": {"temperature": 0.1},
        "messages": messages,
    }
    if NUM_GPU:
        payload["options"]["num_gpu"] = int(NUM_GPU)
    r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=300)
    r.raise_for_status()
    return r.json().get("message", {}).get("content", "").strip()


def render(answer):
    return "\n".join(f"{title}: {answer[name].strip()}" for name, title in FIELDS.items())


def analyze(inc):
    """Возвращает (текст пояснения или None, список замечаний, число попыток).

    None означает, что модель так и не дала приемлемый ответ - его не показываем,
    аналитику достаточно правила и списка проверок.
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Факты об инциденте:\n" + EXAMPLE_FACTS},
        {"role": "assistant", "content": json.dumps(EXAMPLE_ANSWER, ensure_ascii=False)},
        {"role": "user", "content": "Факты об инциденте:\n" + _facts(inc)},
    ]
    warnings = []
    for attempt in range(1, MAX_ATTEMPTS + 1):
        raw = _chat(messages)
        try:
            answer = json.loads(raw)
        except json.JSONDecodeError:
            answer = None
            warnings = ["ответ не является JSON"]
        else:
            warnings = quality_warnings(answer, inc)
        if not warnings:
            return render(answer), [], attempt
        messages += [
            {"role": "assistant", "content": raw},
            {"role": "user", "content": "В ответе ошибки: " + "; ".join(warnings)
             + ". Исправь их и верни JSON заново, соблюдая все правила."},
        ]
    return None, warnings, MAX_ATTEMPTS


def quality_warnings(answer, inc):
    """Автоматические проверки ответа модели. Возвращает список замечаний."""
    if not isinstance(answer, dict):
        return ["ответ должен быть JSON-объектом с полями " + ", ".join(FIELDS)]
    missing = [FIELDS[n] for n in FIELDS if not str(answer.get(n, "")).strip()]
    if missing:
        return ["пустые поля: " + ", ".join(missing)]
    text = " ".join(str(answer[n]) for n in FIELDS)
    warnings = []
    # Японская кана, китайские иероглифы и корейский хангыль (U+3040–30FF, U+3400–9FFF, U+AC00–D7AF)
    if re.search("[぀-ヿ㐀-鿿가-힯]", text):
        warnings.append("есть иероглифы")
    # Латиница допустима для названий и для значений из самих фактов (логины, узлы)
    foreign = {w for w in re.findall(r"[A-Za-z_]+", text)
               if len(w) >= 3 and w.lower() not in ALLOWED_LATIN and w.lower() not in _fact_words(inc)}
    if foreign:
        warnings.append("английские слова: " + ", ".join(sorted(foreign)[:5]))
    unknown_ips = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)) - set(
        re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", _facts(inc)))
    if unknown_ips:
        warnings.append("IP-адреса, которых нет в фактах: " + ", ".join(sorted(unknown_ips)))
    unknown_codes = set(re.findall(r"0x[0-9A-Fa-f]+", text)) - set(re.findall(r"0x[0-9A-Fa-f]+", _facts_only(inc)))
    if unknown_codes:
        warnings.append("коды ошибок, которых нет в фактах: " + ", ".join(sorted(unknown_codes)))
    unknown_events = set(re.findall(r"\b4\d{3}\b|\b1102\b", text)) - {str(e["event_id"]) for e in inc["samples"]}
    if unknown_events:
        warnings.append("упомянуты события, которых нет в фактах: " + ", ".join(sorted(unknown_events))
                        + " (это проверки аналитика, а не произошедшие события)")
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if re.search(CATEGORICAL, sentence, re.I) and not re.search(HEDGES, sentence, re.I):
            warnings.append(f"категоричное утверждение без оговорки: «{sentence.strip()[:80]}»")
            break
    attention = _stems(answer["attention"])
    for check in map(_stems, inc["checks"]):
        common = len(attention & check)
        if attention and check and max(common / len(attention), common / len(check)) >= 0.5:
            warnings.append("поле attention повторяет готовую проверку — нужна другая деталь из фактов")
            break
    if len(text.split()) > MAX_WORDS:
        warnings.append(f"слишком длинно ({len(text.split())} слов, нужно до 70)")
    return warnings


def _stems(text):
    """Грубые основы слов (первые 5 букв) для сравнения фраз без учёта окончаний."""
    return {w.lower()[:5] for w in re.findall(r"\w{4,}", text)}


def _fact_words(inc):
    values = [inc["entity"], inc["ip"], inc["user"], inc["description"], *inc["checks"]]
    for e in inc["samples"]:
        values += [e["user"], e["host"], e["subject_user"], e.get("group")]
    return {w.lower() for v in values if v for w in re.findall(r"[A-Za-z_]+", str(v))}
