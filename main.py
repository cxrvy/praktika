"""Помощник SOC: мониторинг журнала Windows Security (консольная версия).

Окно с интерфейсом: python gui.py

Примеры:
    python main.py                          # тестовые события из events.json
    python main.py --source windows         # журнал Security за последние 24 ч (нужен администратор)
    python main.py --source windows --follow   # непрерывный мониторинг
    python main.py --no-ai                  # без обращения к Ollama
    python main.py --learned                # показать выученные адреса входа
    python main.py --forget-learned         # забыть все выученные адреса (инциденты остаются)
    python main.py --mark 5 false           # отметить инцидент №5 как ложное срабатывание
    python main.py --stats                  # статистика правил: сколько ложных
    python main.py --report                 # HTML-отчёт за неделю в папку reports
"""
import argparse
import sys
from pathlib import Path

import ai
import report
import rules
import storage
from assistant import Assistant

BASE = Path(__file__).resolve().parent


def parse_args():
    p = argparse.ArgumentParser(description="Помощник SOC: мониторинг журнала Windows")
    p.add_argument("--source", choices=["json", "windows"], default="json",
                   help="откуда брать события (по умолчанию тестовый JSON)")
    p.add_argument("--file", default=str(BASE / "events.json"), help="путь к тестовому JSON")
    p.add_argument("--db", default=str(BASE / "incidents.db"), help="путь к базе инцидентов")
    p.add_argument("--hours", type=float, default=24,
                   help="за сколько часов читать журнал Windows при первом запуске")
    p.add_argument("--follow", action="store_true", help="непрерывный мониторинг")
    p.add_argument("--interval", type=int, default=15, help="пауза между проверками, сек")
    p.add_argument("--no-ai", action="store_true", help="не обращаться к Ollama")
    learned = p.add_mutually_exclusive_group()
    learned.add_argument("--mark", nargs=2, metavar=("НОМЕР", "ОТМЕТКА"),
                         help="отметить инцидент: confirmed (подтверждено), false (ложное) "
                              "или clear (снять отметку), и выйти")
    learned.add_argument("--stats", action="store_true",
                         help="статистика правил: сколько инцидентов подтверждено и сколько ложных")
    learned.add_argument("--report", nargs="?", const="", metavar="ФАЙЛ",
                         help="сохранить HTML-отчёт (по умолчанию в папку reports) и выйти")
    p.add_argument("--days", type=int, default=7,
                   help="за сколько дней отчёт (0 - за всё время); неделя заканчивается "
                        "днём последнего инцидента")
    learned.add_argument("--learned", nargs="?", const="", metavar="УЧЁТНАЯ_ЗАПИСЬ",
                         help="показать выученные адреса входа (всех или одной учётной записи) и выйти")
    learned.add_argument("--forget-learned", nargs="?", const="", metavar="УЧЁТНАЯ_ЗАПИСЬ",
                         help="забыть выученные адреса (все или одной учётной записи) и выйти; "
                              "инциденты остаются")
    return p.parse_args()


def show_learned(db, user):
    rows = storage.list_known_logins(db, user)
    if not rows:
        print(f"Для учётной записи {user} выученных адресов нет." if user
              else "Выученных адресов входа пока нет.")
        return
    print(f"{'Учётная запись':<16} {'IP':<16} {'Входов':>6}  {'Первый вход':<19}  {'Последний вход':<19}")
    for username, ip, first, last, count in rows:
        print(f"{username:<16} {ip:<16} {count:>6}  {first:<19}  {last:<19}")
    print(f"Всего адресов: {len(rows)}, учётных записей: {len({r[0] for r in rows})}.")
    print(f"Порог обучения NEW_IP_MIN_LOGINS = {rules.NEW_IP_MIN_LOGINS}: пока у учётной записи "
          "меньше известных входов, правило «Вход с нового IP» для неё молчит.")


MARKS = {"confirmed": "confirmed", "false": "false_positive", "clear": None}


def mark(db, number, value):
    if value not in MARKS or not number.isdigit():
        print("[ОШИБКА] Пример: --mark 5 false. Отметки: confirmed, false, clear.")
        return 1
    row = db.execute("SELECT title FROM incidents WHERE id = ?", (int(number),)).fetchone()
    if not row:
        print(f"[ОШИБКА] Инцидента №{number} нет в базе.")
        return 1
    storage.set_verdict(db, int(number), MARKS[value])
    label = storage.VERDICTS.get(MARKS[value], "без отметки")
    print(f"Инцидент №{number} «{row[0]}»: {label}.")
    return 0


def forget_learned(db, user):
    removed = storage.forget_known_logins(db, user)
    whom = f"учётной записи {user}" if user else "всех учётных записей"
    print(f"Забыто выученных адресов {whom}: {removed}. Инциденты в базе сохранены.")


def print_event(kind, data):
    if kind == "log":
        prefix = f"[{data['tag']}] " if data["tag"] else ("[ОШИБКА] " if data["level"] == "error" else "")
        print(prefix + data["text"])
    elif kind == "incident":
        inc = data["inc"]
        if data["status"] == "updated":
            print(f"[UPDATE #{data['id']}] {inc['title']} | {inc['entity']} | "
                  f"событий: {inc['event_count']} (атака продолжается)")
            return
        print(f"\n[ALERT #{data['id']}] Риск: {inc['severity']} | {inc['title']}")
        print(f"  Период: {inc['first_seen']:%Y-%m-%d %H:%M:%S} — {inc['last_seen']:%H:%M:%S}"
              f" | событий: {inc['event_count']}")
        print(f"  {inc['description']}")
        print("\n  Проверки для аналитика:")
        for line in storage.format_checks(inc["checks"]).splitlines():
            print(f"  {line}")
    elif kind == "ai":
        if data["text"]:
            print(f"\n[Ollama / {ai.MODEL}] Дополнительное пояснение (подсказка, не вывод):\n{data['text']}")
        else:
            print(f"\n[AI] Пояснение отброшено после {data['attempts']} попыток: "
                  f"{'; '.join(data['warnings'])}. Используйте проверки выше.")


def main():
    sys.stdout.reconfigure(errors="replace")
    args = parse_args()
    if args.mark or args.stats or args.report is not None:
        db = storage.connect(args.db)
        try:
            if args.mark:
                return mark(db, *args.mark)
            if args.stats:
                print("\n".join(storage.format_rule_stats(storage.rule_stats(db))))
            else:
                path = report.save(db, args.report or None, days=args.days or None)
                print(f"Отчёт сохранён: {path}")
            return 0
        finally:
            db.close()
    if args.learned is not None or args.forget_learned is not None:
        db = storage.connect(args.db)
        if args.learned is not None:
            show_learned(db, args.learned)
        else:
            forget_learned(db, args.forget_learned)
        db.close()
        return 0
    assistant = Assistant(args.db, use_ai=not args.no_ai, notify=print_event)
    try:
        if args.source == "windows":
            if args.follow:
                print(f"Непрерывный мониторинг журнала Security (каждые {args.interval} с). "
                      "Ctrl+C — остановить.")
            assistant.run_windows(args.hours, args.follow, args.interval)
        else:
            if args.follow:
                print("Ctrl+C — остановить.")
            assistant.run_json(args.file, args.follow, args.interval)
    except (PermissionError, RuntimeError) as exc:
        print(f"[ОШИБКА] {exc}")
        assistant.close()
        return 1
    except KeyboardInterrupt:
        print("\nМониторинг остановлен.")
    print("\n".join(assistant.summary()))
    assistant.close()
    print(f"Результат сохранён в {args.db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
