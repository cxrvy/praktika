"""Ядро помощника: чтение событий, правила, сохранение, AI-пояснения.

Не печатает ничего само - сообщает о происходящем через функцию notify(kind, data).
Так одно и то же ядро используют консоль (main.py) и окно (gui.py).

Виды сообщений:
    "log"      - {"level": "info" | "warning" | "error", "tag": str | None, "text": str}
    "incident" - {"id", "inc", "status": "new" | "updated"}
    "ai"       - {"id", "inc", "text": str | None, "warnings": list, "attempts": int}
"""
import threading
from collections import Counter
from pathlib import Path

import requests

import ai
import rules
import sources
import storage

STATE_KEY = "windows_last_record_id"


class Assistant:
    def __init__(self, db_path, use_ai=True, notify=None, stop_event=None):
        self.db_path = str(db_path)
        self.db = storage.connect(db_path)
        self.notify = notify or (lambda kind, data: None)
        self.stop_event = stop_event or threading.Event()
        self.stats = Counter()
        self.ai_problem = None if use_ai else "AI-пояснения отключены"
        if use_ai:
            self.ai_problem = ai.check_available()
            if self.ai_problem:
                self.log("warning", self.ai_problem, tag="AI НЕ ДОСТУПЕН")
                self.log("warning", "Правила продолжат работать, инциденты сохранятся без AI-пояснений.")

    def log(self, level, text, tag=None):
        self.notify("log", {"level": level, "tag": tag, "text": text})

    def close(self):
        self.db.close()

    def stopped(self, wait=0):
        """Пауза между проверками, которую можно прервать кнопкой «Стоп» или Ctrl+C."""
        # Короткими шагами: в Windows долгое ожидание события не прерывается по Ctrl+C
        for _ in range(max(1, int(wait * 2))):
            if self.stop_event.wait(min(wait, 0.5)):
                return True
        return False

    # ---------- обработка инцидентов ----------

    def check(self, events):
        """Правила с учётом изученных входов, затем запоминание новых входов.

        Порядок важен: сначала сравнить с тем, что уже известно, и только потом выучить.
        """
        known = storage.load_known_logins(self.db)
        self.handle(rules.detect(events, known))
        storage.remember_logins(self.db, events)

    def handle(self, incidents):
        for inc in incidents:
            if self.stopped():
                return
            inc_id, status = storage.save_incident(self.db, inc)
            self.stats[status] += 1
            if status == "duplicate":
                continue
            if status == "new":
                self.stats[inc["severity"]] += 1
            self.notify("incident", {"id": inc_id, "inc": inc, "status": status})
            if status == "new":
                self.explain(inc_id, inc)

    def explain(self, inc_id, inc):
        if self.ai_problem:
            return
        try:
            text, warnings, attempts = ai.analyze(inc)
        except requests.RequestException as exc:
            self.log("error", f"Правило сработало, но AI-пояснение не получено. Причина: {exc}",
                     tag="AI НЕ ДОСТУПЕН")
            return
        self.stats["ai_attempts"] += attempts
        self.stats["ai_ok" if text else "ai_rejected"] += 1
        if text:
            storage.set_ai_analysis(self.db, inc_id, text)
        self.notify("ai", {"id": inc_id, "inc": inc, "text": text, "warnings": warnings, "attempts": attempts})

    def summary(self):
        """Итоги работы в виде строк."""
        s = self.stats
        users, ips = storage.known_logins_stats(self.db)
        learned = f"Изучено обычных адресов входа: {ips} (учётных записей: {users})."
        if not s["new"] and not s["updated"]:
            lines = ["Новых подозрительных событий не найдено."]
            if s["duplicate"]:
                lines.append(f"(Уже известных инцидентов: {s['duplicate']} — повторно не сохранены.)")
            return lines + [learned]
        by_sev = ", ".join(f"{sev}: {s[sev]}" for sev in reversed(rules.SEVERITY_ORDER) if s[sev])
        lines = [f"Итого новых инцидентов: {s['new']} ({by_sev or '—'}); обновлено: {s['updated']}; "
                 f"повторов пропущено: {s['duplicate']}"]
        if s["ai_ok"] or s["ai_rejected"]:
            lines.append(f"AI-пояснений: принято {s['ai_ok']}, отброшено {s['ai_rejected']} "
                         f"(запросов к модели: {s['ai_attempts']})")
        return lines + [learned]

    # ---------- источники ----------

    def run_json(self, path, follow=False, interval=15):
        path = Path(path)

        def check():
            events = sources.read_json(path)
            self.log("info", f"Прочитано событий из {path.name}: {len(events)}")
            self.check(events)

        check()
        if not follow:
            return
        self.log("info", f"Слежу за файлом {path} (каждые {interval} с).")
        last_mtime = path.stat().st_mtime
        while not self.stopped(interval):
            mtime = path.stat().st_mtime
            if mtime != last_mtime:
                last_mtime = mtime
                check()

    def run_windows(self, hours=24, follow=False, interval=15):
        saved = storage.get_state(self.db, STATE_KEY)
        if follow and saved:
            after, since = int(saved), None
            self.log("info", f"Продолжаю мониторинг с записи журнала №{after}.")
        else:
            after, since = None, sources.default_since(hours)
            self.log("info", f"Читаю журнал Security за последние {hours:g} ч.")

        buffer = []  # недавние события - нужны правилам со скользящим окном
        while True:
            events, last_id = sources.read_windows_log(after_record_id=after, since=since)
            if last_id is not None:
                storage.set_state(self.db, STATE_KEY, last_id)
                after, since = last_id, None
            if events or not follow:
                buffer.extend(events)
                if buffer:
                    newest = max(e["time"] for e in buffer)
                    buffer = [e for e in buffer if newest - e["time"] <= rules.WINDOW * 2]
                self.log("info", f"Получено событий: {len(events)}")
                self.check(buffer if follow else events)
            if not follow or self.stopped(interval):
                return
