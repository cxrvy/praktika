"""Автотесты правил: «5 неудачных входов за 10 минут», «Вход в нерабочее время»
и «Вход с нового IP» (обучение на истории входов).

Запуск из папки проекта:  python -m unittest -v
"""
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import rules    # noqa: E402
import sources  # noqa: E402
import storage  # noqa: E402


def brute_force(events):
    return [i for i in rules.detect(events) if i["rule"] == "brute_force"]


def failures(start, step):
    """5 неудачных входов с одного IP, начиная со start, с шагом step."""
    data = {"IpAddress": "192.0.2.10", "TargetUserName": "admin", "LogonType": "10"}
    return [sources.normalize(n, start + step * n, 4625, data) for n in range(5)]


def off_hours(events):
    return [i for i in rules.detect(events) if i["rule"] == "off_hours_login"]


def login(time, user="petrova", logon_type="10", event_id=4624):
    """Один вход с IP 198.51.100.23 в указанное время."""
    data = {"IpAddress": "198.51.100.23", "TargetUserName": user, "LogonType": logon_type}
    return sources.normalize(1, time, event_id, data)


class TestTaskDatasets(unittest.TestCase):
    def test_attack_in_a_row_detected(self):
        """Набор 1: 5 ошибок подряд (раз в минуту) - инцидент HIGH."""
        found = brute_force(sources.read_json(HERE / "attack_burst.json"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "HIGH")
        self.assertEqual(found[0]["event_count"], 5)
        self.assertEqual(found[0]["ip"], "192.0.2.10")

    def test_same_failures_spread_over_day_ignored(self):
        """Набор 2: те же 5 ошибок, растянутые на день (раз в 2 часа) - инцидента нет."""
        events = sources.read_json(HERE / "attack_spread_day.json")
        self.assertEqual(len(events), 5)
        self.assertEqual(brute_force(events), [])


class TestWindowBoundary(unittest.TestCase):
    start = datetime(2026, 10, 26, 10, 0, 0)

    def test_five_failures_within_10_minutes(self):
        # первая и пятая попытки разделены 9 мин 56 с - укладываются в окно
        self.assertEqual(len(brute_force(failures(self.start, timedelta(seconds=149)))), 1)

    def test_five_failures_exactly_10_minutes(self):
        # ровно 10 минут между первой и пятой - граница включается в окно
        self.assertEqual(len(brute_force(failures(self.start, timedelta(seconds=150)))), 1)

    def test_five_failures_over_10_minutes(self):
        # 10 мин 4 с - уже не укладываются в окно
        self.assertEqual(brute_force(failures(self.start, timedelta(seconds=151))), [])

    def test_four_failures_not_enough(self):
        self.assertEqual(brute_force(failures(self.start, timedelta(minutes=1))[:4]), [])


class TestOffHoursDatasets(unittest.TestCase):
    def test_night_login_detected(self):
        """Набор 3: два входа по RDP ночью (23:47 и 00:20) - один инцидент MEDIUM."""
        found = off_hours(sources.read_json(HERE / "off_hours_night.json"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "MEDIUM")
        self.assertEqual(found[0]["event_count"], 2)
        self.assertEqual(found[0]["user"], "petrova")

    def test_same_login_in_daytime_ignored(self):
        """Набор 4: те же входы днём во вторник - инцидента нет."""
        events = sources.read_json(HERE / "off_hours_day.json")
        self.assertEqual(len(events), 2)
        self.assertEqual(off_hours(events), [])


class TestOffHoursBoundary(unittest.TestCase):
    tuesday = datetime(2026, 10, 27)
    saturday = datetime(2026, 10, 31)

    def at(self, day, hour, minute=0):
        return off_hours([login(day.replace(hour=hour, minute=minute))])

    def test_work_hours_boundaries(self):
        self.assertEqual(len(self.at(self.tuesday, 7, 59)), 1)   # 07:59 - ещё нерабочее
        self.assertEqual(self.at(self.tuesday, 8, 0), [])         # 08:00 - рабочее
        self.assertEqual(self.at(self.tuesday, 19, 59), [])       # 19:59 - рабочее
        self.assertEqual(len(self.at(self.tuesday, 20, 0)), 1)   # 20:00 - уже нерабочее

    def test_weekend_daytime_detected(self):
        self.assertEqual(len(self.at(self.saturday, 12, 0)), 1)

    def test_different_nights_are_separate_incidents(self):
        events = [login(datetime(2026, 10, 27, 23, 0)), login(datetime(2026, 10, 28, 23, 0))]
        self.assertEqual(len(off_hours(events)), 2)

    def test_only_successful_remote_logins(self):
        night = self.tuesday.replace(hour=2)
        self.assertEqual(off_hours([login(night, event_id=4625)]), [])     # неудачный вход
        self.assertEqual(off_hours([login(night, logon_type="2")]), [])    # локальный вход
        self.assertEqual(len(off_hours([login(night, logon_type="3")])), 1)  # вход по сети

    def test_allowed_users_ignored(self):
        night = self.tuesday.replace(hour=2)
        old = rules.OFF_HOURS_ALLOWED_USERS
        rules.OFF_HOURS_ALLOWED_USERS = {"svc_backup"}
        try:
            self.assertEqual(off_hours([login(night, user="svc_backup")]), [])
            self.assertEqual(len(off_hours([login(night, user="petrova")])), 1)
        finally:
            rules.OFF_HOURS_ALLOWED_USERS = old


def new_ip(events, known=None):
    return [i for i in rules.detect(events, known or {}) if i["rule"] == "new_ip_login"]


def day_login(hour, ip, user="orlova"):
    """Вход по RDP во вторник днём, чтобы не мешало правило нерабочего времени."""
    data = {"IpAddress": ip, "TargetUserName": user, "LogonType": "10"}
    return sources.normalize(1, datetime(2026, 10, 27, hour), 4624, data)


class TestNewIpDatasets(unittest.TestCase):
    def test_new_ip_detected(self):
        """Набор 5: три входа с 10.0.0.31, затем вход с 203.0.113.77 - инцидент MEDIUM."""
        found = new_ip(sources.read_json(HERE / "new_ip.json"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "MEDIUM")
        self.assertEqual(found[0]["ip"], "203.0.113.77")
        self.assertIn("10.0.0.31", found[0]["description"])

    def test_usual_ip_ignored(self):
        """Набор 6: четвёртый вход с того же 10.0.0.31 - инцидента нет."""
        self.assertEqual(new_ip(sources.read_json(HERE / "known_ip.json")), [])


class TestNewIpLearning(unittest.TestCase):
    def test_learning_period_no_alerts(self):
        # пока известно меньше NEW_IP_MIN_LOGINS входов, программа только учится
        events = [day_login(9, "10.0.0.31"), day_login(10, "10.0.0.31"), day_login(11, "203.0.113.77")]
        self.assertEqual(new_ip(events), [])

    def test_repeated_new_ip_is_one_incident(self):
        usual = [day_login(h, "10.0.0.31") for h in (9, 10, 11)]
        self.assertEqual(len(new_ip(usual + [day_login(12, "203.0.113.77"), day_login(13, "203.0.113.77")])), 1)

    def test_user_names_case_insensitive(self):
        known = {"orlova": {"10.0.0.31": 5}}
        self.assertEqual(new_ip([day_login(9, "10.0.0.31", user="ORLOVA")], known), [])

    def test_knowledge_saved_between_runs(self):
        db = storage.connect(":memory:")
        first_run = [day_login(h, "10.0.0.31") for h in (9, 10, 11)]
        storage.remember_logins(db, first_run)
        self.assertEqual(storage.load_known_logins(db), {"orlova": {"10.0.0.31": 3}})
        # повторная проверка тех же событий не раздувает счётчики
        storage.remember_logins(db, first_run)
        self.assertEqual(storage.load_known_logins(db), {"orlova": {"10.0.0.31": 3}})
        # второй запуск: обычный адрес - тихо, новый - инцидент
        known = storage.load_known_logins(db)
        self.assertEqual(new_ip([day_login(14, "10.0.0.31")], known), [])
        self.assertEqual(len(new_ip([day_login(15, "203.0.113.77")], known)), 1)
        db.close()


if __name__ == "__main__":
    unittest.main()
