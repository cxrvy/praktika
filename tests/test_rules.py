"""Автотесты правил: «5 неудачных входов за 10 минут» и «Вход в нерабочее время».

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


if __name__ == "__main__":
    unittest.main()
