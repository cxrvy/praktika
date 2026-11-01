"""Проверка правила «5 неудачных входов за 10 минут» на двух наборах из задания.

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


if __name__ == "__main__":
    unittest.main()
