"""Автотесты: правила «5 неудачных входов за 10 минут», «Вход в нерабочее время»,
«Вход с нового IP» (обучение), цепочка атаки, MITRE, отметки аналитика и отчёт.

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


class TestOffHoursWeekdayAndNight(unittest.TestCase):
    """Один и тот же вход по RDP: в будний день в 15:00 - норма, в воскресенье или в 02:00 - инцидент."""

    def test_weekday_15_00_no_incident(self):
        tuesday_15 = datetime(2026, 10, 27, 15, 0)
        self.assertEqual(off_hours([login(tuesday_15)]), [])

    def test_sunday_or_02_00_incident(self):
        sunday_15 = datetime(2026, 11, 1, 15, 0)
        tuesday_02 = datetime(2026, 10, 27, 2, 0)
        for when in (sunday_15, tuesday_02):
            with self.subTest(when=f"{rules.WEEKDAY_NAMES[when.weekday()]} {when:%H:%M}"):
                found = off_hours([login(when)])
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["severity"], "MEDIUM")


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


class TestNewIpVsKnownIp(unittest.TestCase):
    def test_new_ip_vs_known_ip(self):
        """При одной и той же истории (3 входа с 10.0.0.31): вход с 10.0.0.31 - тихо,
        вход с 203.0.113.77 - инцидент «Вход с нового IP»."""
        known = {"orlova": {"10.0.0.31": 3}}
        self.assertEqual(new_ip([day_login(14, "10.0.0.31")], known), [])
        found = new_ip([day_login(14, "203.0.113.77")], known)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["ip"], "203.0.113.77")


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

    def test_view_and_forget_learned(self):
        db = storage.connect(":memory:")
        storage.remember_logins(db, [day_login(9, "10.0.0.31"), day_login(10, "10.0.0.31", user="kozlov")])
        self.assertEqual([r[:2] for r in storage.list_known_logins(db)],
                         [("kozlov", "10.0.0.31"), ("orlova", "10.0.0.31")])
        self.assertEqual(storage.forget_known_logins(db, "ORLOVA"), 1)   # одна учётная запись
        self.assertEqual(list(storage.load_known_logins(db)), ["kozlov"])
        self.assertEqual(storage.forget_known_logins(db), 1)             # все остальные
        self.assertEqual(storage.load_known_logins(db), {})
        db.close()


def scenario_db():
    """База в памяти с инцидентами из events.json."""
    db = storage.connect(":memory:")
    for inc in rules.detect(sources.read_json(HERE.parent / "events.json"), {}):
        storage.save_incident(db, inc)
    return db


def admin_events(action_delay):
    """Подбор пароля к admin, успешный вход, затем admin создаёт support_tmp и очищает журнал."""
    start = datetime(2026, 10, 27, 12, 0)
    attack = {"IpAddress": "192.0.2.10", "TargetUserName": "admin", "LogonType": "10"}
    events = [sources.normalize(n, start + timedelta(seconds=10 * n), 4625, attack) for n in range(5)]
    events.append(sources.normalize(6, start + timedelta(minutes=1), 4624, attack))
    later = start + timedelta(minutes=1) + action_delay
    events.append(sources.normalize(7, later, 4720, {"TargetUserName": "support_tmp", "SubjectUserName": "admin"}))
    events.append(sources.normalize(8, later + timedelta(minutes=5), 1102, {"SubjectUserName": "admin"}))
    return events


def chains(events):
    return [i for i in rules.detect(events) if i["rule"] == "attack_chain"]


class TestMitre(unittest.TestCase):
    def test_every_rule_has_known_technique(self):
        for rule in rules.PLAYBOOKS:
            if rule == "attack_chain":
                continue  # коды цепочки собираются из её шагов
            with self.subTest(rule=rule):
                self.assertTrue(rules.MITRE[rule])
                for code in rules.MITRE[rule]:
                    self.assertIn(code, rules.MITRE_NAMES)

    def test_mitre_saved_with_incident(self):
        db = scenario_db()
        row = db.execute("SELECT mitre FROM incidents WHERE rule = 'brute_force'").fetchone()
        self.assertEqual(row[0], "T1110.001")
        db.close()


class TestAttackChain(unittest.TestCase):
    def test_chain_in_scenarios(self):
        """events.json: подбор → вход → создание учётной записи → добавление в группу → очистка журнала."""
        found = chains(sources.read_json(HERE.parent / "events.json"))
        self.assertEqual(len(found), 1)
        chain = found[0]
        self.assertEqual((chain["severity"], chain["entity"], chain["event_count"]), ("CRITICAL", "admin", 5))
        self.assertEqual(chain["mitre"], ["T1110.001", "T1078", "T1136.001", "T1098.007", "T1070.001"])
        self.assertIn("12:01 Успешный вход после подбора пароля", chain["description"])

    def test_actions_soon_after_access_are_chained(self):
        self.assertEqual(len(chains(admin_events(timedelta(hours=2)))), 1)

    def test_actions_much_later_are_not_chained(self):
        # пауза больше CHAIN_GAP (3 ч) - это уже не одна история
        self.assertEqual(chains(admin_events(timedelta(hours=4))), [])

    def test_logins_without_actions_are_not_a_chain(self):
        events = sources.read_json(HERE / "off_hours_night.json")
        self.assertEqual(chains(events), [])


class TestVerdicts(unittest.TestCase):
    def test_false_positive_statistics(self):
        db = scenario_db()
        ids = dict(db.execute("SELECT rule, id FROM incidents"))
        storage.set_verdict(db, ids["off_hours_login"], "false_positive")
        storage.set_verdict(db, ids["brute_force"], "confirmed")
        stats = {s["rule"]: s for s in storage.rule_stats(db)}
        self.assertEqual(stats["off_hours_login"]["false_rate"], 1.0)
        self.assertEqual(stats["brute_force"]["false_rate"], 0.0)
        self.assertIsNone(stats["log_cleared"]["false_rate"])            # ещё не разобран
        self.assertEqual(storage.rule_stats(db)[0]["rule"], "off_hours_login")  # самое «шумное» первым
        storage.set_verdict(db, ids["off_hours_login"], None)              # снять отметку
        self.assertEqual({s["rule"]: s for s in storage.rule_stats(db)}["off_hours_login"]["unreviewed"], 1)
        with self.assertRaises(ValueError):
            storage.set_verdict(db, ids["brute_force"], "maybe")
        db.close()


class TestReport(unittest.TestCase):
    def test_weekly_report(self):
        import report
        db = scenario_db()
        html, start, end = report.build(db, days=7)
        self.assertEqual((str(start), str(end)), ("2026-10-21", "2026-10-27"))  # неделя до последнего инцидента
        for text in ("Всего инцидентов", "Цепочка атаки", "T1110.001", "192.0.2.10", "Инцидентов по дням"):
            self.assertIn(text, html)
        db.close()

    def test_empty_database(self):
        import report
        db = storage.connect(":memory:")
        html, _, _ = report.build(db)
        self.assertIn("Инцидентов за период нет", html)
        db.close()


if __name__ == "__main__":
    unittest.main()
