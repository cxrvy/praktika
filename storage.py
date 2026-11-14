"""Хранение инцидентов в SQLite с защитой от дублей."""
import sqlite3

from rules import WINDOW, is_remote_login

TIME_FMT = "%Y-%m-%d %H:%M:%S"

# Колонки, добавленные к исходной таблице MVP. Старые записи сохраняются.
NEW_COLUMNS = {
    "rule": "TEXT",
    "title": "TEXT",
    "entity": "TEXT",
    "username": "TEXT",
    "first_seen": "TEXT",
    "last_seen": "TEXT",
    "description": "TEXT",
    "checks": "TEXT",
    "updated_at": "TEXT",
}


def format_checks(checks):
    return "\n".join(f"{n}. {c}" for n, c in enumerate(checks, start=1))


def connect(path):
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, event_count INTEGER,
        severity TEXT, ai_analysis TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    existing = {row[1] for row in db.execute("PRAGMA table_info(incidents)")}
    for name, col_type in NEW_COLUMNS.items():
        if name not in existing:
            db.execute(f"ALTER TABLE incidents ADD COLUMN {name} {col_type}")
    db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_rule_entity ON incidents(rule, entity)")
    db.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT)")
    # Изученные входы: откуда обычно входит каждая учётная запись
    db.execute("""CREATE TABLE IF NOT EXISTS known_logins (
        username TEXT, ip TEXT, first_seen TEXT, last_seen TEXT, count INTEGER,
        PRIMARY KEY (username, ip))""")
    db.commit()
    return db


def save_incident(db, inc):
    """Сохраняет инцидент. Если такой же (правило + объект) уже есть и пересекается
    по времени - обновляет его вместо создания дубля.

    Возвращает (id, статус): "new" - новый инцидент, "updated" - выросло число событий,
    "duplicate" - уже был сохранён раньше (например, повторный запуск на тех же данных).
    """
    first = inc["first_seen"].strftime(TIME_FMT)
    last = inc["last_seen"].strftime(TIME_FMT)
    merge_from = (inc["first_seen"] - WINDOW).strftime(TIME_FMT)
    merge_to = (inc["last_seen"] + WINDOW).strftime(TIME_FMT)

    row = db.execute(
        """SELECT id, first_seen, last_seen, event_count FROM incidents
           WHERE rule = ? AND entity = ? AND last_seen >= ? AND first_seen <= ?
           ORDER BY id DESC LIMIT 1""",
        (inc["rule"], inc["entity"], merge_from, merge_to)).fetchone()

    if row:
        inc_id, old_first, old_last, old_count = row
        new_count = max(old_count or 0, inc["event_count"])
        new_last = max(old_last, last)
        if new_count == old_count and new_last == old_last:
            return inc_id, "duplicate"
        db.execute(
            """UPDATE incidents SET first_seen = ?, last_seen = ?, event_count = ?,
               description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (min(old_first, first), new_last, new_count, inc["description"], inc_id))
        db.commit()
        return inc_id, "updated"

    cur = db.execute(
        """INSERT INTO incidents (rule, title, severity, entity, ip, username, first_seen,
               last_seen, event_count, description, checks)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (inc["rule"], inc["title"], inc["severity"], inc["entity"], inc["ip"], inc["user"],
         first, last, inc["event_count"], inc["description"], format_checks(inc["checks"])))
    db.commit()
    return cur.lastrowid, "new"


def set_ai_analysis(db, inc_id, text):
    db.execute("UPDATE incidents SET ai_analysis = ? WHERE id = ?", (text, inc_id))
    db.commit()


def load_known_logins(db):
    """Изученные входы: {учётная запись: {IP: число входов}}."""
    known = {}
    for user, ip, count in db.execute("SELECT username, ip, count FROM known_logins"):
        known.setdefault(user, {})[ip] = count
    return known


def remember_logins(db, events):
    """Запоминает успешные удалённые входы - так программа узнаёт, откуда обычно входит каждый.

    Вход учитывается, только если он новее последнего запомненного для этой пары
    «учётная запись + IP», поэтому повторная проверка тех же событий не раздувает счётчики.
    """
    for e in sorted(events, key=lambda e: e["time"]):
        if not is_remote_login(e):
            continue
        user, time = e["user"].lower(), e["time"].strftime(TIME_FMT)
        row = db.execute("SELECT last_seen FROM known_logins WHERE username = ? AND ip = ?",
                         (user, e["ip"])).fetchone()
        if row is None:
            db.execute("INSERT INTO known_logins VALUES (?, ?, ?, ?, 1)", (user, e["ip"], time, time))
        elif time > row[0]:
            db.execute("UPDATE known_logins SET last_seen = ?, count = count + 1 "
                       "WHERE username = ? AND ip = ?", (time, user, e["ip"]))
    db.commit()


def list_known_logins(db, user=None):
    """Строки изученных входов (username, ip, first_seen, last_seen, count), по учётной записи и частоте."""
    query = "SELECT username, ip, first_seen, last_seen, count FROM known_logins"
    params = ()
    if user:
        query, params = query + " WHERE username = ?", (user.lower(),)
    return db.execute(query + " ORDER BY username, count DESC, ip", params).fetchall()


def forget_known_logins(db, user=None):
    """Забывает изученные входы (все или одной учётной записи). Инциденты не трогает.

    Возвращает, сколько записей удалено.
    """
    if user:
        cur = db.execute("DELETE FROM known_logins WHERE username = ?", (user.lower(),))
    else:
        cur = db.execute("DELETE FROM known_logins")
    db.commit()
    return cur.rowcount


def known_logins_stats(db):
    """(число учётных записей, число адресов) в изученных входах."""
    return db.execute("SELECT COUNT(DISTINCT username), COUNT(*) FROM known_logins").fetchone()


def get_state(db, key, default=None):
    row = db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_state(db, key, value):
    db.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)", (key, str(value)))
    db.commit()
