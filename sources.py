"""Источники событий: журнал Windows Security и тестовый JSON.

Все источники возвращают события в едином формате (словарь):
    record_id  - номер записи в журнале (для JSON - порядковый номер)
    time       - datetime (локальное время)
    event_id   - код события Windows (4625, 4624, ...)
    event      - короткое имя типа события (failed_login, ...)
    ip, user, host, logon_type, subject_user - поля из события (могут быть None)
"""
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

# Коды событий журнала Security, которые отслеживает помощник
EVENT_NAMES = {
    4625: "failed_login",       # неудачный вход
    4624: "success_login",      # успешный вход
    4740: "account_locked",     # учётная запись заблокирована
    4720: "user_created",       # создана учётная запись
    4732: "added_to_group",     # пользователь добавлен в локальную группу
    1102: "log_cleared",        # журнал аудита очищен
}
NAME_TO_ID = {v: k for k, v in EVENT_NAMES.items()}

# Типы входа, интересные для 4624/4625: 2 - интерактивный, 3 - сетевой,
# 8 - сетевой с открытым паролем, 10 - RDP. Служебные входы (5 и др.) - шум.
INTERESTING_LOGON_TYPES = {"2", "3", "8", "10"}
EMPTY_VALUES = {None, "", "-", "::1", "127.0.0.1"}

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _clean(value):
    return None if value in EMPTY_VALUES else value


def _parse_time(text):
    """ISO-строка -> локальное время без часового пояса."""
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def normalize(record_id, time, event_id, data):
    """Приводит поля события к единому формату. data - словарь полей EventData/UserData."""
    event = {
        "record_id": record_id,
        "time": time,
        "event_id": event_id,
        "event": EVENT_NAMES.get(event_id, str(event_id)),
        "ip": _clean(data.get("IpAddress") or data.get("ip")),
        "user": _clean(data.get("TargetUserName") or data.get("user")),
        "host": _clean(data.get("WorkstationName") or data.get("host")),
        "logon_type": _clean(data.get("LogonType") or data.get("logon_type")),
        "subject_user": _clean(data.get("SubjectUserName") or data.get("subject_user")),
        "member": _clean(data.get("MemberName") or data.get("member")),
    }
    if event_id == 4732:
        # В 4732 TargetUserName - это имя группы, а пользователь - в MemberName
        event["group"] = _clean(data.get("TargetUserName") or data.get("group"))
        event["user"] = event["member"]
    return event


def is_relevant(event):
    """Отсекает служебный шум: входы системных служб и локальные входы без IP."""
    if event["event_id"] in (4624, 4625):
        if event["logon_type"] and str(event["logon_type"]) not in INTERESTING_LOGON_TYPES:
            return False
        if event["event_id"] == 4624 and not event["ip"]:
            return False
    return True


# ---------- Тестовый JSON ----------

def read_json(path):
    with Path(path).open(encoding="utf-8") as f:
        raw = json.load(f)
    events = []
    for i, e in enumerate(raw, start=1):
        event_id = e.get("event_id") or NAME_TO_ID.get(e.get("event"))
        if event_id is None:
            continue
        ev = normalize(i, _parse_time(e["time"]), int(event_id), e)
        if is_relevant(ev):
            events.append(ev)
    return events


# ---------- Журнал Windows (Security) ----------

def _parse_event_xml(xml_text):
    root = ET.fromstring(xml_text)
    system = root.find(f"{NS}System")
    event_id = int(system.find(f"{NS}EventID").text)
    record_id = int(system.find(f"{NS}EventRecordID").text)
    time = _parse_time(system.find(f"{NS}TimeCreated").get("SystemTime"))
    data = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{NS}Data"):
            data[d.get("Name")] = d.text
    user_data = root.find(f"{NS}UserData")
    if user_data is not None:
        # 1102 и некоторые другие события хранят поля в UserData/<Имя>/<Поле>
        for el in user_data.iter():
            if len(el) == 0 and el.text:
                data[el.tag.split("}")[-1]] = el.text
    return normalize(record_id, time, event_id, data)


def build_query(after_record_id=None, since=None, event_ids=EVENT_NAMES):
    conditions = ["(" + " or ".join(f"EventID={i}" for i in event_ids) + ")"]
    if after_record_id is not None:
        conditions.append(f"EventRecordID > {after_record_id}")
    elif since is not None:
        ms = int((datetime.now() - since).total_seconds() * 1000)
        conditions.append(f"TimeCreated[timediff(@SystemTime) <= {max(ms, 0)}]")
    return "*[System[" + " and ".join(conditions) + "]]"


def read_windows_log(after_record_id=None, since=None, channel="Security", event_ids=EVENT_NAMES):
    """Читает события из журнала Windows. Для Security нужны права администратора.

    after_record_id - взять только записи новее этого номера (режим мониторинга);
    since           - взять записи не старше этого момента (первый запуск).
    Возвращает (события, номер последней прочитанной записи).
    """
    try:
        import win32evtlog
        import pywintypes
    except ImportError as exc:
        raise RuntimeError("Не установлен pywin32: pip install pywin32") from exc

    query = build_query(after_record_id, since, event_ids)
    try:
        handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath
                                      | win32evtlog.EvtQueryForwardDirection, query)
    except pywintypes.error as exc:
        if exc.winerror == 5:
            raise PermissionError(
                f"Нет доступа к журналу {channel}. Запустите PowerShell от имени администратора.") from exc
        raise

    events = []
    last_record_id = after_record_id
    while True:
        batch = win32evtlog.EvtNext(handle, 100)
        if not batch:
            break
        for h in batch:
            xml_text = win32evtlog.EvtRender(h, win32evtlog.EvtRenderEventXml)
            ev = _parse_event_xml(xml_text)
            # Номер запоминаем и для отброшенных событий, чтобы не читать их повторно
            last_record_id = max(last_record_id or 0, ev["record_id"])
            if is_relevant(ev):
                events.append(ev)
    return events, last_record_id


def default_since(hours):
    return datetime.now() - timedelta(hours=hours)
