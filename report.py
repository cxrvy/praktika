"""HTML-отчёт за период: сколько инцидентов, каких типов, по дням, самые активные IP,
цепочки атак и отметки аналитика. Файл самодостаточный - открывается в любом браузере
без интернета, его можно приложить к отчёту или переслать.
"""
from collections import Counter
from datetime import datetime, timedelta
from html import escape
from pathlib import Path

import rules
import storage

DAY_NAMES = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"]


def period(db, days=7, end=None):
    """Границы отчёта (дата начала, дата конца).

    По умолчанию неделя заканчивается днём последнего инцидента в базе: при работе
    в реальном времени это текущая неделя, а на тестовых данных отчёт не будет пустым.
    days=None - за всё время.
    """
    first, last = db.execute("SELECT MIN(first_seen), MAX(last_seen) FROM incidents "
                             "WHERE rule IS NOT NULL").fetchone()
    if end is None:
        end = datetime.strptime(last[:10], "%Y-%m-%d").date() if last else datetime.now().date()
    if days is None:
        start = datetime.strptime(first[:10], "%Y-%m-%d").date() if first else end
    else:
        start = end - timedelta(days=days - 1)
    return start, end


def _load(db, start, end):
    cur = db.execute(
        """SELECT id, severity, title, rule, entity, ip, username, first_seen, last_seen,
                  event_count, description, mitre, verdict
           FROM incidents WHERE rule IS NOT NULL AND first_seen >= ? AND first_seen <= ?
           ORDER BY first_seen""",
        (f"{start} 00:00:00", f"{end} 23:59:59"))
    names = [c[0] for c in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def _tile(label, value, note="", sev=None):
    chip = f'<span class="chip sev-{sev.lower()}">{sev}</span>' if sev else ""
    return (f'<div class="tile"><div class="tile-label">{chip}{escape(label)}</div>'
            f'<div class="tile-value">{value}</div><div class="tile-note">{escape(note)}</div></div>')


def _day_chart(rows, start, end):
    """Столбчатая диаграмма «инцидентов по дням» (SVG, один ряд - одна шкала)."""
    days = [start + timedelta(days=n) for n in range((end - start).days + 1)]
    counts = Counter(r["first_seen"][:10] for r in rows)
    values = [counts.get(str(d), 0) for d in days]
    top = max(values + [1])
    step = 1 if top <= 5 else 2 if top <= 10 else 5 if top <= 25 else 10
    top = -(-top // step) * step  # округлить вверх до шага сетки

    width, height, left, bottom, pad_top = 720, 240, 36, 34, 12
    plot_w, plot_h = width - left - 8, height - bottom - pad_top
    slot = plot_w / len(days)
    bar = min(24, slot * 0.6)
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="Инцидентов по дням: {", ".join(map(str, values))}">']
    for tick in range(0, top + 1, step):
        y = pad_top + plot_h - plot_h * tick / top
        parts.append(f'<line class="grid" x1="{left}" x2="{width - 8}" y1="{y:.1f}" y2="{y:.1f}"/>'
                     f'<text class="axis" x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{tick}</text>')
    label_every = 1 if len(days) <= 14 else -(-len(days) // 14)
    for n, (day, value) in enumerate(zip(days, values)):
        cx = left + slot * n + slot / 2
        h = plot_h * value / top
        y0 = pad_top + plot_h
        tip = f"{day:%d.%m} ({DAY_NAMES[day.weekday()]}): инцидентов {value}"
        if value:
            r = min(4, h)  # скругление только у верхнего края, у основания - прямо
            x = cx - bar / 2
            path = (f"M{x:.1f},{y0} V{y0 - h + r:.1f} Q{x:.1f},{y0 - h:.1f} {x + r:.1f},{y0 - h:.1f} "
                    f"H{x + bar - r:.1f} Q{x + bar:.1f},{y0 - h:.1f} {x + bar:.1f},{y0 - h + r:.1f} V{y0} Z")
            parts.append(f'<path class="bar" d="{path}"/>')
        # область наведения шире столбца - на неё проще попасть мышью
        parts.append(f'<rect class="hit" x="{cx - slot / 2:.1f}" y="{pad_top}" width="{slot:.1f}" '
                     f'height="{plot_h}" data-tip="{escape(tip)}"><title>{escape(tip)}</title></rect>')
        if n % label_every == 0:
            parts.append(f'<text class="axis" x="{cx:.1f}" y="{height - 16}" text-anchor="middle">'
                         f'{day:%d.%m}</text><text class="axis muted" x="{cx:.1f}" y="{height - 3}" '
                         f'text-anchor="middle">{DAY_NAMES[day.weekday()]}</text>')
    parts.append(f'<line class="baseline" x1="{left}" x2="{width - 8}" y1="{pad_top + plot_h}" '
                 f'y2="{pad_top + plot_h}"/></svg>')
    table = "".join(f"<tr><td>{d:%d.%m.%Y} ({DAY_NAMES[d.weekday()]})</td><td class=num>{v}</td></tr>"
                    for d, v in zip(days, values))
    return ("".join(parts) +
            f'<details><summary>Таблица по дням</summary><table><tr><th>День</th>'
            f'<th class=num>Инцидентов</th></tr>{table}</table></details>')


def _table(headers, rows, numeric=()):
    head = "".join(f'<th{" class=num" if i in numeric else ""}>{escape(h)}</th>'
                   for i, h in enumerate(headers))
    body = "".join("<tr>" + "".join(f'<td{" class=num" if i in numeric else ""}>{c}</td>'
                                    for i, c in enumerate(r)) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def _mitre(codes):
    return " ".join(f'<abbr title="{escape(rules.MITRE_NAMES.get(c, c))}">{c}</abbr>'
                    for c in (codes or "").split(", ") if c)


def build(db, days=7, end=None):
    """Возвращает (html, дата начала, дата конца)."""
    start, end = period(db, days, end)
    rows = _load(db, start, end)
    stats = storage.rule_stats(db, f"{start} 00:00:00", f"{end} 23:59:59")
    sev = Counter(r["severity"] for r in rows)
    reviewed = sum(1 for r in rows if r["verdict"])
    false = sum(1 for r in rows if r["verdict"] == "false_positive")
    chains = [r for r in rows if r["rule"] == "attack_chain"]

    tiles = [
        _tile("Всего инцидентов", len(rows), f"{start:%d.%m} — {end:%d.%m.%Y}"),
        *(_tile("", sev.get(s, 0), sev=s) for s in ("CRITICAL", "HIGH", "MEDIUM")),
        _tile("Цепочек атак", len(chains), "связанных сценариев"),
        _tile("Разобрано аналитиком", f"{reviewed} из {len(rows)}",
              f"ложных: {false}" if reviewed else "отметок пока нет"),
    ]

    rule_rows = []
    for s in stats:
        rate = f"{s['false_rate']:.0%}" if s["false_rate"] is not None else "—"
        rule_rows.append([escape(s["title"]), _mitre(s["mitre"]), s["total"], s["confirmed"],
                          s["false_positive"], s["unreviewed"], rate])
    noisy = [s for s in stats if s["false_rate"] is not None and s["false_rate"] >= 0.5]
    noisy_note = ("<p class=note>Больше половины ложных: "
                  + ", ".join(f"«{escape(s['title'])}»" for s in noisy)
                  + ". Эти правила стоит настроить (пороги, рабочие часы, исключения).</p>"
                  if noisy else "")

    ip_counter = Counter(r["ip"] for r in rows if r["ip"])
    ip_rules = {}
    for r in rows:
        if r["ip"]:
            ip_rules.setdefault(r["ip"], []).append(r["title"])
    top_ips = [[escape(ip), n, escape(", ".join(dict.fromkeys(ip_rules[ip])))]
               for ip, n in ip_counter.most_common(10)]
    users = Counter(r["username"] for r in rows if r["username"])
    top_users = [[escape(u), n] for u, n in users.most_common(10)]

    chain_html = "".join(f'<div class="chain"><b>#{r["id"]} {escape(r["entity"])}</b> '
                         f'({r["first_seen"]} — {r["last_seen"][11:]})<br>{escape(r["description"])}'
                         f'<div class=muted>MITRE: {_mitre(r["mitre"])}</div></div>' for r in chains)

    verdict_names = {None: "—", **storage.VERDICTS}
    all_rows = [[r["id"], f'<span class="chip sev-{r["severity"].lower()}">{r["severity"]}</span>',
                 escape(r["title"]), escape(r["entity"] or "—"), r["first_seen"], _mitre(r["mitre"]),
                 escape(verdict_names.get(r["verdict"], r["verdict"]))] for r in rows]

    body = f"""
<h1>Отчёт помощника SOC</h1>
<p class=muted>Период: {start:%d.%m.%Y} — {end:%d.%m.%Y} · сформирован {datetime.now():%d.%m.%Y %H:%M}</p>
<div class=tiles>{''.join(tiles)}</div>
<h2>Инцидентов по дням</h2>
{_day_chart(rows, start, end)}
<h2>Правила и ложные срабатывания</h2>
<p class=muted>Доля ложных считается среди инцидентов, которые аналитик уже отметил.
Наведите на код MITRE, чтобы увидеть название техники.</p>
{_table(["Правило", "MITRE ATT&CK", "Всего", "Подтверждено", "Ложных", "Не разобрано", "Доля ложных"],
        rule_rows, numeric=(2, 3, 4, 5, 6)) if rule_rows else "<p>Инцидентов за период нет.</p>"}
{noisy_note}
<h2>Цепочки атак</h2>
{chain_html or "<p>Цепочек атак за период не найдено.</p>"}
<div class=cols>
<div><h2>Самые активные IP</h2>
{_table(["IP", "Инцидентов", "Правила"], top_ips, numeric=(1,)) if top_ips else "<p>—</p>"}</div>
<div><h2>Учётные записи</h2>
{_table(["Учётная запись", "Инцидентов"], top_users, numeric=(1,)) if top_users else "<p>—</p>"}</div>
</div>
<h2>Все инциденты</h2>
{_table(["№", "Риск", "Инцидент", "Объект", "Начало", "MITRE", "Отметка"], all_rows, numeric=(0,))
 if all_rows else "<p>Инцидентов за период нет.</p>"}
"""
    return PAGE.replace("{body}", body), start, end


def save(db, path=None, days=7, end=None, folder=None):
    """Сохраняет отчёт в файл и возвращает путь к нему."""
    html, start, end = build(db, days, end)
    if path is None:
        folder = Path(folder or Path(__file__).resolve().parent / "reports")
        folder.mkdir(exist_ok=True)
        path = folder / f"report_{start:%Y-%m-%d}_{end:%Y-%m-%d}.html"
    Path(path).write_text(html, encoding="utf-8")
    return Path(path)


PAGE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Отчёт помощника SOC</title>
<style>
:root {
  color-scheme: light;
  --surface: #fcfcfb; --surface-2: #f3f2ef; --border: #e2e1dc;
  --text: #0b0b0b; --text-2: #52514e; --muted: #7a7974;
  --series-1: #2a78d6; --grid: #e7e6e1;
  --crit-bg: #f8d7da; --crit-fg: #842029; --high-bg: #ffe5d0; --high-fg: #8a3b00;
  --med-bg: #fff3cd; --med-fg: #664d03;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --surface: #1a1a19; --surface-2: #242422; --border: #3a3a37;
    --text: #f0efec; --text-2: #c3c2b7; --muted: #9a998f;
    --series-1: #3987e5; --grid: #2f2f2c;
    --crit-bg: #4a1d22; --crit-fg: #f3b8bd; --high-bg: #4a2a12; --high-fg: #ffcf9f;
    --med-bg: #3d3310; --med-fg: #f2dc8f;
  }
}
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 1040px; padding: 24px 16px 48px; background: var(--surface);
       color: var(--text); font: 15px/1.5 "Segoe UI", system-ui, sans-serif; }
h1 { margin: 0 0 4px; font-size: 26px; }
h2 { margin: 32px 0 10px; font-size: 18px; }
.muted, .tile-note { color: var(--muted); }
.note { color: var(--text-2); background: var(--surface-2); border-left: 3px solid var(--border);
        padding: 8px 12px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px;
         margin-top: 18px; }
.tile { background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
.tile-label { color: var(--text-2); font-size: 13px; }
.tile-value { font-size: 28px; font-weight: 600; line-height: 1.2; margin: 4px 0 2px; }
.tile-note { font-size: 12px; }
.chip { display: inline-block; font-size: 12px; font-weight: 700; padding: 1px 7px; border-radius: 4px; }
.sev-critical { background: var(--crit-bg); color: var(--crit-fg); }
.sev-high { background: var(--high-bg); color: var(--high-fg); }
.sev-medium { background: var(--med-bg); color: var(--med-fg); }
.sev-low { background: var(--surface-2); color: var(--text-2); }
svg { width: 100%; height: auto; display: block; }
.bar { fill: var(--series-1); }
.hit { fill: transparent; cursor: default; }
.hit:hover { fill: var(--text); fill-opacity: .05; }
.grid { stroke: var(--grid); stroke-width: 1; }
.baseline { stroke: var(--muted); stroke-width: 1; }
.axis { fill: var(--text-2); font-size: 12px; }
.axis.muted { fill: var(--muted); font-size: 11px; }
#tip { position: fixed; pointer-events: none; background: var(--text); color: var(--surface);
       font-size: 13px; padding: 4px 8px; border-radius: 4px; display: none; }
details { margin-top: 6px; } summary { cursor: pointer; color: var(--text-2); }
.cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 0 24px; }
table { border-collapse: collapse; width: 100%; font-size: 14px; display: block; overflow-x: auto; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--text-2); font-weight: 600; background: var(--surface-2); }
.num { text-align: right; font-variant-numeric: tabular-nums; }
abbr { text-decoration: underline dotted; cursor: help; }
.chain { border: 1px solid var(--border); border-left: 4px solid var(--crit-fg); border-radius: 6px;
         padding: 10px 12px; margin-bottom: 8px; }
@media print { #tip { display: none !important; } details { display: none; } }
</style></head>
<body>
{body}
<div id="tip"></div>
<script>
const tip = document.getElementById("tip");
document.querySelectorAll(".hit").forEach(el => {
  el.querySelector("title")?.remove();  // своя подсказка вместо системной
  el.addEventListener("mousemove", e => {
    tip.textContent = el.dataset.tip; tip.style.display = "block";
    tip.style.left = (e.clientX + 12) + "px"; tip.style.top = (e.clientY - 30) + "px";
  });
  el.addEventListener("mouseleave", () => { tip.style.display = "none"; });
});
</script>
</body></html>
"""
