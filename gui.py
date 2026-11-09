"""Помощник SOC: оконный интерфейс.

Запуск:  python gui.py   (или двойной щелчок по start_gui.bat)

Проверка выполняется в отдельном потоке, чтобы окно не «зависало», пока модель
готовит пояснение. Поток передаёт сообщения в окно через очередь.
"""
import argparse
import csv
import ctypes
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import ai
import rules
import storage
from assistant import Assistant

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "incidents.db"
PRESETS = {
    "Все сценарии (events.json)": BASE / "events.json",
    "Набор 1: атака подряд": BASE / "tests" / "attack_burst.json",
    "Набор 2: те же 5 ошибок за день": BASE / "tests" / "attack_spread_day.json",
    "Набор 3: вход ночью": BASE / "tests" / "off_hours_night.json",
    "Набор 4: тот же вход днём": BASE / "tests" / "off_hours_day.json",
}

SEVERITY_STYLE = {  # фон строки, цвет текста
    "CRITICAL": ("#f8d7da", "#842029"),
    "HIGH": ("#ffe5d0", "#8a3b00"),
    "MEDIUM": ("#fff3cd", "#664d03"),
    "LOW": ("#e7f1ff", "#084298"),
}
LOG_COLORS = {"info": "#333333", "warning": "#b35c00", "error": "#c62828", "ok": "#2e7d32"}
COLUMNS = [  # (ключ, заголовок, ширина)
    ("id", "№", 40), ("severity", "Риск", 80), ("title", "Инцидент", 180), ("entity", "Объект", 115),
    ("first_seen", "Начало", 135), ("last_seen", "Конец", 70), ("event_count", "Событий", 65),
    ("ai", "AI", 75),
]
SHOWN_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"]  # уровни, которые выдают правила


def enable_sharp_text():
    """Чёткий текст на экранах с масштабированием 125–150 % (иначе Windows растягивает окно и оно мылится)."""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Помощник SOC — мониторинг журнала Windows")
        self.geometry("1280x800")
        self.minsize(1000, 640)
        self.option_add("*Font", ("Segoe UI", 10))

        self.events = queue.Queue()
        self.worker = None
        self.stop_event = threading.Event()
        self.ai_state = {}          # id инцидента -> состояние AI в текущей сессии
        self.rows = {}              # id -> запись из базы
        self.db = storage.connect(DB_PATH)

        self._build_styles()
        self._build_source_panel()
        self._build_status_bar()
        self._build_main_area()
        self._build_log()

        self.load_incidents()
        self.log("info", f"База инцидентов: {DB_PATH}")
        self.log("info", f"Окно правил: {rules.BRUTE_FORCE_THRESHOLD} неудачных входов за "
                         f"{int(rules.WINDOW.total_seconds() // 60)} мин.")
        self.check_ollama()
        self.after(100, self._poll_events)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- построение окна ----------

    def _build_styles(self):
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=24)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 11, "bold"))

    def _build_source_panel(self):
        box = ttk.LabelFrame(self, text="Источник событий", padding=8)
        box.pack(fill="x", padx=10, pady=(10, 4))

        self.source = tk.StringVar(value="json")
        ttk.Radiobutton(box, text="Тестовый файл:", variable=self.source, value="json",
                        command=self._toggle_source).grid(row=0, column=0, sticky="w")
        self.file_var = tk.StringVar(value=next(iter(PRESETS)))
        self.file_box = ttk.Combobox(box, textvariable=self.file_var, values=list(PRESETS), width=55)
        self.file_box.grid(row=0, column=1, sticky="we", padx=4)
        self.browse_btn = ttk.Button(box, text="Обзор…", command=self.browse_file)
        self.browse_btn.grid(row=0, column=2, padx=4)

        ttk.Radiobutton(box, text="Журнал Windows (Security)", variable=self.source,
                        value="windows", command=self._toggle_source).grid(row=1, column=0, sticky="w",
                                                                          pady=(6, 0))
        hours_row = ttk.Frame(box)
        hours_row.grid(row=1, column=1, sticky="w", padx=4, pady=(6, 0))
        ttk.Label(hours_row, text="за последние").pack(side="left")
        self.hours_var = tk.StringVar(value="24")
        self.hours_box = ttk.Spinbox(hours_row, from_=1, to=720, textvariable=self.hours_var, width=5)
        self.hours_box.pack(side="left", padx=4)
        ttk.Label(hours_row, text="ч").pack(side="left")

        self.admin_label = ttk.Label(box)
        self.admin_label.grid(row=1, column=2, columnspan=2, sticky="w", pady=(6, 0))
        self.admin_btn = ttk.Button(box, text="Перезапустить от имени администратора",
                                    command=self.restart_as_admin)
        self._update_admin_label()

        opts = ttk.Frame(box)
        opts.grid(row=2, column=0, columnspan=4, sticky="w", pady=(8, 0))
        self.use_ai = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text=f"AI-пояснения ({ai.MODEL})", variable=self.use_ai).pack(side="left")
        self.follow = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Непрерывный мониторинг, проверка каждые",
                        variable=self.follow).pack(side="left", padx=(16, 4))
        self.interval_var = tk.StringVar(value="15")
        ttk.Spinbox(opts, from_=5, to=3600, textvariable=self.interval_var, width=5).pack(side="left")
        ttk.Label(opts, text="с").pack(side="left", padx=4)

        buttons = ttk.Frame(box)
        buttons.grid(row=0, column=4, rowspan=3, sticky="ne", padx=(20, 0))
        self.start_btn = ttk.Button(buttons, text="▶  Запустить проверку", style="Accent.TButton",
                                    command=self.start)
        self.start_btn.pack(fill="x", ipady=4)
        self.stop_btn = ttk.Button(buttons, text="■  Остановить", command=self.stop, state="disabled")
        self.stop_btn.pack(fill="x", pady=(6, 0))

        box.columnconfigure(1, weight=1)
        self._toggle_source()

    def _build_status_bar(self):
        bar = ttk.Frame(self, padding=(10, 2))
        bar.pack(fill="x")
        self.status_var = tk.StringVar(value="Готов к работе")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=140)  # виден только во время проверки

        self.counter_labels = {}
        for sev in reversed(SHOWN_SEVERITIES):
            bg, fg = SEVERITY_STYLE[sev]
            lbl = tk.Label(bar, text=f"{sev}: 0", bg=bg, fg=fg, padx=8, pady=2,
                           font=("Segoe UI", 9, "bold"))
            lbl.pack(side="right", padx=2)
            self.counter_labels[sev] = lbl
        self.ollama_label = tk.Label(bar, text="Ollama: проверка…", fg="#666666")
        self.ollama_label.pack(side="right", padx=12)

    def _build_main_area(self):
        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=10, pady=4)

        # Левая часть: фильтры и таблица инцидентов
        left = ttk.Frame(panes)
        filters = ttk.Frame(left)
        filters.pack(fill="x", pady=(0, 4))
        ttk.Label(filters, text="Инциденты", style="Header.TLabel").pack(side="left")
        ttk.Button(filters, text="Экспорт в CSV", command=self.export_csv).pack(side="right")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_table())
        ttk.Entry(filters, textvariable=self.search_var, width=18).pack(side="right", padx=4)
        ttk.Label(filters, text="Поиск:").pack(side="right")
        self.sev_filter = tk.StringVar(value="Все")
        sev_box = ttk.Combobox(filters, textvariable=self.sev_filter, state="readonly", width=10,
                               values=["Все"] + SHOWN_SEVERITIES)
        sev_box.pack(side="right", padx=(4, 12))
        sev_box.bind("<<ComboboxSelected>>", lambda _: self.refresh_table())
        ttk.Label(filters, text="Риск:").pack(side="right")

        table = ttk.Frame(left)
        table.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table, columns=[c[0] for c in COLUMNS], show="headings",
                                 selectmode="browse")
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="center" if key in ("id", "event_count", "ai") else "w",
                             stretch=key == "title")
        for sev, (bg, fg) in SEVERITY_STYLE.items():
            self.tree.tag_configure(sev, background=bg, foreground=fg)
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _: self.show_details())
        panes.add(left, weight=3)

        # Правая часть: подробности выбранного инцидента
        right = ttk.Frame(panes)
        head = ttk.Frame(right)
        head.pack(fill="x", pady=(0, 4))
        ttk.Label(head, text="Подробности", style="Header.TLabel").pack(side="left")
        ttk.Button(head, text="Копировать отчёт", command=self.copy_report).pack(side="right")
        details_box = ttk.Frame(right)
        details_box.pack(fill="both", expand=True)
        self.details = tk.Text(details_box, wrap="word", padx=10, pady=8, relief="solid", borderwidth=1,
                               background="#fbfbfb", width=40)  # узкая начальная ширина - место таблице
        details_scroll = ttk.Scrollbar(details_box, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=details_scroll.set)
        details_scroll.pack(side="right", fill="y")
        self.details.tag_configure("h1", font=("Segoe UI", 13, "bold"))
        self.details.tag_configure("h2", font=("Segoe UI", 10, "bold"), spacing1=10, spacing3=3)
        self.details.tag_configure("muted", foreground="#666666")
        self.details.tag_configure("warn", foreground=LOG_COLORS["warning"])
        for sev, (bg, fg) in SEVERITY_STYLE.items():
            self.details.tag_configure(sev, background=bg, foreground=fg, font=("Segoe UI", 10, "bold"))
        self.details.pack(side="left", fill="both", expand=True)
        self._set_details([("Выберите инцидент в таблице слева.", "muted")])
        panes.add(right, weight=2)

    def _build_log(self):
        box = ttk.LabelFrame(self, text="Журнал работы и ошибки", padding=4)
        box.pack(fill="x", padx=10, pady=(4, 10))
        self.log_text = tk.Text(box, height=7, wrap="word", state="disabled", relief="flat",
                                background="#f4f4f4", font=("Consolas", 9))
        for level, color in LOG_COLORS.items():
            self.log_text.tag_configure(level, foreground=color)
        self.log_text.tag_configure("error", foreground=LOG_COLORS["error"], font=("Consolas", 9, "bold"))
        scroll = ttk.Scrollbar(box, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    # ---------- вспомогательное ----------

    def log(self, level, text, tag=None):
        line = f"{datetime.now():%H:%M:%S}  " + (f"[{tag}] " if tag else "") + text + "\n"
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line, level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _toggle_source(self):
        json_mode = self.source.get() == "json"
        self.file_box.configure(state="normal" if json_mode else "disabled")
        self.browse_btn.configure(state="normal" if json_mode else "disabled")
        self.hours_box.configure(state="disabled" if json_mode else "normal")

    def _update_admin_label(self):
        if is_admin():
            self.admin_label.configure(text="✔ Права администратора есть", foreground=LOG_COLORS["ok"])
            self.admin_btn.grid_forget()
        else:
            self.admin_label.configure(text="Нет прав администратора — журнал Security недоступен",
                                       foreground=LOG_COLORS["warning"])
            self.admin_btn.grid(row=2, column=2, columnspan=2, sticky="w", pady=(8, 0))

    def _selected_file(self):
        value = self.file_var.get()
        return PRESETS.get(value, Path(value))

    def browse_file(self):
        path = filedialog.askopenfilename(title="Выберите файл с событиями", initialdir=BASE,
                                          filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")])
        if path:
            self.file_var.set(path)

    def check_ollama(self):
        def worker():
            problem = ai.check_available()
            self.events.put(("ollama", {"problem": problem}))
        threading.Thread(target=worker, daemon=True).start()

    # ---------- запуск и остановка ----------

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        try:
            interval = max(5, int(self.interval_var.get()))
            hours = float(self.hours_var.get().replace(",", "."))
        except ValueError:
            messagebox.showerror("Ошибка ввода", "Интервал и количество часов должны быть числами.")
            return
        source, follow, use_ai = self.source.get(), self.follow.get(), self.use_ai.get()
        path = self._selected_file()
        if source == "json" and not path.is_file():
            messagebox.showerror("Файл не найден", f"Не найден файл с событиями:\n{path}")
            return
        if source == "windows" and not is_admin():
            if messagebox.askyesno("Нужны права администратора",
                                   "Журнал Security читается только с правами администратора.\n\n"
                                   "Перезапустить помощника от имени администратора?"):
                self.restart_as_admin()
            return

        self.stop_event.clear()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.pack(side="left", padx=10)
        self.progress.start(12)
        what = path.name if source == "json" else "журнал Security"
        self.status_var.set(f"Идёт проверка: {what}" + (" (непрерывный мониторинг)" if follow else ""))
        self.log("info", f"Запуск проверки: {what}" + (", AI-пояснения включены" if use_ai else ""))

        def run():
            notify = lambda kind, data: self.events.put((kind, data))  # noqa: E731
            assistant = None
            try:
                assistant = Assistant(DB_PATH, use_ai=use_ai, notify=notify, stop_event=self.stop_event)
                if source == "json":
                    assistant.run_json(path, follow, interval)
                else:
                    assistant.run_windows(hours, follow, interval)
                for line in assistant.summary():
                    notify("log", {"level": "ok", "tag": None, "text": line})
            except PermissionError as exc:
                notify("fatal", {"title": "Нет доступа к журналу", "text": str(exc)})
            except Exception as exc:  # показываем любую ошибку в окне, а не в скрытой консоли
                notify("fatal", {"title": "Ошибка при проверке", "text": f"{type(exc).__name__}: {exc}"})
            finally:
                if assistant:
                    assistant.close()
                notify("done", {})

        self.worker = threading.Thread(target=run, daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        self.stop_btn.configure(state="disabled")
        self.status_var.set("Останавливаю… (дожидаюсь текущего ответа модели)")
        self.log("warning", "Остановка по кнопке.")

    def restart_as_admin(self):
        exe = Path(sys.executable)
        pythonw = exe.with_name("pythonw.exe")
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", str(pythonw if pythonw.exists() else exe), f'"{Path(__file__).resolve()}"',
            str(BASE), 1)
        if result > 32:  # меньшие значения - ошибка или отказ в окне UAC
            self.on_close()
        else:
            self.log("warning", "Перезапуск от имени администратора отменён.")

    def on_close(self):
        self.stop_event.set()
        self.db.close()
        self.destroy()

    # ---------- сообщения от потока проверки ----------

    def _poll_events(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                self._handle_event(kind, data)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _handle_event(self, kind, data):
        if kind == "log":
            self.log(data["level"], data["text"], data["tag"])
        elif kind == "incident":
            inc = data["inc"]
            if data["status"] == "new":
                self.ai_state[data["id"]] = "ожидает…" if self.use_ai.get() else "выкл."
                self.log("error" if inc["severity"] in ("CRITICAL", "HIGH") else "warning",
                         f"#{data['id']} {inc['severity']}: {inc['title']} — {inc['entity']}", "ALERT")
                self.status_var.set(f"Готовлю AI-пояснение для #{data['id']}…" if self.use_ai.get()
                                    else self.status_var.get())
            else:
                self.log("warning", f"#{data['id']} {inc['title']}: событий уже {inc['event_count']} "
                                    "(атака продолжается)", "UPDATE")
            self.load_incidents(select=data["id"] if data["status"] == "new" else None)
        elif kind == "ai":
            if data["text"]:
                self.ai_state[data["id"]] = "есть"
            else:
                self.ai_state[data["id"]] = "отброшено"
                self.log("warning", f"#{data['id']}: пояснение модели отброшено "
                                    f"({'; '.join(data['warnings'])}). Используйте проверки.", "AI")
            self.load_incidents()
        elif kind == "ollama":
            if data["problem"]:
                self.ollama_label.configure(text="● Ollama недоступна", fg=LOG_COLORS["error"])
                self.log("warning", data["problem"], "AI НЕ ДОСТУПЕН")
            else:
                self.ollama_label.configure(text=f"● Ollama: {ai.MODEL}", fg=LOG_COLORS["ok"])
        elif kind == "fatal":
            self.log("error", data["text"], "ОШИБКА")
            messagebox.showerror(data["title"], data["text"])
        elif kind == "done":
            self.progress.stop()
            self.progress.pack_forget()
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.status_var.set("Проверка завершена")

    # ---------- таблица и подробности ----------

    def load_incidents(self, select=None):
        cur = self.db.execute(
            """SELECT id, severity, title, rule, entity, ip, first_seen, last_seen, event_count,
                      description, checks, ai_analysis, created_at
               FROM incidents ORDER BY id DESC""")
        names = [c[0] for c in cur.description]
        self.rows = {r[0]: dict(zip(names, r)) for r in cur.fetchall()}
        self.refresh_table(select)

    def _ai_cell(self, row):
        if row["id"] in self.ai_state and not row["ai_analysis"]:
            return self.ai_state[row["id"]]
        return "есть" if row["ai_analysis"] else "—"

    def refresh_table(self, select=None):
        # Новый инцидент выделяется, только если аналитик сейчас ничего не читает
        selected = (int(self.tree.selection()[0]) if self.tree.selection() else None) or select
        self.tree.delete(*self.tree.get_children())
        sev_filter, needle = self.sev_filter.get(), self.search_var.get().strip().lower()
        counts = {sev: 0 for sev in SHOWN_SEVERITIES}
        for row in self.rows.values():
            sev = row["severity"] or "LOW"
            counts[sev] = counts.get(sev, 0) + 1
            title = row["title"] or "Неудачные входы (запись MVP)"
            entity = row["entity"] or row["ip"] or "—"
            if sev_filter != "Все" and sev != sev_filter:
                continue
            if needle and needle not in f"{title} {entity} {row['description'] or ''}".lower():
                continue
            first = row["first_seen"] or row["created_at"] or "—"
            last = row["last_seen"] or "—"
            if last[:10] == first[:10]:
                last = last[11:]  # тот же день - достаточно времени
            self.tree.insert("", "end", iid=str(row["id"]), tags=(sev,), values=(
                row["id"], sev, title, entity, first, last, row["event_count"], self._ai_cell(row)))
        for sev, lbl in self.counter_labels.items():
            lbl.configure(text=f"{sev}: {counts.get(sev, 0)}")
        if selected and self.tree.exists(str(selected)):
            self.tree.selection_set(str(selected))
            self.tree.see(str(selected))
        self.show_details()

    def _report_parts(self, row):
        sev = row["severity"] or "LOW"
        parts = [
            (f"#{row['id']}  {row['title'] or 'Неудачные входы (запись MVP)'}\n", "h1"),
            (f" {sev} ", sev),
            (f"   Объект: {row['entity'] or row['ip'] or '—'}   •   событий: {row['event_count']}\n", "muted"),
            (f"Период: {row['first_seen'] or row['created_at'] or '—'} — {row['last_seen'] or '—'}\n", "muted"),
            ("Описание\n", "h2"),
            (f"{row['description'] or '—'}\n", None),
            ("Проверки для аналитика\n", "h2"),
            (f"{row['checks'] or 'Для записей старого формата проверки не сохранялись.'}\n", None),
            (f"AI-пояснение ({ai.MODEL}, подсказка, не вывод)\n", "h2"),
        ]
        if row["ai_analysis"]:
            parts.append((row["ai_analysis"] + "\n", None))
        else:
            state = self.ai_state.get(row["id"])
            parts.append(({"ожидает…": "Модель готовит пояснение…",
                           "отброшено": "Пояснение модели не прошло автоматическую проверку и не показано. "
                                        "Используйте проверки выше."}.get(state, "Нет пояснения."), "warn"))
        return parts

    def _set_details(self, parts):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        for text, tag in parts:
            self.details.insert("end", text, tag or ())
        self.details.configure(state="disabled")

    def _selected_row(self):
        sel = self.tree.selection()
        return self.rows.get(int(sel[0])) if sel else None

    def show_details(self):
        row = self._selected_row()
        self._set_details(self._report_parts(row) if row else [("Выберите инцидент в таблице слева.", "muted")])

    def copy_report(self):
        row = self._selected_row()
        if not row:
            return
        self.clipboard_clear()
        self.clipboard_append("".join(text for text, _ in self._report_parts(row)))
        self.log("ok", f"Отчёт по инциденту #{row['id']} скопирован в буфер обмена.")

    def export_csv(self):
        ids = [int(i) for i in self.tree.get_children()]
        if not ids:
            messagebox.showinfo("Экспорт", "В таблице нет инцидентов для экспорта.")
            return
        path = filedialog.asksaveasfilename(title="Сохранить инциденты", defaultextension=".csv",
                                            initialfile=f"incidents_{datetime.now():%Y%m%d_%H%M}.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        fields = ["id", "severity", "title", "entity", "first_seen", "last_seen", "event_count",
                  "description", "checks", "ai_analysis"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig - чтобы Excel понял русский
            writer = csv.writer(f, delimiter=";")
            writer.writerow(fields)
            for i in ids:
                writer.writerow([self.rows[i][k] for k in fields])
        self.log("ok", f"Экспортировано инцидентов: {len(ids)} → {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Помощник SOC: оконный интерфейс")
    parser.add_argument("--db", default=str(DB_PATH), help="путь к базе инцидентов")
    DB_PATH = Path(parser.parse_args().db)
    enable_sharp_text()
    App().mainloop()
