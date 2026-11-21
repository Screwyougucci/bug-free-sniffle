"""Persistent local desktop dashboard for Darth Scanner.

The GUI stores per-target reports and history under the user's local app-data
directory. Active checks require an explicit ownership/authorization confirmation
and generate an exact-host scope file for the entered URL.
"""
from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from .identity import target_id, resource_id
from .app_utils import parse_target_url


APP_NAME = "Darth Scanner"
MIN_INTERVAL = 30


def app_data_dir() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".local" / "share"))
    folder = root / "DarthScanner"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


class DarthScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Darth Scanner — Discovery Command")
        self.root.geometry("1120x760")
        self.root.minsize(900, 620)
        self.root.configure(bg="#101116")
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.process: subprocess.Popen | None = None
        self.worker: threading.Thread | None = None
        self.current_folder: Path | None = None
        self.current_target: str | None = None
        self._style()
        self._build()
        self.root.after(150, self._poll_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.refresh_dashboard()

    def _style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#191b23", foreground="#e7e8ed",
                        fieldbackground="#191b23", rowheight=27, borderwidth=0)
        style.configure("Treeview.Heading", background="#262936", foreground="#f4f4f6",
                        relief="flat", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#343b52")])
        style.configure("TCombobox", fieldbackground="#20232c", foreground="#f4f4f6")

    def _build(self):
        header = tk.Frame(self.root, bg="#171922", padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="DARTH SCANNER", bg="#171922", fg="#f5f5f7",
                 font=("Segoe UI", 20, "bold")).pack(side="left")
        tk.Label(header, text="DISCOVERY COMMAND  •  LOCAL WORKSPACE",
                 bg="#171922", fg="#a5a9b8", font=("Segoe UI", 9)).pack(side="left", padx=18, pady=(7, 0))
        self.status = tk.Label(header, text="● IDLE", bg="#171922", fg="#a8adb9",
                               font=("Segoe UI", 9, "bold"))
        self.status.pack(side="right", pady=(7, 0))

        main = tk.Frame(self.root, bg="#101116", padx=20, pady=16)
        main.pack(fill="both", expand=True)

        target_panel = tk.Frame(main, bg="#191b23", padx=15, pady=13)
        target_panel.pack(fill="x")
        tk.Label(target_panel, text="TARGET WEBSITE", bg="#191b23", fg="#f1f2f5",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        entry_row = tk.Frame(target_panel, bg="#191b23")
        entry_row.pack(fill="x", pady=(8, 5))
        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(entry_row, textvariable=self.url_var, bg="#252833",
                                  fg="#f5f5f7", insertbackground="white", relief="flat",
                                  font=("Consolas", 11))
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=9, padx=(0, 9))
        self.start_button = tk.Button(entry_row, text="START WATCH", command=self.start_watch,
                                      bg="#8d1e2d", fg="white", activebackground="#a52b3c",
                                      relief="flat", padx=17, pady=8, font=("Segoe UI", 9, "bold"))
        self.start_button.pack(side="left", padx=3)
        self.stop_button = tk.Button(entry_row, text="STOP", command=self.stop_watch,
                                     bg="#343744", fg="white", activebackground="#45495a",
                                     relief="flat", padx=17, pady=8, font=("Segoe UI", 9, "bold"),
                                     state="disabled")
        self.stop_button.pack(side="left", padx=3)
        self.authorized_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            target_panel,
            text="I own this website or have explicit permission to run security checks against it.",
            variable=self.authorized_var, bg="#191b23", fg="#d7d9e0",
            activebackground="#191b23", activeforeground="white", selectcolor="#252833",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 0))
        tk.Label(target_panel, text="The app only adds the exact hostname you enter to this target's scope. It does not authorize other subdomains.",
                 bg="#191b23", fg="#9da2b1", font=("Segoe UI", 8)).pack(anchor="w", pady=(5, 0))

        stats = tk.Frame(main, bg="#101116")
        stats.pack(fill="x", pady=12)
        self.stat_vars = {}
        for key, label in [("total", "UNIQUE FINDINGS"), ("new", "NEW"), ("recurring", "RECURRING"),
                           ("changed", "CHANGED"), ("resolved", "RESOLVED"), ("cycles", "SCAN CYCLES")]:
            card = tk.Frame(stats, bg="#191b23", padx=13, pady=10)
            card.pack(side="left", fill="x", expand=True, padx=(0, 7))
            tk.Label(card, text=label, bg="#191b23", fg="#9da2b1",
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            var = tk.StringVar(value="0")
            self.stat_vars[key] = var
            tk.Label(card, textvariable=var, bg="#191b23", fg="#f4f4f6",
                     font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(3, 0))

        split = tk.PanedWindow(main, orient="vertical", bg="#101116", sashwidth=6,
                               sashrelief="flat", bd=0)
        split.pack(fill="both", expand=True)
        findings_panel = tk.Frame(split, bg="#191b23", padx=12, pady=10)
        split.add(findings_panel, minsize=190)
        title_row = tk.Frame(findings_panel, bg="#191b23")
        title_row.pack(fill="x", pady=(0, 8))
        tk.Label(title_row, text="DISCOVERY REGISTRY", bg="#191b23", fg="#f1f2f5",
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Button(title_row, text="REFRESH", command=self.refresh_dashboard, bg="#303442",
                  fg="white", relief="flat", padx=10, pady=4).pack(side="right")
        tk.Button(title_row, text="OPEN DATA FOLDER", command=self.open_data_folder, bg="#303442",
                  fg="white", relief="flat", padx=10, pady=4).pack(side="right", padx=6)

        columns = ("status", "severity", "title", "finding_id", "occurrences", "last_seen")
        self.table = ttk.Treeview(findings_panel, columns=columns, show="headings", height=8)
        widths = {"status": 95, "severity": 80, "title": 320, "finding_id": 190,
                  "occurrences": 85, "last_seen": 155}
        labels = {"status": "STATUS", "severity": "SEVERITY", "title": "DISCOVERY",
                  "finding_id": "FINDING ID", "occurrences": "SEEN", "last_seen": "LAST SEEN"}
        for col in columns:
            self.table.heading(col, text=labels[col])
            self.table.column(col, width=widths[col], minwidth=60, anchor="w")
        self.table.pack(fill="both", expand=True)
        self.table.bind("<Double-1>", self.show_finding_details)

        log_panel = tk.Frame(split, bg="#191b23", padx=12, pady=10)
        split.add(log_panel, minsize=130)
        tk.Label(log_panel, text="LIVE ACTIVITY", bg="#191b23", fg="#f1f2f5",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 7))
        self.log = tk.Text(log_panel, height=7, bg="#11131a", fg="#cbd0dc",
                           insertbackground="white", relief="flat", wrap="word",
                           font=("Consolas", 9), state="disabled")
        self.log.pack(fill="both", expand=True)
        footer = tk.Label(main, text="Local-only dashboard • History persists between launches • Continuous watch stops when you press STOP or close the app",
                          bg="#101116", fg="#818696", font=("Segoe UI", 8))
        footer.pack(anchor="w", pady=(8, 0))

    def _log(self, message: str):
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_running(self, running: bool):
        self.status.configure(text="● WATCHING" if running else "● IDLE",
                              fg="#e4a0a8" if running else "#a8adb9")
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")

    def start_watch(self):
        if self.process is not None and self.process.poll() is None:
            return
        if not self.authorized_var.get():
            messagebox.showwarning("Authorization required",
                                   "Confirm that you own this website or have explicit permission before starting.")
            return
        try:
            target, host = parse_target_url(self.url_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid website", str(exc))
            return
        if not messagebox.askyesno(
            "Confirm authorized testing",
            f"Start continuous, read-only web checks for:\n\n{target}\n\n"
            f"Exact allowed hostname: {host}\n\n"
            "Only proceed if you have permission. The app will keep checking until you stop it."
        ):
            return

        folder = app_data_dir() / (target_id(target) + "-" + resource_id(target))
        folder.mkdir(parents=True, exist_ok=True)
        scope_path = folder / "scope.json"
        output_dir = folder / "reports"
        output_dir.mkdir(exist_ok=True)
        scope = {
            "authorized": True,
            "allowed_hosts": [host],
            "max_pages": 12,
            "max_requests": 24,
            "request_delay_seconds": 1.0,
            "timeout_seconds": 8,
        }
        scope_path.write_text(json.dumps(scope, indent=2), encoding="utf-8")
        self.current_target = target
        self.current_folder = output_dir
        self.url_var.set(target)
        self._log(f"Starting authorized watch: {target}")
        self._log(f"Persistent data: {output_dir}")
        self._set_running(True)
        self.worker = threading.Thread(
            target=self._run_process,
            args=(target, scope_path, output_dir),
            daemon=True,
        )
        self.worker.start()

    def _run_process(self, target: str, scope_path: Path, output_dir: Path):
        command = [
            sys.executable, "-m", "darthscanner", "watch",
            "--target", target,
            "--scope", str(scope_path),
            "--acknowledge-authorization",
            "--output-dir", str(output_dir),
            "--interval", str(MIN_INTERVAL),
        ]
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
            self.process = process
            assert process.stdout is not None
            for line in process.stdout:
                self.events.put(("log", line.rstrip()))
            code = process.wait()
            self.events.put(("exit", f"Watch process ended (exit code {code})."))
        except Exception as exc:
            self.events.put(("exit", f"Could not start scanner: {exc}"))

    def stop_watch(self):
        process = self.process
        if process is not None and process.poll() is None:
            self._log("Stopping watch...")
            process.terminate()
        self._set_running(False)

    def _poll_events(self):
        try:
            while True:
                kind, message = self.events.get_nowait()
                if kind == "log":
                    self._log(message)
                    if "Cycle " in message or "Discovery identities" in message:
                        self.refresh_dashboard()
                else:
                    self._log(message)
                    self.process = None
                    self._set_running(False)
                    self.refresh_dashboard()
        except queue.Empty:
            pass
        self.root.after(150, self._poll_events)

    def refresh_dashboard(self):
        if self.current_folder is None:
            try:
                folder = app_data_dir()
                candidates = sorted(folder.glob("*/reports/history.json"),
                                    key=lambda p: p.stat().st_mtime, reverse=True)
                if candidates:
                    self.current_folder = candidates[0].parent
            except OSError:
                return
        if self.current_folder is None:
            return
        history_path = self.current_folder / "history.json"
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        registry = history.get("finding_registry") or {}
        counts = {key: 0 for key in ("new", "recurring", "changed", "resolved")}
        for item in registry.values():
            status = item.get("status")
            if status in counts:
                counts[status] += 1
        self.stat_vars["total"].set(str(len(registry)))
        for key, value in counts.items():
            self.stat_vars[key].set(str(value))
        self.stat_vars["cycles"].set(str(history.get("cycles_completed", 0)))
        for item in self.table.get_children():
            self.table.delete(item)
        ordered = sorted(registry.values(), key=lambda x: x.get("last_seen", ""), reverse=True)
        for item in ordered:
            self.table.insert("", "end", values=(
                str(item.get("status", "")).upper(),
                str(item.get("severity", "n/a")).upper(),
                item.get("title", "Untitled"),
                item.get("finding_id", ""),
                item.get("occurrences", 0),
                item.get("last_seen", ""),
            ))

    def show_finding_details(self, _event=None):
        selected = self.table.selection()
        if not selected or self.current_folder is None:
            return
        values = self.table.item(selected[0], "values")
        if not values:
            return
        finding_id = values[3]
        try:
            history = json.loads((self.current_folder / "history.json").read_text(encoding="utf-8"))
            item = history.get("finding_registry", {}).get(finding_id, {})
        except (OSError, json.JSONDecodeError):
            return
        detail = tk.Toplevel(self.root)
        detail.title("Discovery details")
        detail.geometry("720x520")
        detail.configure(bg="#191b23")
        body = tk.Text(detail, bg="#11131a", fg="#e7e8ed", insertbackground="white",
                       relief="flat", wrap="word", padx=14, pady=12, font=("Consolas", 9))
        body.pack(fill="both", expand=True, padx=12, pady=12)
        fields = [
            ("Title", item.get("title")), ("Status", item.get("status")),
            ("Severity", item.get("severity")), ("Category", item.get("category")),
            ("Finding ID", item.get("finding_id")), ("Resource ID", item.get("resource_id")),
            ("Behavior ID", item.get("behavior_id")), ("Evidence ID", item.get("evidence_id")),
            ("Test ID", item.get("test_id")), ("URL", item.get("url")),
            ("First seen", item.get("first_seen")), ("Last seen", item.get("last_seen")),
            ("Occurrences", item.get("occurrences")), ("Description", item.get("description")),
            ("Evidence", item.get("evidence")), ("Remediation", item.get("remediation")),
        ]
        body.insert("end", "\n\n".join(f"{label}:\n{value or 'Not available'}" for label, value in fields))
        body.configure(state="disabled")

    def open_data_folder(self):
        folder = self.current_folder or app_data_dir()
        if sys.platform == "win32":
            os.startfile(str(folder))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(folder)])
        else:
            subprocess.Popen(["xdg-open", str(folder)])

    def _on_close(self):
        process = self.process
        if process is not None and process.poll() is None:
            if not messagebox.askyesno("Stop scanner?", "Stop the active watch and close Darth Scanner?"):
                return
            process.terminate()
        self.root.destroy()


def main():
    root = tk.Tk()
    DarthScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
