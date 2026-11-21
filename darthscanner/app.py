"""Persistent local desktop dashboard for Darth Scanner.

The GUI stores per-target reports and history under the user's local app-data
directory. Active checks require an explicit ownership/authorization confirmation
and generate an exact-host scope file for the entered URL.
"""
from __future__ import annotations

import json
import os
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
import queue
import subprocess
import sys
import threading
import tkinter as tk
from urllib.parse import urlsplit
from tkinter import messagebox, ttk
from .identity import target_id, resource_id
from .app_utils import parse_target_url
from .watch import run_watch


APP_NAME = "Darth Scanner"
MIN_INTERVAL = 30


class _QueueWriter:
    """Send scanner output to the in-app activity feed instead of a terminal."""
    def __init__(self, events: queue.Queue):
        self.events = events

    def write(self, value: str) -> int:
        for line in value.splitlines():
            if line.strip():
                self.events.put(("log", line.rstrip()))
        return len(value)

    def flush(self) -> None:
        return None


def app_data_dir() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".local" / "share"))
    folder = root / "DarthScanner"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


class DarthScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Darth Scanner")
        self.root.geometry("1240x820")
        self.root.minsize(980, 680)
        self.root.configure(bg="#0b0e14")
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.stop_event = threading.Event()
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
        style.configure("Treeview", background="#151d2a", foreground="#e8edf5",
                        fieldbackground="#151d2a", rowheight=34, borderwidth=0,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#253247", foreground="#f3f6fb",
                        relief="flat", padding=(9, 10), font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#34465f")], foreground=[("selected", "#ffffff")])
        style.configure("TCombobox", fieldbackground="#20232c", foreground="#f4f4f6")

    def _build(self):
        header = tk.Frame(self.root, bg="#111722", padx=22, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="DARTH SCANNER", bg="#111722", fg="#f7f9fc",
                 font=("Segoe UI", 20, "bold")).pack(side="left")
        tk.Label(header, text="DISCOVERY COMMAND  •  LOCAL WORKSPACE",
                 bg="#111722", fg="#a5a9b8", font=("Segoe UI", 9)).pack(side="left", padx=18, pady=(7, 0))
        self.status = tk.Label(header, text="● IDLE", bg="#111722", fg="#a8adb9",
                               font=("Segoe UI", 9, "bold"))
        self.status.pack(side="right", pady=(7, 0))

        main = tk.Frame(self.root, bg="#0b0e14", padx=20, pady=16)
        main.pack(fill="both", expand=True)

        target_panel = tk.Frame(main, bg="#151d2a", padx=15, pady=13)
        target_panel.pack(fill="x")
        tk.Label(target_panel, text="TARGET WEBSITE", bg="#151d2a", fg="#f3f6fb",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        entry_row = tk.Frame(target_panel, bg="#151d2a")
        entry_row.pack(fill="x", pady=(8, 5))
        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(entry_row, textvariable=self.url_var, bg="#202a3a",
                                  fg="#f7f9fc", insertbackground="white", relief="flat",
                                  font=("Consolas", 11))
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=9, padx=(0, 9))
        self.url_entry.bind("<Return>", self._on_target_change)
        self.url_entry.bind("<FocusOut>", self._on_target_change)
        self.start_button = tk.Button(entry_row, text="START WATCH", command=self.start_watch,
                                      bg="#c0263d", fg="white", activebackground="#e03b55",
                                      relief="flat", padx=17, pady=8, font=("Segoe UI", 9, "bold"))
        self.start_button.pack(side="left", padx=3)
        self.stop_button = tk.Button(entry_row, text="STOP", command=self.stop_watch,
                                     bg="#263447", fg="white", activebackground="#45495a",
                                     relief="flat", padx=17, pady=8, font=("Segoe UI", 9, "bold"),
                                     state="disabled")
        self.stop_button.pack(side="left", padx=3)
        self.authorized_var = tk.BooleanVar(value=False)
        self.include_subdomains_var = tk.BooleanVar(value=False)
        self.cve_lookup_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            target_panel,
            text="I own this website or have explicit permission to run security checks against it.",
            variable=self.authorized_var, bg="#151d2a", fg="#d7d9e0",
            activebackground="#151d2a", activeforeground="white", selectcolor="#202a3a",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 0))
        tk.Checkbutton(
            target_panel,
            text="Include subdomains (passive discovery, then bounded read-only checks)",
            variable=self.include_subdomains_var, bg="#151d2a", fg="#d7d9e0",
            activebackground="#151d2a", activeforeground="white", selectcolor="#202a3a",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 0))
        tk.Checkbutton(
            target_panel,
            text="Automatically check detected software versions against the NVD CVE database",
            variable=self.cve_lookup_var, bg="#151d2a", fg="#d7d9e0",
            activebackground="#151d2a", activeforeground="white", selectcolor="#202a3a",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 0))
        tk.Label(target_panel, text="For subdomain mode, enter the root/apex domain (example.com, not www.example.com). You must be authorized for the entire domain and all its subdomains.",
                 bg="#151d2a", fg="#9eabc0", font=("Segoe UI", 8)).pack(anchor="w", pady=(5, 0))

        stats = tk.Frame(main, bg="#0b0e14")
        stats.pack(fill="x", pady=12)
        self.stat_vars = {}
        for key, label in [("total", "UNIQUE FINDINGS"), ("new", "NEW"), ("recurring", "RECURRING"),
                           ("changed", "CHANGED"), ("resolved", "RESOLVED"), ("cycles", "SCAN CYCLES")]:
            card = tk.Frame(stats, bg="#151d2a", padx=13, pady=10)
            card.pack(side="left", fill="x", expand=True, padx=(0, 7))
            tk.Label(card, text=label, bg="#151d2a", fg="#9eabc0",
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            var = tk.StringVar(value="0")
            self.stat_vars[key] = var
            tk.Label(card, textvariable=var, bg="#151d2a", fg="#f4f4f6",
                     font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(3, 0))

        split = tk.PanedWindow(main, orient="vertical", bg="#0b0e14", sashwidth=6,
                               sashrelief="flat", bd=0)
        split.pack(fill="both", expand=True)
        findings_panel = tk.Frame(split, bg="#151d2a", padx=12, pady=10)
        split.add(findings_panel, minsize=190)
        title_row = tk.Frame(findings_panel, bg="#151d2a")
        title_row.pack(fill="x", pady=(0, 8))
        tk.Label(title_row, text="DISCOVERY REGISTRY", bg="#151d2a", fg="#f3f6fb",
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Button(title_row, text="REFRESH", command=self.refresh_dashboard, bg="#253247",
                  fg="white", relief="flat", padx=10, pady=4).pack(side="right")
        tk.Button(title_row, text="OPEN DATA FOLDER", command=self.open_data_folder, bg="#253247",
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
        self.table.bind("<<TreeviewSelect>>", self.show_finding_details)
        self.table.bind("<Return>", self.show_finding_details)

        log_panel = tk.Frame(split, bg="#151d2a", padx=12, pady=10)
        split.add(log_panel, minsize=130)
        tk.Label(log_panel, text="LIVE ACTIVITY", bg="#151d2a", fg="#f3f6fb",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 7))
        self.log = tk.Text(log_panel, height=7, bg="#0c121c", fg="#cbd0dc",
                           insertbackground="white", relief="flat", wrap="word",
                           font=("Consolas", 9), state="disabled")
        self.log.pack(fill="both", expand=True)
        footer = tk.Label(main, text="Local-only dashboard • History persists between launches • Continuous watch stops when you press STOP or close the app",
                          bg="#0b0e14", fg="#8995a8", font=("Segoe UI", 8))
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
        if self.worker is not None and self.worker.is_alive():
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
            f"Authorized root hostname: {host}\n\n"
            + ("Subdomain discovery and checks: ENABLED (up to 25 discovered hosts; shared request/page budgets).\n\n" if self.include_subdomains_var.get() else "Subdomain discovery: disabled.\n\n")
            + ("NVD CVE identification: ENABLED (detected product versions are checked against the NVD database).\n\n" if self.cve_lookup_var.get() else "NVD CVE identification: disabled.\n\n")
            + "Only proceed if you have permission for the root host and, when enabled, the entire domain and all its subdomains. The app will keep checking until you stop it."
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
            "include_subdomains": bool(self.include_subdomains_var.get()),
            "root_domain": host if self.include_subdomains_var.get() else None,
            "max_pages": 30 if self.include_subdomains_var.get() else 12,
            "max_requests": 24,
            "request_delay_seconds": 1.0,
            "timeout_seconds": 8,
        }
        scope_path.write_text(json.dumps(scope, indent=2), encoding="utf-8")
        self.current_target = target
        self.current_folder = output_dir
        self.url_var.set(target)
        # Switch the visible dashboard immediately; never leave another target's
        # findings on screen while this target's first report is being created.
        self._clear_dashboard()
        self.refresh_dashboard()
        self._log(f"Starting authorized watch: {target}")
        if self.include_subdomains_var.get():
            self._log(f"Subdomain mode enabled for {host}; discovery is passive and checks are bounded.")
        self._log(f"Persistent data: {output_dir}")
        self.stop_event.clear()
        self._set_running(True)
        self.worker = threading.Thread(
            target=self._run_process,
            args=(target, scope_path, output_dir, bool(self.cve_lookup_var.get())),
            daemon=True,
        )
        self.worker.start()

    def _run_process(self, target: str, scope_path: Path, output_dir: Path, cve_lookup: bool):
        """Run the scheduler in this app process and stream all output into the UI."""
        writer = _QueueWriter(self.events)
        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                code = run_watch(
                    target=target,
                    scope_path=str(scope_path),
                    acknowledge_authorization=True,
                    output_dir=str(output_dir),
                    interval=MIN_INTERVAL,
                    stop_event=self.stop_event,
                    cve_lookup=cve_lookup,
                )
            self.events.put(("exit", f"Watch stopped (status {code})."))
        except Exception as exc:
            self.events.put(("exit", f"Scanner error: {exc}"))

    def stop_watch(self):
        if self.worker is not None and self.worker.is_alive():
            self._log("Stop requested — finishing the current bounded check...")
            self.stop_event.set()
            self.stop_button.configure(state="disabled", text="STOPPING…")

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
                    self.worker = None
                    self._set_running(False)
                    self.stop_button.configure(text="STOP", state="disabled")
                    self.refresh_dashboard()
        except queue.Empty:
            pass
        self.root.after(150, self._poll_events)

    def _clear_dashboard(self):
        """Reset all target-specific counters and rows before loading another site."""
        for key in ("total", "new", "recurring", "changed", "resolved", "cycles"):
            self.stat_vars[key].set("0")
        for item in self.table.get_children():
            self.table.delete(item)

    def _on_target_change(self, _event=None):
        """Preview the selected site's own saved history when the URL is edited."""
        try:
            target, _host = parse_target_url(self.url_var.get())
        except ValueError:
            self.current_target = None
            self.current_folder = None
            self._clear_dashboard()
            return
        if target == self.current_target:
            return
        folder = app_data_dir() / (target_id(target) + "-" + resource_id(target))
        self.current_target = target
        self.current_folder = folder / "reports"
        self._clear_dashboard()
        self.refresh_dashboard()

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
            # A new target has no history yet. Keep its dashboard empty rather
            # than displaying the previous target's stale findings.
            self._clear_dashboard()
            return
        registry = history.get("finding_registry") or {}
        if not self.url_var.get().strip() and history.get("target"):
            self.url_var.set(history["target"])
            self.current_target = history["target"]
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
        """Show a structured analyst view when a finding is selected."""
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
        if not item:
            return

        detail = tk.Toplevel(self.root)
        detail.title("Finding intelligence | Darth Scanner")
        detail.geometry("920x740")
        detail.minsize(720, 560)
        detail.configure(bg="#0b1019")
        detail.transient(self.root)

        severity = str(item.get("severity", "unknown")).upper()
        colors = {
            "CRITICAL": ("#4b1720", "#ff7185"),
            "HIGH": ("#49251b", "#ff9b72"),
            "MEDIUM": ("#44351a", "#f4c66b"),
            "LOW": ("#183b35", "#70d6b0"),
            "INFO": ("#1b3048", "#8fc5ff"),
        }
        badge_bg, badge_fg = colors.get(severity, ("#263247", "#c4d0e2"))

        shell = tk.Frame(detail, bg="#0b1019")
        shell.pack(fill="both", expand=True)
        canvas = tk.Canvas(shell, bg="#0b1019", highlightthickness=0)
        scroll = ttk.Scrollbar(shell, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        page = tk.Frame(canvas, bg="#0b1019", padx=24, pady=22)
        page_id = canvas.create_window((0, 0), window=page, anchor="nw")
        page.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(page_id, width=e.width))

        hero = tk.Frame(page, bg="#111b29", padx=20, pady=18,
                        highlightthickness=1, highlightbackground="#293b52")
        hero.pack(fill="x", pady=(0, 14))
        tk.Label(hero, text="DARTH SCANNER  /  FINDING INTELLIGENCE",
                 bg="#111b29", fg="#8fa4bf", font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(hero, text=str(item.get("title", "Untitled finding")),
                 bg="#111b29", fg="#f4f7fb", font=("Segoe UI", 19, "bold"),
                 wraplength=800, justify="left").pack(anchor="w", pady=(9, 12))
        chips = tk.Frame(hero, bg="#111b29")
        chips.pack(anchor="w")
        tk.Label(chips, text="  " + severity + "  ", bg=badge_bg, fg=badge_fg,
                 font=("Segoe UI", 9, "bold"), padx=7, pady=4).pack(side="left", padx=(0, 7))
        tk.Label(chips, text="  " + str(item.get("status", "unknown")).upper() + "  ",
                 bg="#24364d", fg="#c8d8ec", font=("Segoe UI", 9, "bold"),
                 padx=7, pady=4).pack(side="left")
        tk.Label(hero, text="Category: " + str(item.get("category", "unknown")) +
                 "    |    Seen: " + str(item.get("occurrences", 0)) + " time(s)",
                 bg="#111b29", fg="#aab9cb", font=("Segoe UI", 9)).pack(anchor="w", pady=(12, 0))

        def section(title, value, accent="#8fc5ff"):
            card = tk.Frame(page, bg="#141e2d", padx=16, pady=13,
                            highlightthickness=1, highlightbackground="#26364b")
            card.pack(fill="x", pady=(0, 12))
            tk.Label(card, text=title.upper(), bg="#141e2d", fg=accent,
                     font=("Segoe UI", 9, "bold")).pack(anchor="w")
            raw = str(value or "Not available")
            box = tk.Text(card, height=max(2, min(8, len(raw) // 95 + 2)),
                          bg="#0e1724", fg="#e4ebf5", relief="flat", wrap="word",
                          padx=11, pady=9, font=("Segoe UI", 10), borderwidth=0)
            box.pack(fill="x", pady=(8, 0))
            box.insert("1.0", raw)
            box.configure(state="disabled")

        source_url = item.get("source_url") or item.get("url") or history.get("target", "")
        try:
            parsed_source = urlsplit(str(source_url))
            source_site = parsed_source.netloc or parsed_source.path.split("/")[0]
            if not source_site:
                source_site = "Not available"
        except ValueError:
            source_site = "Not available"

        section("Source website", source_site, "#70d6b0")
        section("CVE identifier(s)", ", ".join(item.get("cve_ids") or []) or
                "No directly applicable CVE identified from the available evidence.", "#ff9b72")
        cvss = item.get("cvss_score")
        cvss_text = f"CVSS {item.get('cvss_version') or ''} {cvss}/10".strip() if cvss is not None else "Not scored"
        section("CVSS severity score", cvss_text, "#f4c66b")
        section("Affected software component", item.get("affected_component"))
        section("CVE references", "\n".join(item.get("references") or []), "#8fc5ff")
        section("What the scanner detected", item.get("description"))
        section("Why this may matter", item.get("impact") or
                "This is an automated observation, not proof of exploitability. Review the evidence and affected component in context before treating it as a vulnerability.",
                "#f4c66b")
        section("Exact source code / response snippet",
                (f"Line {item.get('source_line')}:\n" if item.get("source_line") else "")
                + (item.get("source_excerpt") or
                   "No source-code snippet applies to this finding. The evidence is based on response headers or metadata."),
                "#70d6b0")
        section("Evidence collected", item.get("evidence"), "#70d6b0")
        section("Recommended remediation", item.get("remediation"))
        section("Affected URL", item.get("url"))

        meta = tk.Frame(page, bg="#141e2d", padx=16, pady=13,
                        highlightthickness=1, highlightbackground="#26364b")
        meta.pack(fill="x", pady=(0, 12))
        tk.Label(meta, text="TRACKING AND HISTORY", bg="#141e2d", fg="#8fa4bf",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 8))
        fields = [
            ("Finding ID", "finding_id"), ("Resource ID", "resource_id"),
            ("Behavior ID", "behavior_id"), ("Evidence ID", "evidence_id"),
            ("Test ID", "test_id"), ("First seen", "first_seen"),
            ("Last seen", "last_seen"), ("Occurrences", "occurrences"),
        ]
        for label, key in fields:
            row = tk.Frame(meta, bg="#141e2d")
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, width=17, anchor="w", bg="#141e2d",
                     fg="#8fa4bf", font=("Segoe UI", 9)).pack(side="left")
            tk.Label(row, text=str(item.get(key) or "Not available"), anchor="w",
                     bg="#141e2d", fg="#dce5f0", font=("Consolas", 9),
                     wraplength=650, justify="left").pack(side="left", fill="x", expand=True)

        footer = tk.Frame(page, bg="#0b1019")
        footer.pack(fill="x", pady=(2, 12))
        tk.Label(footer, text="Automated findings require human review. Severity is an estimate.",
                 bg="#0b1019", fg="#8292a8", font=("Segoe UI", 8)).pack(side="left")
        tk.Button(footer, text="CLOSE", command=detail.destroy, bg="#293b52",
                  fg="#f4f7fb", activebackground="#354b67", relief="flat",
                  padx=18, pady=8, font=("Segoe UI", 9, "bold")).pack(side="right")

        def wheel(event):
            if getattr(event, "delta", 0):
                canvas.yview_scroll(int(-event.delta / 120), "units")
        canvas.bind_all("<MouseWheel>", wheel)
        detail.bind("<Destroy>", lambda _e: canvas.unbind_all("<MouseWheel>"))

    def open_data_folder(self):
        folder = self.current_folder or app_data_dir()
        if sys.platform == "win32":
            os.startfile(str(folder))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(folder)])
        else:
            subprocess.Popen(["xdg-open", str(folder)])

    def _on_close(self):
        worker_running = self.worker is not None and self.worker.is_alive()
        if worker_running:
            if not messagebox.askyesno("Stop scanner?", "Stop the active check and close Darth Scanner?"):
                return
            self.stop_event.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    DarthScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
