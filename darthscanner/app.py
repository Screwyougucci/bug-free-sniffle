"""Persistent local desktop dashboard for Darth Scanner.

The GUI stores per-target reports and history under the user's local app-data
directory. Active checks require an explicit ownership/authorization confirmation
and generate an exact-host scope file for the entered URL.
"""
from __future__ import annotations

import json
import os
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from pathlib import Path
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from urllib.parse import urlsplit
from tkinter import messagebox, ttk
from .identity import target_id, resource_id, update_full_scan_history
from .app_utils import parse_target_url
from .watch import run_watch, _load_history, _save_history
from .fuzzer import discover_query_parameters, observations_to_dict, run_fuzz_suite, sanitize_url
from .http_client import SafeHttpClient
from .scope import load_scope, Scope
from .github_audit import audit_github_repository, discover_github_repositories
from .exploitability import analyze_exploitability
from .fuzz_reports import build_fuzz_finding_reports
from .fuzz_correlation import correlate_fuzz_observations


APP_NAME = "Darth Scanner"
MIN_INTERVAL = 30


def _enable_windows_dpi_awareness() -> None:
    """Ask Windows for per-monitor DPI rendering before creating Tk windows."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        # PROCESS_PER_MONITOR_DPI_AWARE = 2. Prefer the modern API.
        try:
            # PER_MONITOR_AWARE_V2 (-4) gives modern Windows/Tk the best
            # chance of crisp rendering when moving between mixed-DPI displays.
            if not ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
                raise OSError("Per-monitor v2 DPI awareness unavailable")
        except (AttributeError, OSError):
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except (AttributeError, OSError):
                ctypes.windll.user32.SetProcessDPIAware()
    except (AttributeError, OSError):
        # Keep the app usable on systems where DPI APIs are unavailable.
        pass


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
        self.deep_scan_button = tk.Button(entry_row, text="DEEP CRAWL", command=self.start_deep_scan,
                                           bg="#9b2438", fg="white", activebackground="#bd334b",
                                           relief="flat", padx=15, pady=8, font=("Segoe UI", 9, "bold"))
        self.deep_scan_button.pack(side="left", padx=3)
        self.start_button = tk.Button(entry_row, text="START WATCH", command=self.start_watch,
                                      bg="#c0263d", fg="white", activebackground="#e03b55",
                                      relief="flat", padx=17, pady=8, font=("Segoe UI", 9, "bold"))
        self.start_button.pack(side="left", padx=3)
        self.stop_button = tk.Button(entry_row, text="STOP", command=self.stop_watch,
                                     bg="#263447", fg="white", activebackground="#45495a",
                                     relief="flat", padx=17, pady=8, font=("Segoe UI", 9, "bold"),
                                     state="disabled")
        self.stop_button.pack(side="left", padx=3)
        self.fuzz_button = tk.Button(entry_row, text="FUZZ LAB", command=self.show_fuzz_lab,
                                     bg="#34445b", fg="white", activebackground="#465c79",
                                     relief="flat", padx=17, pady=8, font=("Segoe UI", 9, "bold"))
        self.fuzz_button.pack(side="left", padx=3)

        engine_row = tk.Frame(target_panel, bg="#151d2a")
        engine_row.pack(fill="x", pady=(8, 2))
        self.zap_button = tk.Button(engine_row, text="OWASP ZAP ENGINE", command=self.start_zap_scan,
                                    bg="#9b2438", fg="white", activebackground="#bd334b",
                                    relief="flat", padx=17, pady=8, font=("Segoe UI", 9, "bold"))
        self.zap_button.pack(side="left", padx=(0, 8))
        tk.Button(engine_row, text="GET ZAP", command=self.open_zap_download,
                  bg="#253247", fg="white", relief="flat", padx=12, pady=8,
                  font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 12))
        self.zap_active_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            engine_row,
            text="Enable active scan (sends test requests; separate confirmation)",
            variable=self.zap_active_var, bg="#151d2a", fg="#d7d9e0",
            activebackground="#151d2a", activeforeground="white", selectcolor="#202a3a",
            font=("Segoe UI", 9),
        ).pack(side="left")

        github_row = tk.Frame(target_panel, bg="#151d2a")
        github_row.pack(fill="x", pady=(8, 2))
        tk.Label(github_row, text="GITHUB REPOSITORY", bg="#151d2a", fg="#aebbd0",
                 font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 10))
        self.github_repo_var = tk.StringVar()
        self.github_repo_entry = tk.Entry(github_row, textvariable=self.github_repo_var,
                                          bg="#202a3a", fg="#f7f9fc", insertbackground="white",
                                          relief="flat", font=("Consolas", 10))
        self.github_repo_entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 9))
        self.github_audit_button = tk.Button(github_row, text="GITHUB CODE AUDIT",
                                             command=self.start_github_audit,
                                             bg="#40516b", fg="white", activebackground="#566d8e",
                                             relief="flat", padx=14, pady=7,
                                             font=("Segoe UI", 9, "bold"))
        self.github_audit_button.pack(side="left", padx=(0, 5))
        tk.Button(github_row, text="VIEW REPORT", command=self.open_github_report,
                  bg="#253247", fg="white", relief="flat", padx=11, pady=7,
                  font=("Segoe UI", 9, "bold")).pack(side="left")
        self.authorized_var = tk.BooleanVar(value=False)
        self.github_auto_var = tk.BooleanVar(value=True)
        self.include_subdomains_var = tk.BooleanVar(value=False)
        self.subdomain_depth_var = tk.IntVar(value=5)
        self.subdomain_hosts_var = tk.IntVar(value=25)
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
            text="Also discover and audit a linked GitHub repository when START WATCH begins",
            variable=self.github_auto_var, bg="#151d2a", fg="#d7d9e0",
            activebackground="#151d2a", activeforeground="white", selectcolor="#202a3a",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 0))
        tk.Checkbutton(
            target_panel,
            text="Include subdomains (passive discovery, then bounded read-only checks)",
            variable=self.include_subdomains_var, bg="#151d2a", fg="#d7d9e0",
            activebackground="#151d2a", activeforeground="white", selectcolor="#202a3a",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 0))
        discovery_settings = tk.Frame(target_panel, bg="#151d2a")
        discovery_settings.pack(anchor="w", pady=(5, 0))
        tk.Label(discovery_settings, text="Max depth", bg="#151d2a", fg="#aebbd0",
                 font=("Segoe UI", 8)).pack(side="left")
        tk.Spinbox(discovery_settings, from_=1, to=8, width=4, textvariable=self.subdomain_depth_var,
                   bg="#202a3a", fg="#f7f9fc", insertbackground="white", relief="flat").pack(side="left", padx=(6, 16))
        tk.Label(discovery_settings, text="Max hosts", bg="#151d2a", fg="#aebbd0",
                 font=("Segoe UI", 8)).pack(side="left")
        tk.Spinbox(discovery_settings, from_=1, to=100, width=5, textvariable=self.subdomain_hosts_var,
                   bg="#202a3a", fg="#f7f9fc", insertbackground="white", relief="flat").pack(side="left", padx=(6, 0))

        tk.Checkbutton(
            target_panel,
            text="Automatically check detected software versions against the NVD CVE database",
            variable=self.cve_lookup_var, bg="#151d2a", fg="#d7d9e0",
            activebackground="#151d2a", activeforeground="white", selectcolor="#202a3a",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(6, 0))
        tk.Label(target_panel, text="Enter the root/apex domain. Recursive discovery is passive; active checks require authorization for the entire domain and all subdomains.",
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
        self.show_hardening_var = tk.BooleanVar(value=False)
        tk.Checkbutton(title_row, text="Show hardening advice", variable=self.show_hardening_var,
                       command=self.refresh_dashboard, bg="#151d2a", fg="#b8c5d8",
                       activebackground="#151d2a", activeforeground="white",
                       selectcolor="#202a3a", font=("Segoe UI", 8)).pack(side="left", padx=12)
        tk.Button(title_row, text="REFRESH", command=self.refresh_dashboard, bg="#253247",
                  fg="white", relief="flat", padx=10, pady=4).pack(side="right")
        tk.Button(title_row, text="DOMAIN TREE", command=self.show_domain_tree, bg="#253247",
                  fg="white", relief="flat", padx=10, pady=4).pack(side="right", padx=6)
        tk.Button(title_row, text="OPEN DATA FOLDER", command=self.open_data_folder, bg="#253247",
                  fg="white", relief="flat", padx=10, pady=4).pack(side="right", padx=6)

        columns = ("status", "type", "severity", "cvss", "title", "finding_id", "occurrences", "last_seen")
        self.table = ttk.Treeview(findings_panel, columns=columns, show="headings", height=8)
        widths = {"status": 95, "type": 105, "severity": 80, "cvss": 100, "title": 300, "finding_id": 190,
                  "occurrences": 85, "last_seen": 155}
        labels = {"status": "STATUS", "type": "CLASS", "severity": "SEVERITY", "cvss": "CVSS", "title": "DISCOVERY",
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
        self.status.configure(text="● RUNNING" if running else "● IDLE",
                              fg="#e4a0a8" if running else "#a8adb9")
        self.start_button.configure(state="disabled" if running else "normal")
        self.deep_scan_button.configure(state="disabled" if running else "normal")
        self.zap_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.fuzz_button.configure(state="disabled" if running else "normal")
        self.github_audit_button.configure(state="disabled" if running else "normal")

    def start_github_audit(self):
        if self.worker is not None and self.worker.is_alive():
            return
        if not self.authorized_var.get():
            messagebox.showwarning("Authorization required",
                                   "Confirm that you own the website or have explicit permission to assess it.")
            return
        try:
            target, host = parse_target_url(self.url_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid website", str(exc))
            return

        repository = self.github_repo_var.get().strip()
        if not repository:
            try:
                scope = Scope(authorized=True, allowed_hosts=(host,), max_requests=1,
                              request_delay_seconds=0.5, timeout_seconds=8)
                response = SafeHttpClient(scope, max_requests=1).get(target)
                if response.status is None or response.status >= 400:
                    raise ValueError("Could not read the website landing page for passive GitHub-link discovery.")
                candidates = discover_github_repositories(response.text, limit=10)
            except Exception as exc:
                messagebox.showerror("GitHub discovery failed", str(exc))
                return
            if not candidates:
                messagebox.showinfo("No GitHub links found",
                                    "No public GitHub repository link was found on the website landing page. Paste a repository URL to scan it manually.")
                return
            repository = candidates[0]
            self.github_repo_var.set(repository)
            self._log(f"GitHub discovery found {len(candidates)} repository link(s): {', '.join(candidates)}")
            if len(candidates) > 1:
                self._log("Selected the first discovered repository. Paste another candidate into the field to review it instead.")

        if not messagebox.askyesno(
            "Confirm repository authorization",
            f"Run a bounded, read-only source review of:\n\n{repository}\n\n"
            "Confirm you own this repository or have explicit permission to inspect its source. "
            "Darth Scanner will not execute code or modify repository files."
        ):
            return

        folder = app_data_dir() / (target_id(target) + "-" + resource_id(target)) / "github-source-audit"
        folder.mkdir(parents=True, exist_ok=True)
        self.stop_event.clear()
        self._set_running(True)
        self.stop_button.configure(state="disabled")
        self._log(f"Starting read-only GitHub source audit: {repository}")
        self.worker = threading.Thread(target=self._run_github_audit,
                                       args=(repository, folder), daemon=True)
        self.worker.start()

    def open_github_report(self):
        try:
            target, _host = parse_target_url(self.url_var.get())
        except ValueError as exc:
            messagebox.showerror("Select a website", str(exc))
            return
        folder = app_data_dir() / (target_id(target) + "-" + resource_id(target)) / "github-source-audit"
        report = folder / "latest-report.json"
        if not report.exists():
            messagebox.showinfo("No GitHub report", "Run a GitHub code audit first. Its report will be saved with this website's local scan history.")
            return
        try:
            if sys.platform == "win32":
                os.startfile(str(report))
            else:
                webbrowser.open(report.as_uri())
        except OSError as exc:
            messagebox.showerror("Could not open report", str(exc))

    def _run_github_audit(self, repository: str, output_dir: Path):
        try:
            findings, summary = audit_github_repository(repository, stop_event=self.stop_event)
            payload = {
                "tool": APP_NAME,
                "version": "0.25.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "repository": summary,
                "finding_count": len(findings),
                "findings": [item.to_dict() for item in findings],
                "disclaimer": "Static source matches are unconfirmed review leads. No code was executed and no repository content was modified.",
            }
            output = output_dir / "latest-report.json"
            output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            self.events.put(("log", f"GitHub review complete: {summary['files_reviewed']} files, {len(findings)} source finding(s)."))
            self.events.put(("log", f"Repository access: {summary['access_mode']}; bytes reviewed: {summary['bytes_reviewed']}. Dependency manifests: {len(summary['dependency_manifests'])}."))
            self.events.put(("log", f"GitHub source evidence saved: {output}"))
            self.events.put(("exit", "GitHub source review complete."))
        except Exception as exc:
            self.events.put(("exit", f"GitHub source audit error: {exc}"))

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
            + (f"Recursive subdomain discovery: ENABLED (depth up to {self.subdomain_depth_var.get()}, up to {self.subdomain_hosts_var.get()} DNS-verified hosts; shared request/page budgets).\n\n" if self.include_subdomains_var.get() else "Subdomain discovery: disabled.\n\n")
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
            "max_subdomain_depth": int(self.subdomain_depth_var.get()),
            "max_subdomain_hosts": int(self.subdomain_hosts_var.get()),
            "request_delay_seconds": 1.0,
            "timeout_seconds": 8,
        }
        scope_path.write_text(json.dumps(scope, indent=2), encoding="utf-8")

        github_repo = self.github_repo_var.get().strip() or None
        if self.github_auto_var.get() and not github_repo:
            try:
                first_page = SafeHttpClient(load_scope(scope_path), max_requests=1).get(target)
                if first_page.status is not None and first_page.status < 400:
                    candidates = discover_github_repositories(first_page.text, limit=10)
                    if candidates:
                        github_repo = candidates[0]
                        self.github_repo_var.set(github_repo)
                        self._log(f"Automatic GitHub discovery found {len(candidates)} candidate(s): {', '.join(candidates)}")
                        if len(candidates) > 1:
                            self._log("The first candidate is selected for this run; paste a different repository URL to choose another.")
            except Exception as exc:
                self._log(f"GitHub link discovery skipped: {exc}")
        if github_repo:
            if not messagebox.askyesno(
                "Confirm GitHub repository authorization",
                f"Also perform a read-only source review of:\n\n{github_repo}\n\n"
                "Confirm you own this repository or have explicit permission to inspect it. No code will be executed or modified."
            ):
                github_repo = None
        self.current_target = target
        self.current_folder = output_dir
        self.url_var.set(target)
        # Switch the visible dashboard immediately; never leave another target's
        # findings on screen while this target's first report is being created.
        self._clear_dashboard()
        self.refresh_dashboard()
        self._log(f"Starting authorized watch: {target}")
        if self.include_subdomains_var.get():
            self._log(
                f"Recursive subdomain mode enabled for {host}; depth {scope['max_subdomain_depth']}, "
                f"host limit {scope['max_subdomain_hosts']}. Discovery is passive and active checks are bounded."
            )
        self._log(f"Persistent data: {output_dir}")
        self.stop_event.clear()
        self._set_running(True)
        self.worker = threading.Thread(
            target=self._run_process,
            args=(target, scope_path, output_dir, bool(self.cve_lookup_var.get()), github_repo),
            daemon=True,
        )
        self.worker.start()

    def start_deep_scan(self):
        """Run one full discovery and analysis pass instead of one watch focus."""
        if self.worker is not None and self.worker.is_alive():
            messagebox.showinfo("Deep scan", "Stop the current run before starting a deep scan.")
            return
        if not self.authorized_var.get():
            messagebox.showwarning("Authorization required",
                "Confirm that you own this website or have explicit permission before scanning.")
            return
        try:
            target, host = parse_target_url(self.url_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid website", str(exc))
            return
        if not messagebox.askyesno(
            "Confirm deep authorized scan",
            f"Run a full website crawl and security analysis for:\n\\n{target}\\n\\n"
            f"Budget: up to 150 discovered URL resources and 350 HTTP requests, with a 0.5-second minimum delay. "
            f"Subdomain discovery: {'enabled' if self.include_subdomains_var.get() else 'disabled'}.\\n\\n"
            "The crawl can take several minutes. It follows nested same-origin links, robots.txt and XML sitemaps, iframe routes, JavaScript assets and statically discovered API routes, "
            "but does not execute JavaScript, submit forms, follow redirects, or run destructive exploit tests. "
            "Only proceed if you are authorized for the selected host and any enabled subdomains."
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
            "max_pages": 150,
            "max_requests": 350,
            "max_subdomain_depth": int(self.subdomain_depth_var.get()),
            "max_subdomain_hosts": int(self.subdomain_hosts_var.get()),
            "request_delay_seconds": 0.5,
            "timeout_seconds": 10,
        }
        scope_path.write_text(json.dumps(scope, indent=2), encoding="utf-8")

        github_repo = self.github_repo_var.get().strip() or None
        if self.github_auto_var.get() and not github_repo:
            try:
                first_page = SafeHttpClient(load_scope(scope_path), max_requests=1).get(target)
                if first_page.status is not None and first_page.status < 400:
                    candidates = discover_github_repositories(first_page.text, limit=10)
                    if candidates:
                        github_repo = candidates[0]
                        self.github_repo_var.set(github_repo)
                        self._log(f"GitHub repository candidates discovered: {', '.join(candidates)}")
            except Exception as exc:
                self._log(f"GitHub link discovery skipped: {exc}")
        if github_repo and not messagebox.askyesno(
            "Confirm GitHub repository authorization",
            f"Also review this GitHub repository?\\n\\n{github_repo}\\n\\n"
            "Confirm you own it or have explicit permission. Repository code is not executed or modified."
        ):
            github_repo = None

        self.current_target = target
        self.current_folder = output_dir
        self.url_var.set(target)
        self._clear_dashboard()
        self.refresh_dashboard()
        self.stop_event.clear()
        self._set_running(True)
        self.stop_button.configure(state="normal")
        self._log(f"Starting DEEP CRAWL + FULL ANALYSIS: {target}")
        self._log("Crawler enabled: up to 150 URL resources / 350 requests; HTML links, robots/sitemaps, iframes, JavaScript assets and static API routes.")
        self.worker = threading.Thread(
            target=self._run_deep_scan_process,
            args=(target, scope_path, output_dir, bool(self.cve_lookup_var.get()), github_repo),
            daemon=True,
        )
        self.worker.start()

    def _run_deep_scan_process(self, target: str, scope_path: Path, output_dir: Path,
                               cve_lookup: bool, github_repo: str | None = None):
        """Run one full scan and optional authorized GitHub source audit."""
        writer = _QueueWriter(self.events)
        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                if github_repo:
                    try:
                        self.events.put(("log", f"Starting linked GitHub source review: {github_repo}"))
                        github_findings, github_summary = audit_github_repository(
                            github_repo, stop_event=self.stop_event
                        )
                        github_dir = output_dir.parent / "github-source-audit"
                        github_dir.mkdir(parents=True, exist_ok=True)
                        github_report = {
                            "tool": APP_NAME, "version": "0.23.0",
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "repository": github_summary, "finding_count": len(github_findings),
                            "findings": [item.to_dict() for item in github_findings],
                            "disclaimer": "Static source matches are unconfirmed review leads; repository code was not executed or modified."
                        }
                        github_path = github_dir / "latest-report.json"
                        github_path.write_text(json.dumps(github_report, indent=2, ensure_ascii=False), encoding="utf-8")
                        self.events.put(("log", f"GitHub audit: {github_summary['files_reviewed']} files, {len(github_findings)} review lead(s)."))
                    except Exception as exc:
                        self.events.put(("log", f"GitHub review skipped; website scan continues: {exc}"))

                from .cli import main as cli_main
                report_path = output_dir / "deep-scan-latest.json"
                command = [
                    "scan", "--target", target, "--scope", str(scope_path),
                    "--acknowledge-authorization", "--profile", "full",
                    "--focus", "all", "--output", str(report_path),
                ]
                if not cve_lookup:
                    command.append("--no-cve-lookup")
                code = cli_main(command, stop_event=self.stop_event)
                if code == 0 and report_path.exists():
                    payload = json.loads(report_path.read_text(encoding="utf-8"))
                    history_path = output_dir / "history.json"
                    history = _load_history(history_path)
                    lifecycle = update_full_scan_history(
                        history,
                        target,
                        payload.get("findings", []),
                        str(report_path),
                    )
                    _save_history(history_path, history)
                    self.events.put((
                        "log",
                        "Dashboard history updated from full scan: "
                        f"{len(payload.get('findings', []))} findings; "
                        f"{len(lifecycle['new'])} new, {len(lifecycle['changed'])} changed, "
                        f"{len(lifecycle['recurring'])} recurring."
                    ))
                self.events.put(("log", f"Full crawl report: {report_path}"))
                self.events.put(("exit", f"Full crawl and analysis finished (status {code})."))
        except Exception as exc:
            self.events.put(("exit", f"Deep scan error: {exc}"))

    def open_zap_download(self):
        """Open the official OWASP ZAP download page."""
        webbrowser.open("https://www.zaproxy.org/download/")

    def start_zap_scan(self):
        """Run the real OWASP ZAP crawler and scanner as a managed local engine."""
        if self.worker is not None and self.worker.is_alive():
            messagebox.showinfo("OWASP ZAP", "Stop the current run before starting a ZAP scan.")
            return
        if not self.authorized_var.get():
            messagebox.showwarning(
                "Authorization required",
                "Confirm that you own this website or have explicit permission before scanning.",
            )
            return
        try:
            target, _host = parse_target_url(self.url_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid website", str(exc))
            return

        active_scan = bool(self.zap_active_var.get())
        summary = (
            f"Run OWASP ZAP's traditional spider, browser-based Client Spider when available, "
            f"and passive vulnerability rules against:\n\n{target}\n\n"
            "The ZAP API will listen only on this computer. Crawl scope is restricted to the exact hostname."
        )
        if not messagebox.askyesno("Confirm OWASP ZAP scan", summary):
            return
        if active_scan and not messagebox.askyesno(
            "Confirm active security testing",
            "ACTIVE SCANNING IS ENABLED. ZAP will send test requests designed to identify vulnerabilities. "
            "This can change application state, trigger alerts, or affect fragile services. "
            "Use only a system you own or are explicitly authorized to test, preferably staging. Continue?",
        ):
            return

        folder = app_data_dir() / (target_id(target) + "-" + resource_id(target))
        output_dir = folder / "zap-engine"
        output_dir.mkdir(parents=True, exist_ok=True)
        self.current_target = target
        self.current_folder = output_dir
        self.url_var.set(target)
        self._clear_dashboard()
        self.refresh_dashboard()
        self.stop_event.clear()
        self._set_running(True)
        self._log(f"Starting OWASP ZAP engine for {target}")
        self._log("Passive spidering and passive rules are enabled; active scanning: " +
                  ("ENABLED after separate confirmation." if active_scan else "OFF."))
        self._log(f"ZAP report folder: {output_dir}")
        self.worker = threading.Thread(
            target=self._run_zap_scan_process,
            args=(target, output_dir, active_scan),
            daemon=True,
        )
        self.worker.start()

    def _run_zap_scan_process(self, target: str, output_dir: Path, active_scan: bool):
        """Run ZAP, normalize its alerts, and merge them into Darth's history."""
        try:
            from .zap_engine import run_zap_scan
            payload = run_zap_scan(
                target,
                active_scan=active_scan,
                stop_event=self.stop_event,
                progress=lambda message: self.events.put(("log", message)),
            )
            payload["tool"] = APP_NAME
            payload["version"] = "0.25.0"
            payload["generated_at"] = datetime.now(timezone.utc).isoformat()
            report_path = output_dir / "latest-report.json"
            report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            history_path = output_dir / "history.json"
            history = _load_history(history_path)
            lifecycle = update_full_scan_history(
                history, target, payload.get("findings", []), str(report_path)
            )
            _save_history(history_path, history)
            self.events.put((
                "log",
                f"OWASP ZAP finished: engine {payload.get('engine_version', 'unknown')}; "
                f"{payload.get('discovered_url_count', 0)} URLs; "
                f"{payload.get('alert_count', 0)} alert(s).",
            ))
            self.events.put((
                "log",
                f"Darth history updated: {len(payload.get('findings', []))} findings; "
                f"{len(lifecycle['new'])} new, {len(lifecycle['changed'])} changed, "
                f"{len(lifecycle['recurring'])} recurring.",
            ))
            self.events.put(("log", f"ZAP evidence report: {report_path}"))
            self.events.put(("exit", "OWASP ZAP scan stopped." if self.stop_event.is_set() else "OWASP ZAP scan complete."))
        except Exception as exc:
            self.events.put(("exit", f"OWASP ZAP engine error: {exc}"))

    def show_fuzz_lab(self):
        """Open the bounded HTTP parameter fuzzing workspace."""
        if self.worker is not None and self.worker.is_alive():
            messagebox.showinfo("Fuzz Lab", "Stop the current scan before starting a fuzzing run.")
            return
        window = tk.Toplevel(self.root)
        window.title("Professional HTTP Fuzz Lab | Darth Scanner")
        window.geometry("760x360")
        window.configure(bg="#0b0e14")
        panel = tk.Frame(window, bg="#151d2a", padx=20, pady=18)
        panel.pack(fill="both", expand=True, padx=16, pady=16)
        tk.Label(panel, text="HTTP PARAMETER FUZZING", bg="#151d2a", fg="#f3f6fb",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(panel, text="Adaptive benign GET mutations • repeated baseline • response-difference evidence",
                 bg="#151d2a", fg="#9eabc0", font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 14))
        tk.Label(panel, text="URL with query parameters", bg="#151d2a", fg="#d7d9e0",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        url_var = tk.StringVar(value=self.url_var.get().strip())
        url_entry = tk.Entry(panel, textvariable=url_var, bg="#202a3a", fg="#f7f9fc",
                             insertbackground="white", relief="flat", font=("Consolas", 10))
        url_entry.pack(fill="x", ipady=8, pady=(5, 12))
        controls = tk.Frame(panel, bg="#151d2a")
        controls.pack(anchor="w")
        tk.Label(controls, text="Max cases / parameter", bg="#151d2a", fg="#aebbd0").pack(side="left")
        cases_var = tk.IntVar(value=12)
        tk.Spinbox(controls, from_=1, to=32, width=5, textvariable=cases_var,
                   bg="#202a3a", fg="#f7f9fc", insertbackground="white", relief="flat").pack(side="left", padx=(7, 18))
        tk.Label(controls, text="Max parameters", bg="#151d2a", fg="#aebbd0").pack(side="left")
        params_var = tk.IntVar(value=7)
        tk.Spinbox(controls, from_=1, to=7, width=5, textvariable=params_var,
                   bg="#202a3a", fg="#f7f9fc", insertbackground="white", relief="flat").pack(side="left", padx=7)
        tk.Label(panel, text="GET only. No form submission, uploads, credential guessing, redirect following, or exploit payloads. "
                 "The run shares a 24-request budget. Promising GET-only signals are automatically repeated once when budget allows; only hashes and metadata are saved, never response bodies or raw test values.",
                 bg="#151d2a", fg="#9eabc0", font=("Segoe UI", 8), wraplength=680,
                 justify="left").pack(anchor="w", pady=(14, 10))

        def begin():
            if not self.authorized_var.get():
                messagebox.showwarning("Authorization required",
                    "Confirm the ownership/permission checkbox in the main window first.")
                return
            try:
                target, host = parse_target_url(url_var.get())
                max_cases = int(cases_var.get())
                max_params = int(params_var.get())
                if not 1 <= max_cases <= 32 or not 1 <= max_params <= 7:
                    raise ValueError("Cases must be 1–32 and parameters 1–7 (one request is reserved for automatic verification).")
                parameters = discover_query_parameters(url_var.get().strip(), max_params)
                if not parameters:
                    raise ValueError("Enter a URL containing at least one query parameter.")
            except (ValueError, TypeError) as exc:
                messagebox.showerror("Invalid fuzz target", str(exc))
                return
            if not messagebox.askyesno(
                "Confirm authorized fuzzing",
                f"Run bounded GET fuzzing against {target}?\n\n"
                f"Parameters: {', '.join(parameters)}\n"
                f"Maximum cases per parameter: {max_cases}\n"
                f"Maximum requests: 24 (shared across all parameters)\n\n"
                "Confirm that you are authorized to test this exact host."
            ):
                return
            folder = app_data_dir() / (target_id(target) + "-" + resource_id(target))
            folder.mkdir(parents=True, exist_ok=True)
            fuzz_dir = folder / "fuzz"
            fuzz_dir.mkdir(exist_ok=True)
            scope_path = folder / "fuzz-scope.json"
            scope_path.write_text(json.dumps({
                "authorized": True, "allowed_hosts": [host],
                "max_pages": 1, "max_requests": 24,
                "request_delay_seconds": 1.0, "timeout_seconds": 8,
            }, indent=2), encoding="utf-8")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            output_path = fuzz_dir / f"fuzz-{stamp}.json"
            self.stop_event.clear()
            self._set_running(True)
            self._log(f"Starting authorized fuzz run: {sanitize_url(url_var.get().strip())}")
            self._log(f"Parameters discovered: {', '.join(parameters)}")
            self._log("Fuzzing is GET-only, rate-limited, and capped at 24 requests. One request is reserved for automatic repeatability verification.")
            self.worker = threading.Thread(
                target=self._run_fuzz,
                args=(url_var.get().strip(), scope_path, output_path, max_cases, max_params),
                daemon=True,
            )
            self.worker.start()
            window.destroy()

        tk.Button(panel, text="START FUZZING", command=begin, bg="#c0263d", fg="white",
                  activebackground="#e03b55", relief="flat", padx=18, pady=9,
                  font=("Segoe UI", 9, "bold")).pack(anchor="e", pady=(5, 0))

    def _run_fuzz(self, url: str, scope_path: Path, output_path: Path,
                  max_cases: int, max_params: int):
        """Run one bounded fuzz campaign and persist sanitized evidence."""
        writer = _QueueWriter(self.events)
        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                scope = load_scope(scope_path)
                client = SafeHttpClient(scope, max_requests=scope.max_requests)
                parameters = discover_query_parameters(url, max_params)
                observations = run_fuzz_suite(
                    url, parameters, scope, client, max_cases, stop_event=self.stop_event, auto_verify=True,
                )
                observation_data = observations_to_dict(observations)
                tested_parameters = sorted({item.parameter for item in observations})
                verification_results = [
                    item.automatic_verification for item in observations
                    if item.automatic_verification.get("attempted")
                ]
                repeated_count = sum(
                    item.get("outcome") == "repeatable-observation"
                    for item in verification_results
                )
                finding_reports = build_fuzz_finding_reports(observation_data, output_path.parent / "findings")
                correlations = correlate_fuzz_observations(observation_data)
                correlation_dir = output_path.parent / "correlations"
                correlation_dir.mkdir(parents=True, exist_ok=True)
                (correlation_dir / "index.json").write_text(json.dumps({"tool": APP_NAME, "correlation_count": len(correlations), "correlations": correlations, "note": "Correlated hypotheses only; no exploit is confirmed and no CVSS is assigned."}, indent=2), encoding="utf-8")
                payload = {
                    "tool": APP_NAME,
                    "version": "0.21.0",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "target": sanitize_url(url),
                    "requests_made": client.requests_made,
                    "parameters": tested_parameters,
                    "parameters_skipped_by_budget": [name for name in parameters if name not in tested_parameters],
                    "automatic_verification": {
                        "attempts": len(verification_results),
                        "repeatable_observations": repeated_count,
                        "exploit_confirmed": False,
                        "note": "Automatic checks repeat selected benign GET observations once; repeatability is not proof of exploitability."
                    },
                    "fuzz_observations": observation_data,
                    "exploitability_analysis": analyze_exploitability(observation_data),
                    "correlated_hypotheses": correlations,
                    "finding_reports": [
                        {"report_id": item["report_id"], "category": item["category"],
                         "title": item["title"], "severity_estimate": item["severity_estimate"],
                         "confidence": item["confidence"], "file": "findings/" + item["report_id"] + ".json"}
                        for item in finding_reports
                    ],
                    "anomaly_count": sum(bool(item.signal_types) for item in observations),
                    "disclaimer": "Fuzz anomalies and finding reports are unconfirmed triage leads. No response bodies or raw test values are stored.",
                }
                output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                self.events.put(("log", f"Fuzz run complete: {len(observations)} case(s), {payload['anomaly_count']} anomaly signal(s)."))
                self.events.put(("log", f"Automatic PoC verification: {len(verification_results)} attempt(s), {repeated_count} repeatable observation(s). No exploit is auto-confirmed."))
                if payload["parameters_skipped_by_budget"]:
                    self.events.put(("log", "Parameters skipped to preserve the verification request budget: " + ", ".join(payload["parameters_skipped_by_budget"])))
                self.events.put(("log", f"Exploitability triage produced {len(payload['exploitability_analysis'])} unconfirmed hypothesis/hypotheses for manual validation."))
                self.events.put(("log", f"Created {len(finding_reports)} separate vulnerability-pattern evidence report(s)."))
                self.events.put(("log", f"Correlated {len(correlations)} same-resource evidence hypothesis/hypotheses."))
                self.events.put(("log", "Correlation index saved in: " + str(correlation_dir / "index.json")))
                self.events.put(("log", "Individual evidence reports saved in: " + str(output_path.parent / "findings")))
                self.events.put(("log", f"Fuzz evidence saved: {output_path}"))
            self.events.put(("exit", "Fuzz run stopped." if self.stop_event.is_set() else "Fuzz run complete."))
        except Exception as exc:
            self.events.put(("exit", f"Fuzz error: {exc}"))

    def _run_process(self, target: str, scope_path: Path, output_dir: Path, cve_lookup: bool, github_repo: str | None = None):
        """Run the scheduler in this app process and stream all output into the UI."""
        writer = _QueueWriter(self.events)
        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                if github_repo:
                    try:
                        self.events.put(("log", f"Starting linked GitHub source review: {github_repo}"))
                        github_findings, github_summary = audit_github_repository(github_repo, stop_event=self.stop_event)
                        github_dir = output_dir.parent / "github-source-audit"
                        github_dir.mkdir(parents=True, exist_ok=True)
                        github_report = {
                            "tool": APP_NAME, "version": "0.23.0",
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "repository": github_summary, "finding_count": len(github_findings),
                            "findings": [item.to_dict() for item in github_findings],
                            "disclaimer": "Static source matches are unconfirmed review leads. No code was executed and no repository content was modified."
                        }
                        github_path = github_dir / "latest-report.json"
                        github_path.write_text(json.dumps(github_report, indent=2, ensure_ascii=False), encoding="utf-8")
                        self.events.put(("log", f"GitHub audit complete: {github_summary['files_reviewed']} files, {len(github_findings)} finding(s). Report: {github_path}"))
                    except Exception as exc:
                        self.events.put(("log", f"GitHub source review could not complete; website scan will continue: {exc}"))
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
        hardening_categories = {"http-headers", "csp", "cors", "information", "cookies", "cache"}
        for item in ordered:
            kind = item.get("kind") or ("hardening-observation" if item.get("category") in hardening_categories else "finding")
            if kind == "hardening-observation" and not self.show_hardening_var.get():
                continue
            display_class = "HARDENING" if kind == "hardening-observation" else ("OBSERVATION" if kind == "observation" else "CANDIDATE")
            self.table.insert("", "end", values=(
                str(item.get("status", "")).upper(),
                display_class,
                str(item.get("severity", "n/a")).upper(),
                (f"{float(item['cvss_score']):.1f}" if isinstance(item.get("cvss_score"), (int, float)) else "N/A"),
                item.get("title", "Untitled"),
                item.get("finding_id", ""),
                item.get("occurrences", 0),
                item.get("last_seen", ""),
            ))

    def show_domain_tree(self):
        """Display the latest recursively discovered host hierarchy."""
        if self.current_folder is None:
            messagebox.showinfo("Domain tree", "Start a scan with subdomain discovery enabled first.")
            return
        reports = sorted(self.current_folder.glob("cycle-*.json"),
                         key=lambda path: path.stat().st_mtime, reverse=True)
        discovery = None
        for report_path in reports:
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8"))
                candidate = payload.get("domain_discovery")
                if candidate and candidate.get("enabled"):
                    discovery = candidate
                    break
            except (OSError, json.JSONDecodeError):
                continue
        if not discovery:
            messagebox.showinfo("Domain tree", "No recursive subdomain results are saved for this target yet.")
            return

        window = tk.Toplevel(self.root)
        window.title("Recursive domain tree | Darth Scanner")
        window.geometry("760x600")
        window.configure(bg="#0b0e14")
        tk.Label(window, text=f"AUTHORIZED ROOT  /  {discovery.get('root_domain') or 'unknown'}",
                 bg="#0b0e14", fg="#f3f6fb", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=18, pady=(16, 4))
        tk.Label(window, text=f"Depth limit: {discovery.get('max_depth')}  •  Host limit: {discovery.get('max_hosts')}  •  DNS-verified discoveries only",
                 bg="#0b0e14", fg="#9eabc0", font=("Segoe UI", 8)).pack(anchor="w", padx=18, pady=(0, 12))
        tree = ttk.Treeview(window, columns=("depth", "status"), show="tree headings")
        tree.heading("#0", text="HOSTNAME")
        tree.heading("depth", text="LEVEL")
        tree.heading("status", text="DNS")
        tree.column("#0", width=480)
        tree.column("depth", width=80, anchor="center")
        tree.column("status", width=120, anchor="center")
        tree.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        root = str(discovery.get("root_domain") or "")
        root_id = tree.insert("", "end", text=root, values=("root", "authorized"), open=True)
        parent_ids = {root: root_id}
        for item in sorted(discovery.get("hosts") or [], key=lambda value: (value.get("depth", 0), value.get("host", ""))):
            host = str(item.get("host", ""))
            parent = str(item.get("parent") or root)
            parent_id = parent_ids.get(parent, root_id)
            node_id = tree.insert(parent_id, "end", text=host,
                                  values=(item.get("depth", ""), "verified" if item.get("dns_verified") else "unverified"))
            parent_ids[host] = node_id
        if not discovery.get("hosts"):
            tree.insert(root_id, "end", text="No DNS-verified subdomains discovered", values=("", ""))

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
        section("CVSS vector", item.get("cvss_vector") or "Not supplied by the NVD record.", "#f4c66b")
        section("CVSS source and vector validation", json.dumps(item.get("cvss_validation") or {"source": item.get("cvss_source") or "Not supplied", "note": "CVSS is vulnerability severity, not target-specific exploitability."}, indent=2), "#f4c66b")
        section("Affected software component", item.get("affected_component"))
        section("CVE references", "\n".join(item.get("references") or []), "#8fc5ff")
        section("What the scanner detected", item.get("description"))
        section("Why this may matter", item.get("impact") or
                "This is an automated observation, not proof of exploitability. Review the evidence and affected component in context before treating it as a vulnerability.",
                "#f4c66b")
        source_location = [str(item.get("source_kind") or "Client-visible response source"), str(item.get("source_url") or item.get("url") or "URL unavailable")]
        if item.get("source_line"):
            source_location.append("Line " + str(item.get("source_line")))
        source_location.append(item.get("source_excerpt") or "No source excerpt applies; this finding is based on response metadata.")
        source_location.append("This is source exposed in the HTTP response, not the server-side application source file. Server-side file paths and line numbers require owner-provided source code or repository access.")
        section("Exact source location / code evidence", "\n".join(source_location), "#70d6b0")
        section("Evidence collected", item.get("evidence"), "#70d6b0")
        section("Safe proof of concept / reproduction steps",
                "\n".join(item.get("reproduction_steps") or []) or
                "No repeatable HTTP steps were generated for this finding.", "#70d6b0")
        evidence_details = item.get("evidence_details") or {}
        evidence_lines = [
            f"{key}: {value}" for key, value in evidence_details.items()
            if key != "response_headers"
        ]
        evidence_lines.append("Response headers:")
        evidence_lines.extend(
            f"  {key}: {value}" for key, value in (evidence_details.get("response_headers") or {}).items()
        )
        section("Request / response evidence", "\n".join(evidence_lines), "#8fc5ff")
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
    _enable_windows_dpi_awareness()
    root = tk.Tk()
    try:
        # Tk uses points for fonts. Match its point-to-pixel scale to the
        # monitor DPI so text stays crisp instead of being bitmap-stretched.
        dpi = float(root.winfo_fpixels("1i"))
        if dpi > 0:
            root.tk.call("tk", "scaling", dpi / 72.0)
    except (tk.TclError, ValueError, TypeError):
        pass
    DarthScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
