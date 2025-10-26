
import os
import sys
import time
import json
import csv
import queue
import shutil
import signal
import hashlib
import threading
import subprocess
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk

import psutil
from colorama import Fore, Style, init as colorama_init

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

REFRESH_INTERVAL = 1.0
VT_LOOKUP_INTERVAL = 15.0
MEM_THRESHOLD_MB = 500
CPU_THRESHOLD_PCT = 80.0
CPU_SPIKE_SAMPLES = 3
QUARANTINE_DIR = Path("quarantine").resolve()
LOG_DIR = Path("logs").resolve()
ACTIONS_LOG = LOG_DIR / "actions.log"
ACTIONS_CSV = LOG_DIR / "actions.csv"
VT_API_KEY = "<PUT_YOUR_API_KEY_HERE>"
RECENT_ACTIONS: list[str] = []
LAST_ACTION_BY_PID: dict[int, str] = {}
RECENT_ACTIONS_MAX = 200
RECENT_NOTICE_ROWS: list[dict] = []
NOTICE_TTL_SECONDS = 20
MAX_NOTICE_ROWS = 10

def _add_notice(name: str, pid: int | None, action: str, detail: str, severity: str = "danger"):
    RECENT_NOTICE_ROWS.append({
        "name": name or "<unknown>",
        "pid": pid,
        "action": action,
        "detail": detail,
        "ts": time.time(),
        "severity": severity,
    })
    while len(RECENT_NOTICE_ROWS) > MAX_NOTICE_ROWS:
        del RECENT_NOTICE_ROWS[0]

PROCDUMP_PATH = os.environ.get("PROCDUMP_PATH") or "procdump.exe"

def bytes_to_mb(b: int) -> float:
    return b / (1024 * 1024)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def safe_process_name(p: psutil.Process) -> str:
    try:
        return p.name()
    except Exception:
        return "<unknown>"


def safe_process_exe(p: psutil.Process) -> Path | None:
    try:
        exe = p.exe()
        return Path(exe) if exe else None
    except Exception:
        return None


def ensure_dirs():
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not ACTIONS_CSV.exists():
        with open(ACTIONS_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "action", "pid", "proc_name", "detail"])  # header


def log_action(action: str, pid: int | None, proc_name: str | None, detail: str):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {action} pid={pid} name={proc_name} :: {detail}\n"
    # write to disk logs
    with open(ACTIONS_LOG, 'a', encoding='utf-8') as f:
        f.write(line)
    with open(ACTIONS_CSV, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([ts, action, pid or '', proc_name or '', detail])

    # update in-memory recent actions and per-pid last action for live UI
    entry = f"{ts} | {action} | pid={pid} | {proc_name} | {detail}"
    RECENT_ACTIONS.append(entry)
    if len(RECENT_ACTIONS) > RECENT_ACTIONS_MAX:
        del RECENT_ACTIONS[0: len(RECENT_ACTIONS) - RECENT_ACTIONS_MAX]
    try:
        if pid is not None:
            # keep short description for the per-pid column
            LAST_ACTION_BY_PID[int(pid)] = f"{action}: {detail}"
    except Exception:
        pass

    # push prominent GUI notices for key events
    try:
        act_upper = (action or "").upper()
        name_for_notice = proc_name or "<unknown>"
        if "QUARANTINE_" in act_upper:
            _add_notice(name_for_notice, pid, "QUARANTINED", detail, severity="danger")
        elif act_upper == "KILL":
            _add_notice(name_for_notice, pid, "KILLED", detail, severity="danger")
        elif act_upper == "SUSPEND":
            _add_notice(name_for_notice, pid, "SUSPENDED", detail, severity="warning")
        elif act_upper == "DUMP":
            _add_notice(name_for_notice, pid, "MEMORY DUMP", detail, severity="warning")
        elif act_upper == "PROC_END":
            _add_notice(name_for_notice, pid, "EXITED", detail, severity="info")
    except Exception:
        pass


class VTWorker(threading.Thread):

    def __init__(self, api_key: str | None, mode_online: bool):
        super().__init__(daemon=True)
        self.api_key = api_key
        self.mode_online = mode_online
        self.queue: "queue.Queue[tuple[int, str, Path]]" = queue.Queue()
        self.last_lookup = 0.0
        self.cache: dict[str, dict] = {}  # sha256 -> VT json (or {"error": str})
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.is_set():
            now = time.time()
            if not self.mode_online or not REQUESTS_AVAILABLE:
                # offline mode or requests missing: sleep a bit and loop
                time.sleep(1.0)
                continue

            if now - self.last_lookup < VT_LOOKUP_INTERVAL:
                time.sleep(0.2)
                continue

            try:
                item = self.queue.get_nowait()
            except queue.Empty:
                time.sleep(0.5)
                continue

            pid, sha256, exe_path = item
            self.last_lookup = time.time()
            try:
                data = self._vt_lookup_sha256(sha256)
                self.cache[sha256] = data
                detections = self._detections_from_data(data)
                log_action("VT_LOOKUP", pid, exe_path.name, f"detections={detections} sha256={sha256}")
            except Exception as e:
                self.cache[sha256] = {"error": str(e)}
                log_action("VT_ERROR", pid, exe_path.name, str(e))

    def stop(self):
        self.stop_event.set()

    def schedule_lookup(self, pid: int, sha256: str, exe_path: Path):
        if sha256 in self.cache:
            return
        # avoid queue duplicates
        for _pid, _sha, _p in list(self.queue.queue):
            if _sha == sha256:
                return
        self.queue.put((pid, sha256, exe_path))

    # --- VT API helpers ---
    def _vt_lookup_sha256(self, sha256: str) -> dict:
        # Use VT v3: GET https://www.virustotal.com/api/v3/files/{id}
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.api_key}
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 404:
            # unknown file; we don't auto-upload to stay within limits
            return {"data": None, "meta": {"note": "hash not found on VT"}}
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _detections_from_data(data: dict) -> int:
        try:
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            return int(stats.get("malicious", 0))
        except Exception:
            return 0


class PolicyEngine:
    def __init__(self, vt_worker: VTWorker):
        self.vt_worker = vt_worker
        self.cpu_breach_counts: dict[int, int] = {}  # pid -> consecutive spikes

    def evaluate(self, p: psutil.Process, sample_cpu: float, mem_mb: float, vt_status: dict | None):
        name = safe_process_name(p).lower()
        pid = p.pid

        # Rule 1: explicit virus.exe name
        if name == 'virus.exe':
            self._kill_and_quarantine(p, reason="name matched policy (virus.exe)")
            return

        # Rule 2: resource usage thresholds
        over_mem = mem_mb > MEM_THRESHOLD_MB
        over_cpu = sample_cpu > CPU_THRESHOLD_PCT
        if over_cpu:
            self.cpu_breach_counts[pid] = self.cpu_breach_counts.get(pid, 0) + 1
        else:
            self.cpu_breach_counts[pid] = 0

        if over_mem or self.cpu_breach_counts.get(pid, 0) >= CPU_SPIKE_SAMPLES:
            detail = []
            if over_mem:
                detail.append(f"mem={mem_mb:.0f}MB>")
            if self.cpu_breach_counts.get(pid, 0) >= CPU_SPIKE_SAMPLES:
                detail.append(f"cpu>{CPU_THRESHOLD_PCT:.0f}% x{self.cpu_breach_counts[pid]}")
            self._kill_process(p, reason="resource threshold: " + ", ".join(detail))
            return

        # Rule 3: VirusTotal malicious detections
        if vt_status is not None:
            detections = vt_status.get("detections", 0)
            if detections > 3:
                self._suspend_dump_quarantine(p, reason=f"VT detections={detections}")

    # ---- Actions ----
    def _kill_process(self, p: psutil.Process, reason: str):
        pid = p.pid
        name = safe_process_name(p)
        try:
            p.kill()
            log_action("KILL", pid, name, reason)
        except Exception as e:
            log_action("KILL_FAIL", pid, name, str(e))

    def _kill_and_quarantine(self, p: psutil.Process, reason: str):
        exe = safe_process_exe(p)
        self._kill_process(p, reason)
        if exe and exe.exists():
            self._quarantine(exe, from_pid=p.pid, proc_name=safe_process_name(p))

    def _suspend_dump_quarantine(self, p: psutil.Process, reason: str):
        pid = p.pid
        name = safe_process_name(p)
        try:
            p.suspend()
            log_action("SUSPEND", pid, name, reason)
        except Exception as e:
            log_action("SUSPEND_FAIL", pid, name, str(e))
        # dump memory
        self._dump_memory(pid, name)
        # quarantine executable
        exe = safe_process_exe(p)
        if exe and exe.exists():
            self._quarantine(exe, from_pid=pid, proc_name=name)

    def _dump_memory(self, pid: int, name: str):
        dump_path = QUARANTINE_DIR / f"dump_{pid}_{int(time.time())}.dmp"
        try:
            subprocess.run([PROCDUMP_PATH, "-accepteula", "-ma", str(pid), str(dump_path)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log_action("DUMP", pid, name, f"created {dump_path}")
        except Exception as e:
            log_action("DUMP_FAIL", pid, name, f"{e} (ensure procdump.exe is available)")

    def _quarantine(self, exe_path: Path, from_pid: int | None = None, proc_name: str | None = None):
        try:
            sha = sha256_file(exe_path)
        except Exception:
            sha = ""
        target = QUARANTINE_DIR / f"{exe_path.name}.{int(time.time())}.quar"
        try:
            # attempt to move; if fails (locked), copy instead
            try:
                shutil.move(str(exe_path), str(target))
                moved = True
            except Exception:
                shutil.copy2(str(exe_path), str(target))
                moved = False
            action = "QUARANTINE_MOVE" if moved else "QUARANTINE_COPY"
            detail = f"{exe_path} -> {target} sha256={sha}"
            log_action(action, from_pid, proc_name, detail)
        except Exception as e:
            log_action("QUARANTINE_FAIL", from_pid, proc_name, f"{exe_path}: {e}")


class DesktopVirusHandler(FileSystemEventHandler):
    def __init__(self, policy: PolicyEngine):
        super().__init__()
        self.policy = policy

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.name.lower() == 'virus.exe':
            # Quarantine immediately
            self.policy._quarantine(path, from_pid=None, proc_name='(file) virus.exe')


def start_desktop_watch(policy: PolicyEngine) -> Observer | None:
    if not WATCHDOG_AVAILABLE:
        return None
    try:
        desktop = Path(os.path.join(os.path.expanduser('~'), 'Desktop'))
        if not desktop.exists():
            return None
        handler = DesktopVirusHandler(policy)
        observer = Observer()
        observer.schedule(handler, str(desktop), recursive=False)
        observer.start()
        return observer
    except Exception:
        return None


class Monitor:
    def __init__(self, mode_online: bool, vt_api_key: str | None):
        self.mode_online = mode_online
        self.vt = VTWorker(vt_api_key, mode_online)
        self.policy = PolicyEngine(self.vt)
        self.prev_pids: set[int] = set()
        self.vt_view: dict[int, dict] = {}  # pid -> {status}
        self.stop_event = threading.Event()
        self.desktop_observer = None
        self.latest_procs = []  # list of (name, pid, cpu, mem_mb, vt_info)
        self.gui_root = None
        self.tree = None
        self.log_text = None
        self._gui_closed = threading.Event()

    def start(self):
        ensure_dirs()
        colorama_init()
        self.vt.start()
        self.desktop_observer = start_desktop_watch(self.policy)
        log_action("START", None, None, f"mode={'ONLINE' if self.mode_online else 'OFFLINE'}")
        # warm up cpu_percent
        for p in psutil.process_iter(['pid']):
            try:
                psutil.Process(p.pid).cpu_percent(None)
            except Exception:
                pass
        # Start background monitor thread
        monitor_thread = threading.Thread(target=self._loop, daemon=True)
        monitor_thread.start()
        # Start GUI on main thread
        try:
            self.start_gui()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self.stop_event.set()
        self.vt.stop()
        if self.desktop_observer is not None:
            try:
                self.desktop_observer.stop()
                self.desktop_observer.join(timeout=3)
            except Exception:
                pass
        # If GUI is running, destroy window if not already closed
        if self.gui_root is not None and not self._gui_closed.is_set():
            try:
                self.gui_root.after(0, self.gui_root.destroy)
            except Exception:
                pass

    def _loop(self):
        while not self.stop_event.is_set():
            procs = []
            current_pids = set()
            for p in psutil.process_iter(['pid', 'name', 'memory_info']):
                current_pids.add(p.pid)
                try:
                    proc = psutil.Process(p.pid)
                    name = safe_process_name(proc)
                    cpu = proc.cpu_percent(interval=None)
                    mem_mb = bytes_to_mb(proc.memory_info().rss)
                    exe = safe_process_exe(proc)

                    # schedule VT lookup if in online mode
                    vt_info = None
                    if self.mode_online and exe and exe.exists():
                        try:
                            sha = sha256_file(exe)
                            self.vt.schedule_lookup(proc.pid, sha, exe)
                            data = self.vt.cache.get(sha)
                            if data is not None:
                                vt_info = {
                                    'detections': VTWorker._detections_from_data(data),
                                    'status': 'found' if data.get('data') else data.get('meta', {}).get('note', 'unknown')
                                }
                        except Exception:
                            pass

                    # keep a view cache for UI
                    if vt_info:
                        self.vt_view[proc.pid] = vt_info

                    procs.append((name, proc.pid, cpu, mem_mb, vt_info))

                    # Evaluate policies
                    self.policy.evaluate(proc, cpu, mem_mb, vt_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # New / terminated process detection
            started = current_pids - self.prev_pids
            ended = self.prev_pids - current_pids
            for pid in sorted(started):
                try:
                    name = psutil.Process(pid).name()
                except Exception:
                    name = '<unknown>'
                log_action("PROC_START", pid, name, "started")
            for pid in sorted(ended):
                log_action("PROC_END", pid, "", "exited")

            self.prev_pids = current_pids

            # Save process info for GUI
            self.latest_procs = procs

            # Console output (for backward compatibility)
            os.system('cls' if os.name == 'nt' else 'clear')
            print(self._header())
            self._render_table(procs)
            self._render_footer()

            time.sleep(REFRESH_INTERVAL)
    def start_gui(self):
        self.gui_root = tk.Tk()
        self.gui_root.title("Windows EDR Monitor")
        self.gui_root.geometry("900x600")
        # --- Treeview for process table ---
        columns = ("Name", "PID", "CPU%", "MEM(MB)", "VT", "Action")
        self.tree = ttk.Treeview(self.gui_root, columns=columns, show="headings", height=20)
        for col, width in zip(columns, (200, 70, 60, 80, 80, 250)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")

        # Define tags for colored rows
        self.tree.tag_configure('sev_red', background='#3b0000', foreground='#ff7676')
        self.tree.tag_configure('sev_yellow', background='#3b3200', foreground='#ffe08a')
        self.tree.tag_configure('sev_orange', background='#3b1f00', foreground='#ffb26b')
        self.tree.tag_configure('sev_grey', background='#1f1f1f', foreground='#cfcfcf')

        self.tree.pack(fill="both", expand=False, padx=10, pady=(10, 0))

        # --- Text widget for live logs ---
        self.log_text = tk.Text(self.gui_root, height=12, wrap="none", state="disabled", bg="#181818", fg="#e0e0e0")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(6, 10))

        # Add a vertical scrollbar to the log_text
        log_scroll = tk.Scrollbar(self.log_text, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side="right", fill="y")

        # Periodically refresh UI
        self.refresh_ui()

        def on_close():
            self._gui_closed.set()
            self.stop_event.set()
            self.gui_root.destroy()

        self.gui_root.protocol("WM_DELETE_WINDOW", on_close)
        self.gui_root.mainloop()

    def refresh_ui(self):
        # Update process table
        if self.tree:
            # Remove all items
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Prepare data: first, add short-lived notices at the top
            now = time.time()
            live_notices = []
            for n in list(RECENT_NOTICE_ROWS):
                if now - n["ts"] <= NOTICE_TTL_SECONDS:
                    live_notices.append(n)
            # purge expired
            RECENT_NOTICE_ROWS[:] = live_notices[-MAX_NOTICE_ROWS:]

            # Insert notices (no PID or process may have exited already)
            for n in reversed(live_notices):  # newest first on top
                vt_str = "—"
                pid_str = str(n["pid"]) if n["pid"] is not None else "-"
                action_text = f"[DANGEROUS] {n['action']} - {n['detail']}" if n["severity"] == "danger" else f"{n['action']} - {n['detail']}"
                row = (n["name"][:30], pid_str, "", "", vt_str, action_text[:80])
                tag = 'sev_red' if n["severity"] == 'danger' else ('sev_orange' if n["severity"] == 'warning' else 'sev_grey')
                self.tree.insert("", "end", values=row, tags=(tag,))

            # Then, normal process rows sorted by CPU desc then mem desc
            procs = sorted(self.latest_procs, key=lambda x: (-x[2], -x[3]))
            for name, pid, cpu, mem_mb, vt_info in procs[:200]:
                vt_str = "offline"
                severity_tag = None
                if vt_info is not None:
                    det = vt_info.get('detections', 0)
                    vt_str = f"det={det}"
                    if det > 3:
                        severity_tag = 'sev_red'
                    elif det > 0:
                        severity_tag = 'sev_yellow'
                action = LAST_ACTION_BY_PID.get(pid, '')
                # escalate severity based on last action keywords
                act_upper = action.upper()
                if any(k in act_upper for k in ["KILL", "QUARANTINE_"]):
                    severity_tag = 'sev_red'
                    if action and not action.startswith('[DANGEROUS]'):
                        action = f"[DANGEROUS] {action}"
                elif any(k in act_upper for k in ["SUSPEND", "DUMP", "RESOURCE THRESHOLD"]):
                    severity_tag = severity_tag or 'sev_orange'
                row = (name[:30], str(pid), f"{cpu:.1f}", f"{mem_mb:.0f}", vt_str, (action[:80] if action else ''))
                self.tree.insert("", "end", values=row, tags=((severity_tag,) if severity_tag else ()))
        # Update log text
        if self.log_text:
            self.log_text.config(state="normal")
            self.log_text.delete("1.0", tk.END)
            # Show last 20 actions
            for line in RECENT_ACTIONS[-20:]:
                self.log_text.insert(tk.END, line + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state="disabled")
        # Schedule next refresh
        if not self.stop_event.is_set():
            self.gui_root.after(1000, self.refresh_ui)

    def _header(self) -> str:
        mode = f"{Fore.GREEN}ONLINE{Style.RESET_ALL}" if self.mode_online else f"{Fore.YELLOW}OFFLINE{Style.RESET_ALL}"
        return (
            f"Windows EDR Monitor  |  Mode: {mode}  |  VT rate: every {int(VT_LOOKUP_INTERVAL)}s  |  "
            f"Mem>{MEM_THRESHOLD_MB}MB -> kill  |  CPU>{int(CPU_THRESHOLD_PCT)}% x{CPU_SPIKE_SAMPLES} -> kill\n"
        )

    def _render_table(self, procs: list[tuple[str,int,float,float,dict|None]]):
        # sort by CPU desc then mem desc
        procs.sort(key=lambda x: (-x[2], -x[3]))
        # header
        print(f"{'NAME':30} {'PID':>7} {'CPU%':>7} {'MEM(MB)':>10} {'VT':>10} {'ACTION':30}")
        print('-' * 110)
        for name, pid, cpu, mem_mb, vt_info in procs[:60]:  # show top 60
            vt_str = "offline"
            color = Style.RESET_ALL
            if vt_info is not None:
                det = vt_info.get('detections', 0)
                vt_str = f"det={det}"
                if det > 3:
                    color = Fore.RED
                elif det > 0:
                    color = Fore.YELLOW
            action = LAST_ACTION_BY_PID.get(pid, '')
            if len(action) > 30:
                action = action[:27] + '...'
            line = f"{name[:30]:30} {pid:7d} {cpu:7.1f} {mem_mb:10.0f} {vt_str:>10} {action:30}"
            print(color + line + Style.RESET_ALL)

    def _render_footer(self):
        print('\nRecent actions (tail of log):')
        print('-' * 75)
        try:
            with open(ACTIONS_LOG, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-10:]
                for line in lines:
                    print(line.rstrip())
        except FileNotFoundError:
            print('(no actions yet)')


def prompt_mode_and_key() -> tuple[bool, str | None]:
    print("Select mode: [1] Online (uses VirusTotal)  |  [2] Offline")
    choice = input("Enter 1 or 2: ").strip()
    if choice == '1':
        api_key = VT_API_KEY if VT_API_KEY and VT_API_KEY != "<PUT_YOUR_API_KEY_HERE>" else os.environ.get('VT_API_KEY')
        if not api_key:
            if not REQUESTS_AVAILABLE:
                print("requests module not available; switching to offline.")
                return False, None
            api_key = input("Enter VirusTotal API key: ").strip()
        return True, api_key
    return False, None


def main():
    if os.name != 'nt':
        print("This script is intended for Windows (nt). Exiting.")
        sys.exit(1)

    ensure_dirs()
    online, key = prompt_mode_and_key()
    mon = Monitor(online, key)
    mon.start()


if __name__ == '__main__':
    main()
