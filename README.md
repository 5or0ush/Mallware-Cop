# Mallware-Cop — Windows EDR Monitor

> That smells like a virus . . .

Mallware-Cop is a Windows-focused, educational **EDR-style (Endpoint Detection & Response)** monitor written in Python. It observes running processes in real time, performs optional **VirusTotal** hash lookups, and applies a basic response policy (kill/suspend/dump/quarantine). A smooth **Tkinter GUI** shows a live table of processes and an action feed without terminal flicker.

> ⚠️ For learning/lab use only. Don’t deploy to production systems.

---

## Key Features

- **Real-time process monitor**
  - Name, PID, CPU%, memory (MB), VT detections, last action
  - Updates every second; no flicker (Tkinter GUI)
- **Policy engine**
  - `virus.exe` → **Kill** + **Quarantine**
  - VirusTotal `detections > 3` → **Suspend** → **Dump Memory** → **Quarantine**
  - Memory `> 500 MB` or CPU `> 80%` for 3 consecutive samples → **Kill**
- **Desktop watcher**
  - Any file named `virus.exe` appearing on the **Desktop** is quarantined immediately
- **Quarantine & artifacts**
  - Moves/copies executables to `./quarantine/` (timestamped). Memory dumps (via **procdump.exe**) also land here.
- **Color-coded GUI**
  - **Red**: dangerous (Kill/Quarantine, or VT detections >3)
  - **Yellow**: suspicious (VT detections >0)
  - **Orange**: warnings (Suspend/Dump/Resource threshold)
  - **Grey**: normal process exit
- **Action logging & reports**
  - Human-readable: `logs/actions.log`
  - Structured CSV: `logs/actions.csv`

---

## How It Works (Architecture)

```
+--------------------------+     +-------------------+
|  Tkinter GUI (main thread) <---+  Shared State     |
|  - Treeview process table |     |  - latest_procs   |
|  - Action log pane        |     |  - LAST_ACTION_*  |
+-------------^-------------+     +---------^---------+
              |                             |
              | after(1000ms)               |
              |                             |
+-------------+-------------+     +---------+---------+
|  Monitor loop (thread)    |     | VT Worker (thread)|
|  - Enumerate processes    |     | - Hash lookups    |
|  - Sample CPU/memory      |     |   every 15s       |
|  - Enforce policies       |     | - Cache results   |
|  - Log actions            |     +-------------------+
+-------------^-------------+
              |
              v
+--------------------------+
| Desktop Watcher (watchdog)
| - Quarantine Desktop\virus.exe
+--------------------------+
```

### Components

- **Monitor loop** (background thread)
  - Enumerates processes with `psutil`, samples CPU/memory, extracts executable paths, computes SHA‑256, evaluates policies, pushes updates to a shared list used by GUI.
- **VirusTotal worker** (background thread)
  - Every **15s**, looks up one new (uncached) SHA‑256 via VT v3 `GET /api/v3/files/{sha256}`. Results cached to avoid rate limits (4/min). No auto-upload.
- **Policy engine**
  - Applies rules and performs actions (kill, suspend, dump with `procdump.exe`, quarantine via copy/move). All actions are logged and reflected live in the GUI.
- **Desktop watcher**
  - Watches the Desktop directory and quarantines any file named `virus.exe` immediately (even if not running).
- **GUI**
  - `ttk.Treeview` for the process grid. `tk.Text` for recent actions. Color tags indicate severity; short-lived **notice rows** surface critical events at the top for ~20s.

---

## Requirements

- **Windows 10/11**, **Python 3.10+**
- Python packages:
  ```powershell
  pip install psutil requests watchdog colorama
  ```
- (Optional) **Sysinternals Procdump** for memory dumps
  ```powershell
  setx PROCDUMP_PATH "C:\\Tools\\Sysinternals\\procdump.exe"
  ```

---

## Configuration

| Setting | Where | Notes |
|--------:|:------|:------|
| VT API Key | In-file `VT_API_KEY = "<PUT_YOUR_API_KEY_HERE>"` or `setx VT_API_KEY "..."` | Used in **Online** mode for hash lookups every 15s |
| Procdump path | `setx PROCDUMP_PATH "C:\\path\\procdump.exe"` | Needed for memory dumps; otherwise `DUMP_FAIL` is logged |
| Thresholds | Top of `EDR.py` | `VT_LOOKUP_INTERVAL`, `MEM_THRESHOLD_MB`, `CPU_THRESHOLD_PCT`, `CPU_SPIKE_SAMPLES` |

---

## Running

```powershell
python EDR.py
```
Choose:
- `1` **Online** – VirusTotal lookups (rate-limited); GUI shows `det=N`
- `2` **Offline** – No VT calls; GUI shows `offline`

Close the window to stop monitoring. Logs and quarantine artifacts remain on disk.

---

## Testing (Copy–Paste)

### Live process appearance/disappearance
```powershell
start notepad
start calc
```
Close them to see **EXITED** notices and log entries.

### Desktop watcher — immediate quarantine
```powershell
$desk = "$env:USERPROFILE\Desktop"
$eicar = 'X5O!P%@AP[4\\PXZ54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "$desk\eicar.com" -Value $eicar -Encoding ASCII
Rename-Item -Path "$desk\eicar.com" -NewName "virus.exe"
```
Expect a **red notice row** `[DANGEROUS] QUARANTINED - ...` and an item in `./quarantine/`.

### Name policy — kill + quarantine running `virus.exe`
- Rename any harmless EXE to `virus.exe` and run it.
- Expect `[DANGEROUS] KILL: name matched policy (virus.exe)` and quarantine of the exe.

### Resource thresholds
```powershell
# Memory >500MB
ython -c "import time; x=bytearray(700*1024*1024); time.sleep(120)"

# CPU >80% for ~3s
python -c "while True: pass"
```
Expect **red** kill actions and corresponding notices/log entries.

### VirusTotal (Online mode)
- Keep several apps open. Every ~15s, new hashes show `det=N` in the VT column.
- If `det>0` → **yellow**; if `det>3` → **red** and policy triggers **Suspend → Dump → Quarantine**.

> If Procdump isn’t configured, you’ll see `DUMP_FAIL` (orange) but quarantine still occurs.

---

## Logs & Reports

| Path | Description |
|------|-------------|
| `logs/actions.log` | Human-readable audit trail of all actions |
| `logs/actions.csv` | Structured log for Excel/BI (timestamp, action, pid, proc, detail) |
| `quarantine/` | Quarantined executables (`.quar`) and memory dumps (`.dmp`) |

**Examples** (PowerShell):
```powershell
Get-Content .\logs\actions.log -Tail 50
Import-Csv .\logs\actions.csv | Format-Table -AutoSize
Get-ChildItem .\quarantine\
```

---

## Safety & Scope

- Educational tool; not a full EDR. Use in lab/VMs.
- The EICAR test file is safe and industry-standard for AV testing.
- Some actions (suspend/dump) may require Administrator privileges.
- System/Protected processes may not be fully accessible.

---

## FAQ

**Does it upload binaries to VirusTotal?**
> No. It only performs **hash lookups** (`GET /files/{sha256}`) to respect rate limits and privacy.

**Why do some processes show `AccessDenied` in logs?**
> Protected/system processes are sometimes restricted. The monitor skips them gracefully.

**The GUI shows `DUMP_FAIL`. What now?**
> Install **procdump.exe** and set `PROCDUMP_PATH`, then re-run.

**Can I change thresholds?**
> Yes, adjust the constants near the top of `EDR.py`.

---

## Roadmap

- Per-process allow/deny list
- Configurable policy rules via UI
- On-demand file hashing / manual VT scan
- System tray mode
- Export to JSONL / Syslog

---