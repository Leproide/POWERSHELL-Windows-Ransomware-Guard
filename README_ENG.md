# RansomwareGuard

Early-warning ransomware detection for Windows based on **canary files** and SHA-256 hash monitoring.  
Places decoy files in folders you care about, builds a hash baseline, and immediately alerts you via Telegram, Gotify and/or a Windows popup if any file is modified or deleted.

---

## How it works

The idea is straightforward: ransomware encrypts every file it can find in a folder. RansomwareGuard plants realistic-looking decoy files (Office documents, SQL dumps, backups) in your monitored folders. On every scheduled run it recomputes their SHA-256 hashes and compares them against the baseline. Any change triggers an alert.

```
Script launched
    │
    ├─ First run ──► Interactive setup
    │                   ├─ Choose one or more folders to monitor
    │                   ├─ Configure Telegram / Gotify / popup
    │                   ├─ Folder has existing files? ──► hash those as baseline
    │                   ├─ Folder is empty?           ──► create realistic canary files
    │                   ├─ Set audit SACL to track processes
    │                   └─ Register Windows Scheduled Task (runs as SYSTEM)
    │
    └─ Subsequent runs (scheduled) ──► Hash check
                                           ├─ No changes ──► log OK
                                           └─ Modified / deleted
                                                ├─ Query Security Event Log (ID 4663)
                                                │  for responsible process + user
                                                └─ Send alert: Telegram + Gotify + Popup
```

---

## Requirements

| Requirement | Detail |
|---|---|
| Windows | 10 / 11 / Server 2016+ |
| PowerShell | 5.1 or higher |
| Privileges | **Administrator** (Task Scheduler, SACL, Security Event Log) |
| Network | Access to `api.telegram.org` and/or your Gotify server |

---

## Installation

1. Download `RansomwareGuard.ps1` and place it in a dedicated folder (e.g. `C:\RansomwareGuard\`)

2. Open PowerShell **as Administrator** and allow script execution if needed:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

3. Run the script:

```powershell
.\RansomwareGuard.ps1
```

The interactive setup will guide you through all steps.

---

## First-run setup walkthrough

### 1 — Folders to monitor

Enter paths one at a time. You can add as many as you want, across different drives.  
Press **Enter with no input** to finish.

```
[Folders to monitor]
  Path #1 (required)         : C:\Shared\Office
  + Added: C:\Shared\Office
  Path #2 (or ENTER to finish): D:\Backup\Data
  + Added: D:\Backup\Data
  Path #3 (or ENTER to finish): [ENTER]

  +-- Selected folders ----------------------------------------
  |  1. C:\Shared\Office
  |  2. D:\Backup\Data
  +------------------------------------------------------------

  Confirm these 2 path(s)? (Y/n)
```

If a path does not exist the script offers to create it. Duplicate paths are silently ignored.

### 2 — Telegram

You need:
- **Bot token** — create one with [@BotFather](https://t.me/BotFather) on Telegram
- **Chat ID** — your personal ID, a group or a channel. Retrieve it with [@userinfobot](https://t.me/userinfobot)

### 3 — Gotify

You need:
- **Server URL** (e.g. `https://push.example.com`)
- **Port** — optional, leave blank for 80/443
- **App Token** — generate one in the Gotify dashboard under *Apps → Create App*

### 4 — Notification channels

Each channel can be enabled or disabled independently:

```
Enable Telegram?          (Y/n)
Enable Gotify?            (Y/n)
Enable Windows Popup/MSG? (Y/n)
```

You can also toggle these at any time by editing `rg_config.json`:

```json
"EnableTelegram": true,
"EnableGotify":   true,
"EnablePopup":    false
```

### 5 — Check interval

How often (in minutes) the Scheduled Task runs. Default: **15 minutes**.

---

## Generated files

All created in the same folder as the script:

| File | Contents |
|---|---|
| `rg_config.json` | Full configuration (tokens, paths, interval, notification flags) |
| `rg_hashes.json` | SHA-256 baseline for every monitored file |
| `rg_log.txt` | Timestamped log of every run |

---

## Canary files

When a monitored folder is **empty**, the script automatically creates files that look legitimate to avoid being skipped by ransomware that filters out obvious bait:

| File | Apparent type |
|---|---|
| `desktop.ini` | Genuine Windows folder metadata |
| `~WRL0003.tmp` | Word temp file with real OLE2 binary header |
| `Budget_2024_Final.xlsx` | CSV with monthly financial data |
| `Service_Agreement_Rev3.docx` | RTF with contract text |
| `passwords_backup.txt` | Internal notes with server names, shares, tickets |
| `HR_Salaries_Confidential.xlsx` | CSV with salary and department data |
| `System_Backup_Config.xml` | XML org chart export |
| `network_credentials.txt` | Fake network credential list |
| `QuickBooks_Backup.qbb` | Real QuickBooks header + ASCII noise |
| `DB_Export_20240115.sql` | INSERT statements on tables like `invoices`, `customers` |

If the folder **already contains files**, the script uses those as the baseline without creating anything new.

> File content contains **no references** to monitoring, security or scripts.

---

## Scheduled Task

The task is registered in **Task Scheduler → Task Scheduler Library** as `RansomwareGuard_Monitor`.

| Setting | Value |
|---|---|
| Run as | SYSTEM |
| Privileges | Highest available |
| Trigger | Every N minutes (configurable) |
| If already running | Stop existing instance and restart |
| On battery | Runs on battery too |
| Time limit | None |

Verify the task exists:

```powershell
Get-ScheduledTask -TaskName "RansomwareGuard_Monitor"
```

---

## Process identification

RansomwareGuard uses the **Windows Security Event Log (Event ID 4663)** to identify which process modified or deleted a monitored file.

### How it is set up

During first-run setup the script automatically configures:

1. **`auditpol`** — enables File System auditing system-wide (successes only, negligible performance impact)
2. **SACL** (Security ACL) — sets an audit rule on every monitored folder that logs write and delete operations by any user, inherited by all files and subfolders

### Alert format

```
[SERVER-01] RansomwareGuard ALERT

POSSIBLE RANSOMWARE detected on SERVER-01
Time: 03/05/2026 17:58:36
Monitored paths: C:\Shared\Office, D:\Backup\Data

Modified files (1):
  - passwords_backup.txt [Process: notepad++.exe PID:43928 User: SERVER-01\Alice]

Deleted files (1):
  - Budget_2024_Final.xlsx [Process: explorer.exe PID:5120 User: SERVER-01\Alice]
```

> **Note:** Event ID 4663 is only logged if auditing was active *before* the modification occurred. If you reinstall the script on a machine, use option **5** in the management menu to reapply the SACL rules.

---

## Management menu

```powershell
.\RansomwareGuard.ps1 --manage
```

```
╔══════════════════════════════════╗
║   RansomwareGuard - Management   ║
╚══════════════════════════════════╝
  1. Recompute hash baseline (after legitimate updates)
  2. Send test notification
  3. Show current configuration
  4. Reconfigure from scratch
  5. Reapply audit SACL on folders
  6. Exit
```

| Option | When to use |
|---|---|
| **1** | After legitimately modifying files in a monitored folder (e.g. updating documents). Recomputes the baseline without triggering alerts. |
| **2** | To verify that Telegram, Gotify and popup are all working correctly. |
| **3** | To display the current saved configuration. |
| **4** | To start fresh — deletes config and hashes, reruns setup. |
| **5** | To reapply audit SACL rules after adding new folders or moving the script to a different machine. |

---

## Manual configuration (rg_config.json)

The config file is plain JSON and can be edited directly:

```json
{
  "MonitorPaths":   ["C:\\Shared\\Office", "D:\\Backup\\Data"],
  "TelegramToken":  "123456:ABCdef...",
  "TelegramChatId": "-100123456789",
  "GotifyUrl":      "https://push.example.com",
  "GotifyToken":    "AbCdEfGh",
  "CheckInterval":  15,
  "SetupDone":      true,
  "EnableTelegram": true,
  "EnableGotify":   true,
  "EnablePopup":    true
}
```

Changes take effect on the next scheduled run — no restart required.

---

## Multi-machine deployment

The script is designed to run autonomously across multiple PCs or servers:

- Hostname is resolved dynamically with `[System.Net.Dns]::GetHostName()` — returns the full network name or FQDN when domain-joined
- Every notification subject includes the machine name: `[SERVER-ACCOUNTING] RansomwareGuard ALERT`
- Deploy the same script to N machines, each with its own `rg_config.json`

---

## Project structure

```
RansomwareGuard/
├── RansomwareGuard.ps1   ← main script
├── rg_config.json        ← generated on first run
├── rg_hashes.json        ← generated on first run
└── rg_log.txt            ← generated on first run
```

---

## Known limitations

- Process identification requires that the Security Event Log has not been rotated between the modification and the next check run. On high-traffic systems, increase the maximum size of the `Security` log in Event Viewer.
- Canary files protect only the monitored folders, not the entire filesystem. Choose high-value locations such as network shares, backup destinations and critical document folders.
- RansomwareGuard is an **early-warning system**, not an antivirus. It detects activity *after* it begins — it does not prevent it.
- It is good practice to modify the permissions of the folder containing the script so that only **SYSTEM** has access to it.
