#Requires -Version 5.1
<#

https://github.com/Leproide/POWERSHELL-Windows-Ransomware-Guard

.SYNOPSIS
    RansomwareGuard - Honeypot file monitor with multi-channel notifications
.DESCRIPTION
    Creates canary files in monitored folders.
    Computes SHA-256 hashes at every run and notifies via Telegram, Gotify and
    Windows popup/MSG if any modification is detected (potential ransomware encryption).
.NOTES
    First run : interactive setup -> saves rg_config.json
    Subsequent: hash verification only
    --manage  : opens the management menu
#>

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# PATHS
# $PSScriptRoot and $PSCommandPath are automatic variables always defined
# (empty string when not applicable) - safe with StrictMode.
# $MyInvocation.MyCommand.Path is AVOIDED: under SYSTEM/Task Scheduler
# the .Path property may be absent and StrictMode throws an exception.
# ---------------------------------------------------------------------------
$ScriptDir = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($PSCommandPath) {
    Split-Path -Parent $PSCommandPath
} else {
    $PWD.Path
}

# StrictMode activated AFTER path resolution
Set-StrictMode -Version Latest
$ConfigFile = Join-Path $ScriptDir "rg_config.json"
$HashDb     = Join-Path $ScriptDir "rg_hashes.json"
$LogFile    = Join-Path $ScriptDir "rg_log.txt"

# ---------------------------------------------------------------------------
# CANARY FILE NAMES
# Mix of Office, text and backup extensions - appetising for ransomware
# ---------------------------------------------------------------------------
$CanaryNames = @(
    "desktop.ini",
    "~WRL0003.tmp",
    "Budget_2024_Final.xlsx",
    "Service_Agreement_Rev3.docx",
    "passwords_backup.txt",
    "HR_Salaries_Confidential.xlsx",
    "System_Backup_Config.xml",
    "network_credentials.txt",
    "QuickBooks_Backup.qbb",
    "DB_Export_20240115.sql"
)

# ---------------------------------------------------------------------------
# HELPER: Log
# ---------------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    if ($Level -eq "WARN" -or $Level -eq "ERROR") {
        Write-Host $line -ForegroundColor Yellow
    } else {
        Write-Host $line
    }
}

# ---------------------------------------------------------------------------
# HELPER: Compute SHA-256
# ---------------------------------------------------------------------------
function Get-FileSHA256 {
    param([string]$Path)
    try {
        $hash = Get-FileHash -Path $Path -Algorithm SHA256
        return $hash.Hash
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# NOTIFICATIONS
# ---------------------------------------------------------------------------
function Send-TelegramNotify {
    param($Cfg, [string]$Text)
    try {
        $url      = "https://api.telegram.org/bot$($Cfg.TelegramToken)/sendMessage"
        $bodyObj  = @{ chat_id = $Cfg.TelegramChatId; text = $Text; parse_mode = "HTML" }
        # Explicit UTF-8 byte encoding to preserve emoji characters
        $jsonStr   = $bodyObj | ConvertTo-Json -Compress
        $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonStr)
        $req = [System.Net.WebRequest]::Create($url)
        $req.Method      = "POST"
        $req.ContentType = "application/json; charset=utf-8"
        $req.Timeout     = 10000
        $stream = $req.GetRequestStream()
        $stream.Write($jsonBytes, 0, $jsonBytes.Length)
        $stream.Close()
        $req.GetResponse().Close()
        Write-Log "Telegram notification sent."
    } catch {
        Write-Log "Telegram send error: $_" "WARN"
    }
}

function Send-GotifyNotify {
    param($Cfg, [string]$Title, [string]$Msg)
    try {
        $url      = "$($Cfg.GotifyUrl)/message?token=$($Cfg.GotifyToken)"
        $bodyObj  = @{ title = $Title; message = $Msg; priority = 8 }
        # Explicit UTF-8 byte encoding to preserve emoji characters
        $jsonStr   = $bodyObj | ConvertTo-Json -Compress
        $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonStr)
        $req = [System.Net.WebRequest]::Create($url)
        $req.Method      = "POST"
        $req.ContentType = "application/json; charset=utf-8"
        $req.Timeout     = 10000
        $stream = $req.GetRequestStream()
        $stream.Write($jsonBytes, 0, $jsonBytes.Length)
        $stream.Close()
        $req.GetResponse().Close()
        Write-Log "Gotify notification sent."
    } catch {
        Write-Log "Gotify send error: $_" "WARN"
    }
}

function Send-WindowsAlert {
    param([string]$Message)
    # MSG * works in interactive sessions; fallback to Toast or WScript popup
    try {
        $msgExe = "$env:SystemRoot\System32\msg.exe"
        if (Test-Path $msgExe) {
            & $msgExe * /TIME:60 $Message 2>$null
        }
    } catch { }

    # Fallback 1: native Windows 10/11 Toast Notification (no extra modules required)
    try {
        $xml = @"
<?xml version="1.0"?>
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>RansomwareGuard ALERT</text>
      <text>$Message</text>
    </binding>
  </visual>
</toast>
"@
        [Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom,ContentType=WindowsRuntime] | Out-Null
        $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xmlDoc.LoadXml($xml)
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
        $appId = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
        Write-Log "Toast notification shown."
    } catch {
        # Fallback 2: WScript popup - visible even when running as SYSTEM
        try {
            $wsh = New-Object -ComObject WScript.Shell
            $wsh.Popup($Message, 0, "RansomwareGuard ALERT", 16) | Out-Null
        } catch {
            Write-Log "Unable to show graphical alert: $_" "WARN"
        }
    }
}

function Send-AllAlerts {
    param($Cfg, [string]$Subject, [string]$Body)

    # Read enable flags; if absent in config (backward compatibility) default to true
    $doTelegram = if ($Cfg.ContainsKey("EnableTelegram")) { [bool]$Cfg.EnableTelegram } else { $true }
    $doGotify   = if ($Cfg.ContainsKey("EnableGotify"))   { [bool]$Cfg.EnableGotify   } else { $true }
    $doPopup    = if ($Cfg.ContainsKey("EnablePopup"))    { [bool]$Cfg.EnablePopup    } else { $true }

    if ($doTelegram) {
        Send-TelegramNotify -Cfg $Cfg -Text "<b>$Subject</b>`n$Body"
    } else {
        Write-Log "Telegram notification disabled (EnableTelegram=false)."
    }
    if ($doGotify) {
        Send-GotifyNotify -Cfg $Cfg -Title $Subject -Msg $Body
    } else {
        Write-Log "Gotify notification disabled (EnableGotify=false)."
    }
    if ($doPopup) {
        Send-WindowsAlert -Message "$Subject`n$Body"
    } else {
        Write-Log "Popup/MSG notification disabled (EnablePopup=false)."
    }
}

# ---------------------------------------------------------------------------
# FIRST RUN: interactive setup
# ---------------------------------------------------------------------------
function Invoke-FirstSetup {
    Write-Host "`n╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║        RansomwareGuard - Initial Setup       ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    # --- Folders to monitor (one or more) ---
    $monitorPaths = [System.Collections.Generic.List[string]]::new()
    Write-Host "`n[Folders to monitor]" -ForegroundColor Cyan
    Write-Host "  Enter paths one at a time." -ForegroundColor Gray
    Write-Host "  Press ENTER with no input to finish (minimum 1)." -ForegroundColor Gray

    while ($true) {
        $idx    = $monitorPaths.Count + 1
        $prompt = if ($monitorPaths.Count -eq 0) { "  Path #$idx (required)" } `
                  else                            { "  Path #$idx (or ENTER to finish)" }
        $input_ = (Read-Host $prompt).Trim()

        if ($input_ -eq '') {
            if ($monitorPaths.Count -eq 0) {
                Write-Host "  x You must enter at least one path." -ForegroundColor Red
                continue
            }
            break
        }

        if (-not (Test-Path $input_ -PathType Container)) {
            $create = Read-Host "  x Path not found. Create the folder? (y/N)"
            if ($create -match '^[yY]$') {
                try {
                    New-Item -ItemType Directory -Path $input_ -Force | Out-Null
                    Write-Host "  + Folder created." -ForegroundColor Green
                } catch {
                    Write-Host "  x Unable to create folder: $_" -ForegroundColor Red
                    continue
                }
            } else {
                continue
            }
        }

        if ($monitorPaths.Contains($input_)) {
            Write-Host "  ! Path already added, skipped." -ForegroundColor Yellow
            continue
        }

        $monitorPaths.Add($input_)
        Write-Host "  + Added: $input_" -ForegroundColor Green
    }

    # Summary and confirmation
    Write-Host "`n  +-- Selected folders ----------------------------------------" -ForegroundColor Cyan
    for ($i = 0; $i -lt $monitorPaths.Count; $i++) {
        Write-Host "  |  $($i+1). $($monitorPaths[$i])" -ForegroundColor White
    }
    Write-Host "  +------------------------------------------------------------" -ForegroundColor Cyan
    $confirm = Read-Host "`n  Confirm these $($monitorPaths.Count) path(s)? (Y/n)"
    if ($confirm -match '^[nN]$') {
        Write-Host "  Setup cancelled. Restart the script to begin again." -ForegroundColor Yellow
        exit 0
    }

    # --- Telegram ---
    Write-Host "`n[Telegram Bot]"
    $tgToken  = Read-Host "  Bot token (e.g. 123456:ABC...)"
    $tgChatId = Read-Host "  Destination Chat ID (e.g. -100123456789)"

    # --- Gotify ---
    Write-Host "`n[Gotify]"
    $gotifyHost  = Read-Host "  Gotify host (e.g. https://push.example.com)"
    $gotifyPort  = Read-Host "  Gotify port (leave blank for default 80/443)"
    $gotifyToken = Read-Host "  Gotify App Token"
    # Build URL: append port only if specified
    $gotifyUrl = if ($gotifyPort -match '^\d+$') {
        "$($gotifyHost.TrimEnd('/'))`:$gotifyPort"
    } else {
        $gotifyHost.TrimEnd('/')
    }

    # --- Enable/disable notifications ---
    Write-Host "`n[Notifications - enable/disable]"
    $enTelegram = Read-Host "  Enable Telegram? (Y/n)"
    $enGotify   = Read-Host "  Enable Gotify?   (Y/n)"
    $enPopup    = Read-Host "  Enable Windows Popup/MSG? (Y/n)"

    # --- Task interval (minutes) ---
    Write-Host "`n[Scheduler]"
    $interval = Read-Host "  Check interval in minutes for the Scheduled Task (default: 15)"
    if (-not $interval -or $interval -notmatch '^\d+$') { $interval = "15" }

    $cfg = @{
        MonitorPaths   = @($monitorPaths)
        TelegramToken  = $tgToken
        TelegramChatId = $tgChatId
        GotifyUrl      = $gotifyUrl
        GotifyToken    = $gotifyToken
        CheckInterval  = [int]$interval
        SetupDone      = $true
        EnableTelegram = ($enTelegram -notmatch '^[nN]$')
        EnableGotify   = ($enGotify   -notmatch '^[nN]$')
        EnablePopup    = ($enPopup    -notmatch '^[nN]$')
    }

    # --- For each folder: use existing files or create canary files ---
    $hashes      = @{}
    $totalErrors = 0

    foreach ($canaryDir in $monitorPaths) {
        Write-Host "`n  -- $canaryDir --" -ForegroundColor Cyan

        $existingFiles = @(Get-ChildItem -Path $canaryDir -File -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -notmatch '^rg_' })

        if ($existingFiles.Count -gt 0) {
            Write-Host "  Found $($existingFiles.Count) existing file(s) - computing hash baseline..." -ForegroundColor Gray
            foreach ($f in $existingFiles) {
                $hash = Get-FileSHA256 -Path $f.FullName
                if ($hash) {
                    $hashes[$f.FullName] = $hash
                    Write-Host "    + $($f.Name)  [$($hash.Substring(0,16))...]" -ForegroundColor Green
                } else {
                    Write-Host "    x $($f.Name)  [hash failed]" -ForegroundColor Red
                    $totalErrors++
                }
            }
        } else {
            Write-Host "  Empty folder - creating canary files..." -ForegroundColor Gray
            foreach ($name in $CanaryNames) {
                $fullPath = Join-Path $canaryDir $name
                try {
                    $fileContent = New-CanaryContent -FileName $name
                    if ($fileContent -eq '__BINARY_OLE2__') {
                        # Binary OLE2 file (Word/tmp header) - written as byte[]
                        $rngB  = [System.Random]::new()
                        $ole   = [byte[]](0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                        $noise = [byte[]](1..496 | ForEach-Object { $rngB.Next(0,256) })
                        [System.IO.File]::WriteAllBytes($fullPath, ($ole + $noise))
                    } else {
                        [System.IO.File]::WriteAllText($fullPath, $fileContent, [System.Text.Encoding]::UTF8)
                    }
                    if (Test-Path $fullPath) {
                        $hash = Get-FileSHA256 -Path $fullPath
                        if ($hash) {
                            $hashes[$fullPath] = $hash
                            Write-Host "    + $name  [$($hash.Substring(0,16))...]" -ForegroundColor Green
                        } else {
                            Write-Host "    x $name  [hash failed]" -ForegroundColor Red
                            $totalErrors++
                        }
                    } else {
                        Write-Host "    x $name  [NOT found on disk after write!]" -ForegroundColor Red
                        Write-Log "ERROR: file not found after write: $fullPath" "ERROR"
                        $totalErrors++
                    }
                } catch {
                    Write-Host "    x $name  [error: $_]" -ForegroundColor Red
                    Write-Log "ERROR creating '$name' in $canaryDir : $_" "ERROR"
                    $totalErrors++
                }
            }
        }
    }

    if ($totalErrors -gt 0) {
        Write-Host "`n  WARNING: $totalErrors file(s) could not be prepared." -ForegroundColor Yellow
    } else {
        Write-Host "`n  + All files ready across $($monitorPaths.Count) folder(s) ($($hashes.Count) hashes total)." -ForegroundColor Green
    }

    # --- Save config ---
    $cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-Log "Configuration saved to $ConfigFile"

    # --- Save hash baseline ---
    $hashes | ConvertTo-Json | Set-Content -Path $HashDb -Encoding UTF8
    Write-Log "Hash baseline saved: $($hashes.Count) file(s)"

    # --- Enable audit SACL on monitored folders ---
    Write-Host "`n[Audit SACL]" -ForegroundColor Cyan
    Enable-FolderAuditing -Paths @($monitorPaths)

    # --- Register Scheduled Task ---
    Register-RGScheduledTask -Cfg $cfg

    Write-Host "`n  Setup complete! The task will run every $interval minute(s).`n" -ForegroundColor Green

    # Optional test notification
    $test = Read-Host "Send a test notification? (y/N)"
    if ($test -match '^[yY]$') {
        Send-AllAlerts -Cfg $cfg `
            -Subject "[$script:Hostname] RansomwareGuard - Setup OK" `
            -Body "Setup completed on $script:Hostname. Monitored folders: $($monitorPaths -join ', ')"
    }
}

# ---------------------------------------------------------------------------
# Generate realistic canary file content per extension.
# No references to scripts, monitoring or security in the content.
# ---------------------------------------------------------------------------
function New-CanaryContent {
    param([string]$FileName)
    $ext  = [System.IO.Path]::GetExtension($FileName).ToLower()
    $rng  = [System.Random]::new()

    function Get-RandStr { param([int]$Len)
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        -join (1..$Len | ForEach-Object { $chars[$rng.Next($chars.Length)] })
    }
    function Get-RandInt { param([int]$Min,[int]$Max) $rng.Next($Min,$Max) }

    $firstNames = @('James','Emily','Robert','Sarah','Michael','Laura','David','Jessica','William','Emma')
    $lastNames  = @('Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Wilson','Moore')
    $depts      = @('Administration','Sales','IT','Human Resources','Logistics','Marketing','Procurement')
    $year       = (Get-Date).Year
    $month      = (Get-Date).ToString('MM')
    $day        = (Get-Date).ToString('dd')
    $host_      = $script:Hostname

    switch ($ext) {

        ".txt" {
            $lines = @(
                "Last updated: $month/$day/$year",
                "Owner: $($firstNames[$rng.Next($firstNames.Length)]) $($lastNames[$rng.Next($lastNames.Length)])",
                "Department: $($depts[$rng.Next($depts.Length)])",
                "",
                "Primary server  : $host_",
                "Share           : \\$host_\Data_$($depts[$rng.Next($depts.Length)])",
                "Service account : svc_$(Get-RandStr 6)",
                "Port            : $(Get-RandInt 1024 9000)",
                "",
                "Note: verify access after maintenance on $month/$(Get-RandInt 1 28)/$year",
                "Reference ticket: INC$(Get-RandInt 100000 999999)"
            )
            return $lines -join "`r`n"
        }

        ".ini" {
            return "[.ShellClassInfo]`r`nIconResource=C:\Windows\System32\imageres.dll,$(Get-RandInt 1 200)`r`nIconIndex=$(Get-RandInt 0 50)`r`n[ViewState]`r`nMode=`r`nVid={$(([System.Guid]::NewGuid()).ToString().ToUpper())}`r`nFolderType=Documents"
        }

        ".xml" {
            $entries = @()
            1..(Get-RandInt 4 9) | ForEach-Object {
                $fn  = $firstNames[$rng.Next($firstNames.Length)]
                $ln  = $lastNames[$rng.Next($lastNames.Length)]
                $id  = Get-RandInt 1000 9999
                $sal = Get-RandInt 28000 95000
                $entries += "  <employee id=`"$id`"><first>$fn</first><last>$ln</last><dept>$($depts[$rng.Next($depts.Length)])</dept><salary>$sal</salary></employee>"
            }
            return "<?xml version=`"1.0`" encoding=`"utf-8`"?>`r`n<staff year=`"$year`" company=`"$(Get-RandStr 6) Ltd`" exported=`"$month/$day/$year`">`r`n$($entries -join "`r`n")`r`n</staff>"
        }

        ".sql" {
            $table = @('customers','orders','invoices','contracts','products','employees')[$rng.Next(6)]
            $rows  = @()
            1..(Get-RandInt 5 12) | ForEach-Object {
                $fn  = $firstNames[$rng.Next($firstNames.Length)]
                $ln  = $lastNames[$rng.Next($lastNames.Length)]
                $id  = Get-RandInt 1 9999
                $val = Get-RandInt 100 50000
                $rows += "INSERT INTO $table VALUES ($id, '$fn', '$ln', $val, '$year-$month-$day');"
            }
            return "-- $table export $month/$day/$year`r`n-- Host: $host_`r`nUSE [$(Get-RandStr 8)_db];`r`nGO`r`n`r`n$($rows -join "`r`n")"
        }

        ".xlsx" {
            $headers = "Month;Category;Amount;Cost Center;Notes"
            $cats    = @('Payroll','Rent','Utilities','Vendors','Reimbursements','Depreciation')
            $rows    = @($headers)
            1..(Get-RandInt 8 20) | ForEach-Object {
                $m   = Get-RandInt 1 12
                $amt = "{0:N2}" -f ($rng.NextDouble() * 50000 + 500)
                $cc  = "CC$(Get-RandInt 100 999)"
                $rows += "$m/$year;$($cats[$rng.Next($cats.Length)]);$amt;$cc;$(Get-RandStr 8)"
            }
            return $rows -join "`r`n"
        }

        ".docx" {
            $fn1 = $firstNames[$rng.Next($firstNames.Length)]; $ln1 = $lastNames[$rng.Next($lastNames.Length)]
            $fn2 = $firstNames[$rng.Next($firstNames.Length)]; $ln2 = $lastNames[$rng.Next($lastNames.Length)]
            $art = Get-RandInt 3 12; $pag = Get-RandInt 2 8
            return "{\rtf1\ansi\deff0{\fonttbl{\f0 Times New Roman;}}\f0\fs24 " +
                   "Service Agreement - $month/$day/$year\par\par " +
                   "Between $fn1 $ln1 (hereinafter Client) and $fn2 $ln2 (hereinafter Provider).\par\par " +
                   "Article 1 - Scope\par The Provider agrees to deliver the services described in Annex A.\par\par " +
                   "Article 2 - Duration\par This agreement is valid for $(Get-RandInt 12 36) months from the signing date.\par\par " +
                   "Total pages: $pag - Articles: $art\par}"
        }

        ".qbb" {
            $magic = "QBWIN`t$(Get-RandStr 4)`tBackup`t$year$month$day`tver=R$(Get-RandInt 10 30).$(Get-RandInt 0 9)"
            $noise = -join (1..200 | ForEach-Object { [char]($rng.Next(32,126)) })
            return "$magic`r`n$noise"
        }

        ".tmp" {
            # Signals that this type must be written as byte[] - handled by the caller
            return "__BINARY_OLE2__"
        }

        default {
            $rows = @("ID;Description;Qty;Price;Total;Date")
            1..(Get-RandInt 6 15) | ForEach-Object {
                $id  = Get-RandInt 1000 9999
                $qty = Get-RandInt 1 100
                $prc = "{0:N2}" -f ($rng.NextDouble() * 500 + 10)
                $tot = "{0:N2}" -f ($qty * [double]$prc.Replace(',','.'))
                $rows += "$id;$(Get-RandStr 12);$qty;$prc;$tot;$month/$day/$year"
            }
            return $rows -join "`r`n"
        }
    }
}

# ---------------------------------------------------------------------------
# Register Windows Scheduled Task
# ---------------------------------------------------------------------------
function Register-RGScheduledTask {
    param($Cfg)
    $taskName = "RansomwareGuard_Monitor"
    $psExe    = "powershell.exe"

    # Resolve the real path of the running script.
    # $PSCommandPath is the most reliable variable across all PS3+ contexts.
    # $ScriptDir is already resolved at startup and used as fallback.
    $scriptPath = if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
        $PSCommandPath
    } elseif ($ScriptDir) {
        $found = Get-ChildItem -Path $ScriptDir -Filter "*.ps1" -File -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if ($found) { $found.FullName } else { $null }
    } else {
        $null
    }

    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        Write-Log "ERROR: cannot determine script path for Scheduled Task. Detected: '$scriptPath'" "ERROR"
        Write-Host "  x Task NOT registered: script path not found." -ForegroundColor Red
        Write-Host "    Register the task manually pointing to this script." -ForegroundColor Yellow
        return
    }

    Write-Log "Script for Scheduled Task: $scriptPath"

    $action = New-ScheduledTaskAction -Execute $psExe `
                  -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""

    # Safe CheckInterval access with StrictMode: ContainsKey/Match before accessing value
    $checkMins = 15
    if ($Cfg -is [hashtable] -and $Cfg.ContainsKey('CheckInterval') -and $null -ne $Cfg['CheckInterval']) {
        $checkMins = [int]$Cfg['CheckInterval']
    } elseif ($Cfg.PSObject.Properties.Match('CheckInterval').Count -gt 0) {
        $val = $Cfg.PSObject.Properties['CheckInterval'].Value
        if ($null -ne $val) { $checkMins = [int]$val }
    }
    Write-Log "CheckInterval: $checkMins min (Cfg type: $($Cfg.GetType().Name))"

    $trigger   = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes $checkMins) `
                     -Once -At (Get-Date)
    # Advanced settings (battery, StopExisting, no time limit) applied via COM after registration
    $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $null = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal |
                Register-ScheduledTask -TaskName $taskName -Force

        # Apply via COM the options unavailable in the PS cmdlet:
        #   MultipleInstances = 3  -> StopExisting
        #   DisallowStartIfOnBatteries = false
        #   StopIfGoingOnBatteries     = false
        #   ExecutionTimeLimit         = PT0S (no limit)
        $svc  = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $fold = $svc.GetFolder("\")
        $t    = $fold.GetTask($taskName)
        $def  = $t.Definition
        $def.Settings.MultipleInstances          = 3
        $def.Settings.DisallowStartIfOnBatteries = $false
        $def.Settings.StopIfGoingOnBatteries     = $false
        $def.Settings.ExecutionTimeLimit         = "PT0S"
        $fold.RegisterTaskDefinition($taskName, $def, 4, $null, $null, 5) | Out-Null

        Write-Log "Task '$taskName' registered -> every $checkMins min, SYSTEM, script: $scriptPath"
        Write-Host "  + Task registered: $taskName  (script: $scriptPath)" -ForegroundColor Green
    } catch {
        Write-Log "Unable to register task (requires admin privileges): $_" "WARN"
        Write-Host "  x Task NOT registered (administrator privileges required): $_" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Enable SACL auditing on monitored folders
# Requires: auditpol (audit object access) + Set-Acl with audit rule
# ---------------------------------------------------------------------------
function Enable-FolderAuditing {
    param([string[]]$Paths)

    # 1. Enable File System audit in Windows (successes only, no performance impact)
    # Using GUID instead of display name: subcategory names are locale-dependent
    # and differ between Windows languages/versions (Win11 IT/DE/FR break the string lookup).
    # GUID {0CCE921F-69AE-11D9-BED3-505054503030} = "File System" - always works.
    try {
        $auditOut = & auditpol.exe /set /subcategory:"{0CCE921F-69AE-11D9-BED3-505054503030}" /success:enable 2>&1
        Write-Log "File System audit enabled via auditpol. Output: $auditOut"
    } catch {
        Write-Log "Unable to configure auditpol: $_" "WARN"
    }

    # 2. Set SACL on every monitored folder
    foreach ($folder in $Paths) {
        if (-not (Test-Path $folder)) { continue }
        try {
            $acl = Get-Acl -Path $folder -Audit
            # Audit Everyone for Write + Delete, inherited by files and subfolders, Success only
            $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                [System.Security.AccessControl.FileSystemRights]"Write,Delete,DeleteSubdirectoriesAndFiles",
                [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                [System.Security.AccessControl.PropagationFlags]"None",
                [System.Security.AccessControl.AuditFlags]"Success"
            )
            $acl.AddAuditRule($auditRule)
            Set-Acl -Path $folder -AclObject $acl
            Write-Log "Audit SACL set on: $folder"
            Write-Host "  + Audit SACL applied: $folder" -ForegroundColor Green
        } catch {
            Write-Log "Unable to set SACL on '$folder': $_" "WARN"
            Write-Host "  x SACL failed on $folder : $_" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# Query the Security Event Log to find who modified a file
# Event ID 4663 = object access attempt (write/delete)
# ---------------------------------------------------------------------------
function Get-FileModifierInfo {
    param([string]$FilePath, [int]$LookbackMinutes = 60)

    $results  = @()
    try {
        $since    = (Get-Date).AddMinutes(-$LookbackMinutes)
        $fileName = Split-Path $FilePath -Leaf

        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4663
            StartTime = $since
        } -ErrorAction SilentlyContinue

        foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()

            # Direct XML parsing without namespace manager for simplicity
            $objName     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectName'        }).'#text'
            $procName    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessName'       }).'#text'
            $subjectUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName'   }).'#text'
            $subjectDom  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'
            $pid_raw     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId'         }).'#text'
            # The log records PID in hexadecimal (e.g. 0xab98) - convert to decimal
            $pid_        = if ($pid_raw -match '^0x[0-9a-fA-F]+$') {
                               [Convert]::ToInt64($pid_raw, 16).ToString()
                           } else { $pid_raw }
            $accesses    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'AccessList'        }).'#text'

            if ($objName -and $objName -like "*$fileName*") {
                $results += [PSCustomObject]@{
                    Time        = $ev.TimeCreated
                    File        = $objName
                    Process     = if ($procName) { Split-Path $procName -Leaf } else { '?' }
                    ProcessPath = $procName
                    PID         = $pid_
                    User        = if ($subjectDom -and $subjectUser) { "$subjectDom\$subjectUser" } else { $subjectUser }
                    Access      = $accesses -replace '\s+', ' '
                }
            }
        }
    } catch {
        Write-Log "Error reading Security log for '$FilePath': $_" "WARN"
    }

    # Return the most recent events, up to 5
    return @($results | Sort-Object Time -Descending | Select-Object -First 5)
}

# ---------------------------------------------------------------------------
# HASH CHECK (normal run)
# ---------------------------------------------------------------------------
function Invoke-HashCheck {
    param($Cfg)

    Write-Log "Starting canary file verification..."

    if (-not (Test-Path $HashDb)) {
        Write-Log "Hash database not found: $HashDb" "ERROR"
        return
    }

    $baseline     = Get-Content $HashDb -Raw | ConvertFrom-Json
    $alerts       = @()
    $missingFiles = @()

    foreach ($entry in $baseline.PSObject.Properties) {
        $filePath     = $entry.Name
        $expectedHash = $entry.Value

        if (-not (Test-Path $filePath)) {
            $missingFiles += $filePath
            Write-Log "MISSING FILE: $filePath" "WARN"
            continue
        }

        $currentHash = Get-FileSHA256 -Path $filePath
        if ($currentHash -ne $expectedHash) {
            $alerts += [PSCustomObject]@{
                File     = $filePath
                Expected = $expectedHash.Substring(0,16) + "..."
                Current  = $currentHash.Substring(0,16) + "..."
            }
            Write-Log "MODIFICATION DETECTED: $filePath" "WARN"
            Write-Log "  Expected : $expectedHash" "WARN"
            Write-Log "  Found    : $currentHash" "WARN"
        }
    }

    if ($alerts.Count -gt 0 -or $missingFiles.Count -gt 0) {
        $alertMsg  = "POSSIBLE RANSOMWARE detected on $script:Hostname`n"
        $alertMsg += "Time: $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')`n"
        $pathList_ = if ($Cfg -is [hashtable]) { $Cfg['MonitorPaths'] } else { $Cfg.MonitorPaths }
        $alertMsg += "Monitored paths: $($pathList_ -join ', ')`n"

        if ($alerts.Count -gt 0) {
            $alertMsg += "`nModified files ($($alerts.Count)):`n"
            foreach ($a in $alerts) {
                $modInfo = Get-FileModifierInfo -FilePath $a.File -LookbackMinutes 120
                $who = if (@($modInfo).Count -gt 0) {
                    $m = $modInfo[0]
                    " [Process: $($m.Process) PID:$($m.PID) User: $($m.User)]"
                } else { " [process not found in log]" }
                $alertMsg += "  - $(Split-Path $a.File -Leaf)$who`n"
            }
        }
        if ($missingFiles.Count -gt 0) {
            $alertMsg += "`nDeleted files ($($missingFiles.Count)):`n"
            foreach ($f in $missingFiles) {
                $delInfo = Get-FileModifierInfo -FilePath $f -LookbackMinutes 120
                $who = if (@($delInfo).Count -gt 0) {
                    $m = $delInfo[0]
                    " [Process: $($m.Process) PID:$($m.PID) User: $($m.User)]"
                } else { " [process not found in log]" }
                $alertMsg += "  - $(Split-Path $f -Leaf)$who`n"
            }
        }

        Send-AllAlerts -Cfg $Cfg -Subject "[$script:Hostname] RansomwareGuard ALERT" -Body $alertMsg
        Write-Log "ALERT sent: $($alerts.Count) modification(s), $($missingFiles.Count) deletion(s)" "WARN"
    } else {
        $fileCount = @($baseline.PSObject.Properties).Count
        Write-Log "Check OK - no modifications detected ($fileCount file(s))."
    }
}

# ---------------------------------------------------------------------------
# MANAGEMENT MENU (--manage argument)
# ---------------------------------------------------------------------------
function Invoke-ManageMenu {
    param($Cfg)
    Write-Host "`n╔══════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   RansomwareGuard - Management   ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  1. Recompute hash baseline (after legitimate updates)"
    Write-Host "  2. Send test notification"
    Write-Host "  3. Show current configuration"
    Write-Host "  4. Reconfigure from scratch"
    Write-Host "  5. Reapply audit SACL on folders"
    Write-Host "  6. Exit"
    $choice = Read-Host "`nChoice"
    switch ($choice) {
        "1" {
            $hashes = @{}
            $paths_ = @(if ($Cfg -is [hashtable]) { $Cfg['MonitorPaths'] } else { $Cfg.MonitorPaths })
            foreach ($dir in $paths_) {
                Write-Host "`n  -- $dir" -ForegroundColor Cyan
                Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '^rg_' } | ForEach-Object {
                    $h = Get-FileSHA256 -Path $_.FullName
                    if ($h) {
                        $hashes[$_.FullName] = $h
                        Write-Host "  + $($_.Name) [$($h.Substring(0,16))...]" -ForegroundColor Green
                    }
                }
            }
            $hashes | ConvertTo-Json | Set-Content -Path $HashDb -Encoding UTF8
            $pathCount_ = @($paths_).Count
            Write-Log "Hash baseline recomputed across $pathCount_ folder(s), $($hashes.Count) file(s)."
        }
        "2" {
            Send-AllAlerts -Cfg $Cfg `
                -Subject "[$script:Hostname] RansomwareGuard Test" `
                -Body "Test notification from $script:Hostname"
        }
        "3" {
            $Cfg | Format-List
        }
        "4" {
            Remove-Item $ConfigFile -Force -ErrorAction SilentlyContinue
            Remove-Item $HashDb     -Force -ErrorAction SilentlyContinue
            Invoke-FirstSetup
        }
        "5" {
            $paths_ = @(if ($Cfg -is [hashtable]) { $Cfg['MonitorPaths'] } else { $Cfg.MonitorPaths })
            Write-Host "`n  Reapplying audit SACL..." -ForegroundColor Cyan
            Enable-FolderAuditing -Paths $paths_
        }
        "6"     { Write-Host "Exiting." }
        default { Write-Host "Exiting." }
    }
}

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
# Real network hostname (possibly FQDN), more reliable than $env:COMPUTERNAME
$script:Hostname = [System.Net.Dns]::GetHostName()
Write-Log "=== RansomwareGuard started (user: $env:USERNAME, host: $script:Hostname) ==="

# --manage argument opens the management menu
if ($args -contains "--manage") {
    if (Test-Path $ConfigFile) {
        $cfgRaw = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        $cfg = @{}
        $cfgRaw.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
        Invoke-ManageMenu -Cfg $cfg
    } else {
        Write-Host "No configuration found. Run the script without arguments to start setup." -ForegroundColor Yellow
    }
    exit 0
}

# First run if config does not exist
if (-not (Test-Path $ConfigFile)) {
    Write-Log "First run detected - starting interactive setup."
    Invoke-FirstSetup
    exit 0
}

# Normal run: load config and verify hashes
$cfgRaw = Get-Content $ConfigFile -Raw | ConvertFrom-Json
$cfg = @{}
$cfgRaw.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }

Invoke-HashCheck -Cfg $cfg

Write-Log "=== RansomwareGuard finished ==="
