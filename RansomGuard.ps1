#Requires -Version 5.1
<#

https://github.com/Leproide/POWERSHELL-Windows-Ransomware-Guard/

.SYNOPSIS
    RansomwareGuard - Honeypot file monitor con notifiche multi-canale
.DESCRIPTION
    Crea file "esca" (canary files) in cartelle monitorate.
    Usa FileSystemWatcher per rilevare modifiche, cancellazioni e rinomina
    in tempo reale (zero scritture su disco, zero carico CPU a riposo).
    Notifica via Telegram, Gotify e MSG al primo evento su un canary.
    Esegue inoltre un hash check periodico come controllo di sicurezza aggiuntivo.
.NOTES
    Primo avvio      : configurazione interattiva -> salva config.json
    --watch          : avvia il watcher continuo (usato dal Task Scheduler)
    --manage         : apre il menu di gestione
    Senza argomenti  : singolo hash check manuale (test rapido)
#>

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# PERCORSI
# $PSScriptRoot e $PSCommandPath sono variabili automatiche sempre definite
# (stringa vuota se non applicabile) - sicure con StrictMode.
# $MyInvocation.MyCommand.Path viene EVITATO: sotto SYSTEM/Task Scheduler
# la proprieta .Path puo essere assente e StrictMode lancia eccezione.
# ---------------------------------------------------------------------------
$ScriptDir = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($PSCommandPath) {
    Split-Path -Parent $PSCommandPath
} else {
    $PWD.Path
}

# StrictMode attivato DOPO la risoluzione del percorso
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# OS detection: metodo di identificazione processo adattivo
#   Win10/11 (build 10240+) e Server 2016+ (build 14393+):
#     Primario  -> Security log 4663 + 4656 correlati via HandleId
#   Fallback: snapshot processi per eta (tutti, nessun filtro)
# ---------------------------------------------------------------------------
$script:OSBuild = [System.Environment]::OSVersion.Version.Build
$script:CanUseSecLog = ($script:OSBuild -ge 10240)   # Win10/11 e Server 2016+
# OS build e CanUseSecLog impostati prima di caricare le funzioni
$ConfigFile = Join-Path $ScriptDir "rg_config.json"
$HashDb     = Join-Path $ScriptDir "rg_hashes.json"
$LogFile    = Join-Path $ScriptDir "rg_log.txt"
$PendingFile = Join-Path $ScriptDir "rg_pending.json"

# ---------------------------------------------------------------------------
# NOMI VEROSIMILI PER I FILE ESCA
# Mescolano estensioni Office, testo, backup - appetibili per un ransomware
# ---------------------------------------------------------------------------
$CanaryNames = @(
    "desktop.ini",
    "~WRL0003.tmp",
    "Budget_2024_Final.xlsx",
    "Contratto_Fornitura_Rev3.docx",
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
    $ts  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    if ($Level -eq "WARN" -or $Level -eq "ERROR") {
        Write-Host $line -ForegroundColor Yellow
    } else {
        Write-Host $line
    }
}

# ---------------------------------------------------------------------------
# HELPER: Calcola SHA256
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
# NOTIFICHE
# ---------------------------------------------------------------------------
function Send-TelegramNotify {
    param($Cfg, [string]$Text)
    try {
        $url     = "https://api.telegram.org/bot$($Cfg.TelegramToken)/sendMessage"
        $bodyObj = @{ chat_id = $Cfg.TelegramChatId; text = $Text; parse_mode = "HTML" }
        $jsonStr  = $bodyObj | ConvertTo-Json -Compress
        $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonStr)
        $response = [System.Net.WebRequest]::Create($url)
        $response.Method      = "POST"
        $response.ContentType = "application/json; charset=utf-8"
        $response.Timeout     = 10000
        $stream = $response.GetRequestStream()
        $stream.Write($jsonBytes, 0, $jsonBytes.Length)
        $stream.Close()
        $response.GetResponse().Close()
        Write-Log "Notifica Telegram inviata."
    } catch {
        Write-Log "Errore invio Telegram: $_" "WARN"
    }
}

function Send-GotifyNotify {
    param($Cfg, [string]$Title, [string]$Msg)
    try {
        $url      = "$($Cfg.GotifyUrl)/message?token=$($Cfg.GotifyToken)"
        $bodyObj  = @{ title = $Title; message = $Msg; priority = 8 }
        $jsonStr  = $bodyObj | ConvertTo-Json -Compress
        $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonStr)
        $req = [System.Net.WebRequest]::Create($url)
        $req.Method      = "POST"
        $req.ContentType = "application/json; charset=utf-8"
        $req.Timeout     = 10000
        $stream = $req.GetRequestStream()
        $stream.Write($jsonBytes, 0, $jsonBytes.Length)
        $stream.Close()
        $req.GetResponse().Close()
        Write-Log "Notifica Gotify inviata."
    } catch {
        Write-Log "Errore invio Gotify: $_" "WARN"
    }
}

function Send-WindowsAlert {
    param([string]$Message)
    # Prova MSG * (funziona su Pro/Server con sessioni RDP/console attive)
    try {
        $msgExe = "$env:SystemRoot\System32\msg.exe"
        if (Test-Path $msgExe) {
            & $msgExe * /TIME:60 $Message 2>$null
        }
    } catch { }

    # Fallback 1: Toast Notification nativo Windows 10/11
    try {
        $xmlToast = "<?xml version=""1.0""?>" +
                    "<toast><visual><binding template=""ToastGeneric"">" +
                    "<text>⚠️ RansomwareGuard ALERT</text>" +
                    "<text>" + [System.Security.SecurityElement]::Escape($Message) + "</text>" +
                    "</binding></visual></toast>"
        [Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom,ContentType=WindowsRuntime] | Out-Null
        $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xmlDoc.LoadXml($xmlToast)
        $toast  = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
        $appId  = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
        Write-Log "Toast notification inviata."
    } catch {
        # Fallback 2: popup WScript visibile anche da SYSTEM
        try {
            $wsh = New-Object -ComObject WScript.Shell
            $wsh.Popup($Message, 0, "⚠️ RansomwareGuard ALERT", 16) | Out-Null
        } catch {
            Write-Log "Impossibile mostrare avviso grafico: $_" "WARN"
        }
    }
}

function Send-AllAlerts {
    param($Cfg, [string]$Subject, [string]$Body)
    $doTelegram = if ($Cfg.ContainsKey("EnableTelegram")) { [bool]$Cfg.EnableTelegram } else { $true }
    $doGotify   = if ($Cfg.ContainsKey("EnableGotify"))   { [bool]$Cfg.EnableGotify   } else { $true }
    $doPopup    = if ($Cfg.ContainsKey("EnablePopup"))    { [bool]$Cfg.EnablePopup    } else { $true }
    if ($doTelegram) {
        Send-TelegramNotify -Cfg $Cfg -Text "<b>$Subject</b>`n$Body"
    } else {
        Write-Log "Notifica Telegram disabilitata (EnableTelegram=false)."
    }
    if ($doGotify) {
        Send-GotifyNotify -Cfg $Cfg -Title $Subject -Msg $Body
    } else {
        Write-Log "Notifica Gotify disabilitata (EnableGotify=false)."
    }
    if ($doPopup) {
        Send-WindowsAlert -Message "$Subject`n$Body"
    } else {
        Write-Log "Notifica Popup/MSG disabilitata (EnablePopup=false)."
    }
}

# ---------------------------------------------------------------------------
# PRIMO AVVIO: configurazione interattiva
# ---------------------------------------------------------------------------
function Invoke-FirstSetup {
    Write-Host "`n+=========================================+" -ForegroundColor Cyan
    Write-Host "||   RansomwareGuard - Setup iniziale   ||" -ForegroundColor Cyan
    Write-Host "+=========================================+`n" -ForegroundColor Cyan

    $monitorPaths = [System.Collections.Generic.List[string]]::new()
    Write-Host "`n[Cartelle da monitorare]" -ForegroundColor Cyan
    Write-Host "  Inserisci i percorsi uno alla volta." -ForegroundColor Gray
    Write-Host "  Premi INVIO senza scrivere nulla per terminare (minimo 1)." -ForegroundColor Gray

    while ($true) {
        $idx = $monitorPaths.Count + 1
        $prompt = if ($monitorPaths.Count -eq 0) { "  Percorso #$idx (obbligatorio)" } `
                  else                            { "  Percorso #$idx (o INVIO per finire)" }
        $input_ = (Read-Host $prompt).Trim()

        if ($input_ -eq "") {
            if ($monitorPaths.Count -eq 0) {
                Write-Host "  ! Devi inserire almeno un percorso." -ForegroundColor Red
                continue
            }
            break
        }

        if (-not (Test-Path $input_ -PathType Container)) {
            $create = Read-Host "  ! Percorso non trovato. Creare la cartella? (s/N)"
            if ($create -match "^[sS]$") {
                try {
                    New-Item -ItemType Directory -Path $input_ -Force | Out-Null
                    Write-Host "  OK Cartella creata." -ForegroundColor Green
                } catch {
                    Write-Host "  ! Impossibile creare la cartella: $_" -ForegroundColor Red
                    continue
                }
            } else {
                continue
            }
        }

        if ($monitorPaths.Contains($input_)) {
            Write-Host "  !! Percorso gia inserito, ignorato." -ForegroundColor Yellow
            continue
        }

        $monitorPaths.Add($input_)
        Write-Host "  >> Aggiunto: $input_" -ForegroundColor Green
    }

    Write-Host "`n  Riepilogo cartelle selezionate:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $monitorPaths.Count; $i++) {
        Write-Host "    $($i+1). $($monitorPaths[$i])" -ForegroundColor White
    }
    $confirm = Read-Host "`n  Confermi questi $($monitorPaths.Count) percorsi? (S/n)"
    if ($confirm -match "^[nN]$") {
        Write-Host "  Configurazione annullata. Riavvia lo script per ricominciare." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "`n[Telegram Bot]"
    $tgToken  = Read-Host "  Token bot Telegram (es. 123456:ABC...)"
    $tgChatId = Read-Host "  Chat ID destinatario (es. -100123456789)"

    Write-Host "`n[Gotify]"
    $gotifyHost  = Read-Host "  Host Gotify (es. https://push.example.com)"
    $gotifyPort  = Read-Host "  Porta Gotify (lascia vuoto per default 80/443)"
    $gotifyToken = Read-Host "  App Token Gotify"
    $gotifyUrl = if ($gotifyPort -match "^\d+$") {
        "$($gotifyHost.TrimEnd("/"))`:$gotifyPort"
    } else {
        $gotifyHost.TrimEnd("/")
    }

    Write-Host "`n[Notifiche - abilita/disabilita]"
    $enTelegram = Read-Host "  Abilita Telegram? (S/n)"
    $enGotify   = Read-Host "  Abilita Gotify?   (S/n)"
    $enPopup    = Read-Host "  Abilita Popup/MSG Windows? (S/n)"

    Write-Host "`n[Hash check periodico]"
    $interval = Read-Host "  Intervallo hash check in minuti (default: 15, minimo: 5)"
    if (-not $interval -or $interval -notmatch "^\d+$" -or [int]$interval -lt 5) { $interval = "15" }
    
    # --- INIZIO MODIFICA: Aggiunta opzione per il Kill del processo ---
    Write-Host "`n[Risposta Attiva]"
    $enKill = Read-Host "  Abilita la terminazione automatica del processo sospetto? (s/N)"
    # --- FINE MODIFICA ---

    $cfg = @{
        MonitorPaths   = @($monitorPaths)
        TelegramToken  = $tgToken
        TelegramChatId = $tgChatId
        GotifyUrl      = $gotifyUrl
        GotifyToken    = $gotifyToken
        CheckInterval  = [int]$interval
        SetupDone      = $true
        EnableTelegram = ($enTelegram -notmatch "^[nN]$")
        EnableGotify   = ($enGotify   -notmatch "^[nN]$")
        EnablePopup    = ($enPopup    -notmatch "^[nN]$")
        EnableProcessKill = ($enKill -match "^[sS]$") # --- MODIFICA ---
    }

    $hashes = @{}
    $totalErrors = 0

    foreach ($canaryDir in $monitorPaths) {
        Write-Host "`n  -- $canaryDir --" -ForegroundColor Cyan

        $existingFiles = @(Get-ChildItem -Path $canaryDir -File -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -notmatch "^rg_" })

        if ($existingFiles.Count -gt 0) {
            Write-Host "  Trovati $($existingFiles.Count) file esistenti -- calcolo hash baseline..." -ForegroundColor Gray
            foreach ($f in $existingFiles) {
                $hash = Get-FileSHA256 -Path $f.FullName
                if ($hash) {
                    $hashes[$f.FullName] = $hash
                    Write-Host "    OK $($f.Name)  [$($hash.Substring(0,16))...]" -ForegroundColor Green
                } else {
                    Write-Host "    !! $($f.Name)  [hash fallito]" -ForegroundColor Red
                    $totalErrors++
                }
            }
        } else {
            Write-Host "  Cartella vuota -- creazione file esca..." -ForegroundColor Gray
            foreach ($name in $CanaryNames) {
                $fullPath = Join-Path $canaryDir $name
                try {
                    $fileContent = New-CanaryContent -FileName $name
                    if ($fileContent -eq "__BINARY_OLE2__") {
                        $rngB = [System.Random]::new()
                        $ole  = [byte[]](0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                        $noise= [byte[]](1..496 | ForEach-Object { $rngB.Next(0,256) })
                        [System.IO.File]::WriteAllBytes($fullPath, ($ole + $noise))
                    } else {
                        [System.IO.File]::WriteAllText($fullPath, $fileContent, [System.Text.Encoding]::UTF8)
                    }
                    if (Test-Path $fullPath) {
                        $hash = Get-FileSHA256 -Path $fullPath
                        if ($hash) {
                            $hashes[$fullPath] = $hash
                            Write-Host "    OK $name  [$($hash.Substring(0,16))...]" -ForegroundColor Green
                        } else {
                            Write-Host "    !! $name  [hash fallito]" -ForegroundColor Red
                            $totalErrors++
                        }
                    } else {
                        Write-Host "    !! $name  [NON creato su disco!]" -ForegroundColor Red
                        Write-Log "ERRORE: file non trovato dopo scrittura: $fullPath" "ERROR"
                        $totalErrors++
                    }
                } catch {
                    Write-Host "    !! $name  [errore: $_]" -ForegroundColor Red
                    Write-Log "ERRORE creazione $name in $canaryDir : $_" "ERROR"
                    $totalErrors++
                }
            }
        }
    }

    if ($totalErrors -gt 0) {
        Write-Host "`n  !! $totalErrors errori durante la preparazione file." -ForegroundColor Yellow
    } else {
        Write-Host "`n  OK Tutti i file pronti su $($monitorPaths.Count) cartelle ($($hashes.Count) hash totali)." -ForegroundColor Green
    }

    $cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-Log "Configurazione salvata in $ConfigFile"

    $hashes | ConvertTo-Json | Set-Content -Path $HashDb -Encoding UTF8
    Write-Log "Hash baseline salvati: $($hashes.Count) file"

    # Abilita audit SACL sulle cartelle e sui file canary
    Write-Host "`n[Audit SACL + Handle Manipulation]" -ForegroundColor Cyan
    $allCanaryPaths = @($hashes.Keys)
    Enable-FolderAuditing -Paths @($monitorPaths) -CanaryFiles $allCanaryPaths

    Register-RGScheduledTask -Cfg $cfg

    Write-Host "`n  ✅ Setup completato! Il watcher partira al prossimo avvio del sistema.`n" -ForegroundColor Green
    Write-Host "  Per avviarlo subito: .\RansomGuard.ps1 --watch" -ForegroundColor Gray

    $test = Read-Host "Vuoi inviare una notifica di test? (s/N)"
    if ($test -match "^[sS]$") {
        Send-AllAlerts -Cfg $cfg `
            -Subject "[$script:Hostname] RansomwareGuard - Setup OK" `
            -Body "Setup completato su $script:Hostname. Cartelle monitorate: $($monitorPaths -join ", ")"
    }
}

# ---------------------------------------------------------------------------
# Genera contenuto verosimile per ogni estensione.
# ---------------------------------------------------------------------------
function New-CanaryContent {
    param([string]$FileName)
    $ext  = [System.IO.Path]::GetExtension($FileName).ToLower()
    $base = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $rng  = [System.Random]::new()

    function Get-RandStr { param([int]$Len)
        $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        -join (1..$Len | ForEach-Object { $chars[$rng.Next($chars.Length)] })
    }
    function Get-RandInt { param([int]$Min,[int]$Max) $rng.Next($Min,$Max) }

    $firstNames = @("Marco","Laura","Giovanni","Alessia","Roberto","Francesca","Luca","Sara","Andrea","Elena")
    $lastNames  = @("Rossi","Ferrari","Bianchi","Romano","Conti","Ricci","Marino","Greco","Bruno","Gallo")
    $depts      = @("Amministrazione","Commerciale","IT","Risorse Umane","Logistica","Marketing","Acquisti")
    $year  = (Get-Date).Year
    $month = (Get-Date).ToString("MM")
    $day   = (Get-Date).ToString("dd")
    $host_ = $script:Hostname

    switch ($ext) {
        ".txt" {
            $lines = @(
                "Ultimo aggiornamento: $day/$month/$year",
                "Responsabile: $($firstNames[$rng.Next($firstNames.Length)]) $($lastNames[$rng.Next($lastNames.Length)])",
                "Reparto: $($depts[$rng.Next($depts.Length)])",
                "",
                "Server principale : $host_",
                "Share             : \\$host_\Dati_$($depts[$rng.Next($depts.Length)])",
                "Utente servizio   : svc_$(Get-RandStr 6)",
                "Porta             : $(Get-RandInt 1024 9000)",
                "",
                "Note: verificare accessi dopo manutenzione del $(Get-RandInt 1 28)/$month/$year",
                "Ticket riferimento: INC$(Get-RandInt 100000 999999)"
            )
            return $lines -join "`r`n"
        }
        ".ini" {
            return "[.ShellClassInfo]`r`nIconResource=C:\Windows\System32\imageres.dll,$(Get-RandInt 1 200)`r`nIconIndex=$(Get-RandInt 0 50)`r`n[ViewState]`r`nMode=`r`nVid={$(([System.Guid]::NewGuid()).ToString().ToUpper())}`r`nFolderType=Documents"
        }
        ".xml" {
            $entries = @()
            1..(Get-RandInt 4 9) | ForEach-Object {
                $fn = $firstNames[$rng.Next($firstNames.Length)]
                $ln = $lastNames[$rng.Next($lastNames.Length)]
                $id = Get-RandInt 1000 9999
                $sal= Get-RandInt 28000 95000
                $entries += "  <dipendente id=""$id""><nome>$fn</nome><cognome>$ln</cognome><reparto>$($depts[$rng.Next($depts.Length)])</reparto><ral>$sal</ral></dipendente>"
            }
            return "<?xml version=""1.0"" encoding=""utf-8""?>`r`n<organico anno=""$year"" societa=""$(Get-RandStr 6) S.r.l."" esportato=""$day/$month/$year"">`r`n$($entries -join "`r`n")`r`n</organico>"
        }
        ".sql" {
            $table = @("clienti","ordini","fatture","contratti","prodotti","dipendenti")[$rng.Next(6)]
            $rows  = @()
            1..(Get-RandInt 5 12) | ForEach-Object {
                $fn  = $firstNames[$rng.Next($firstNames.Length)]
                $ln  = $lastNames[$rng.Next($lastNames.Length)]
                $id  = Get-RandInt 1 9999
                $val = Get-RandInt 100 50000
                $rows += "INSERT INTO $table VALUES ($id, ""$fn"", ""$ln"", $val, ""$year-$month-$day"");"
            }
            return "-- $table export $day/$month/$year`r`n-- Host: $host_`r`nUSE [$(Get-RandStr 8)_db];`r`nGO`r`n`r`n$($rows -join ""`r`n"")"
        }
        ".xlsx" {
            $headers = "Mese;Categoria;Importo;Centro di costo;Note"
            $cats    = @("Personale","Affitti","Utenze","Fornitori","Rimborsi","Ammortamenti")
            $rows    = @($headers)
            1..(Get-RandInt 8 20) | ForEach-Object {
                $m   = Get-RandInt 1 12
                $imp = "{0:N2}" -f ($rng.NextDouble() * 50000 + 500)
                $cc  = "CC$(Get-RandInt 100 999)"
                $rows += "$m/$year;$($cats[$rng.Next($cats.Length)]);$imp;$cc;$(Get-RandStr 8)"
            }
            return $rows -join "`r`n"
        }
        ".docx" {
            $fn1 = $firstNames[$rng.Next($firstNames.Length)]; $ln1 = $lastNames[$rng.Next($lastNames.Length)]
            $fn2 = $firstNames[$rng.Next($firstNames.Length)]; $ln2 = $lastNames[$rng.Next($lastNames.Length)]
            $art = Get-RandInt 3 12; $pag = Get-RandInt 2 8
            return "{\rtf1\ansi\deff0{\fonttbl{\f0 Times New Roman;}}\f0\fs24 " +
                   "Contratto di fornitura servizi - $day/$month/$year\par\par " +
                   "Tra $fn1 $ln1 (di seguito Committente) e $fn2 $ln2 (di seguito Fornitore).\par\par " +
                   "Art. 1 - Oggetto del contratto\par Il Fornitore si impegna a erogare i servizi.\par\par " +
                   "Art. 2 - Durata\par Durata di $(Get-RandInt 12 36) mesi dalla sottoscrizione.\par\par " +
                   "Totale pagine: $pag - Articoli: $art\par}"
        }
        ".qbb" {
            $magic = "QBWIN`t$(Get-RandStr 4)`tBackup`t$year$month$day`tver=R$(Get-RandInt 10 30).$(Get-RandInt 0 9)"
            $noise = -join (1..200 | ForEach-Object { [char]($rng.Next(32,126)) })
            return "$magic`r`n$noise"
        }
        ".tmp" {
            return "__BINARY_OLE2__"
        }
        default {
            $rows = @("ID;Descrizione;Quantita;Prezzo;Totale;Data")
            1..(Get-RandInt 6 15) | ForEach-Object {
                $id  = Get-RandInt 1000 9999
                $qty = Get-RandInt 1 100
                $prc = "{0:N2}" -f ($rng.NextDouble() * 500 + 10)
                $tot = "{0:N2}" -f ($qty * [double]$prc.Replace(",","."))
                $rows += "$id;$(Get-RandStr 12);$qty;$prc;$tot;$day/$month/$year"
            }
            return $rows -join "`r`n"
        }
    }
}

# ---------------------------------------------------------------------------
# Abilita auditing SACL sulle cartelle e sui file canary.
# Usa GUID di auditpol per essere locale-safe (funziona su IT/EN/etc).
#   {0CCE921F} = File System
#   {0CCE9223} = Handle Manipulation (necessario per avere 4656 con ProcessName)
# ---------------------------------------------------------------------------
function Enable-FolderAuditing {
    param([string[]]$Paths, [string[]]$CanaryFiles = @())

    # Abilita sottocategorie audit via GUID
    foreach ($guid in @("{0CCE921F-69AE-11D9-BED3-505054503030}",
                        "{0CCE9223-69AE-11D9-BED3-505054503030}")) {
        try {
            # --- INIZIO MODIFICA: Rimossa chiamata ridondante e migliorato il logging ---
            & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable
            Write-Log "Audit policy impostata per subcategory $guid"
            # --- FINE MODIFICA ---
        } catch {
            Write-Log "auditpol fallito per $guid : $_" "WARN"
        }
    }

    # SACL su cartelle (ereditata dai file figli)
    $folderRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        [System.Security.AccessControl.FileSystemRights]"WriteData,AppendData,Delete,DeleteSubdirectoriesAndFiles",
        [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
        [System.Security.AccessControl.PropagationFlags]"None",
        [System.Security.AccessControl.AuditFlags]"Success"
    )
    foreach ($folder in $Paths) {
        if (-not (Test-Path $folder)) { continue }
        try {
            $acl = Get-Acl -Path $folder -Audit
            $acl.AddAuditRule($folderRule)
            Set-Acl -Path $folder -AclObject $acl
            Write-Log "SACL folder: $folder"
            Write-Host "  OK SACL impostata su: $folder" -ForegroundColor Green
        } catch {
            Write-Log "SACL folder fallita $folder : $_" "WARN"
            Write-Host "  !! SACL fallita su $folder : $_" -ForegroundColor Yellow
        }
    }

    # SACL esplicita anche sui singoli file canary
    # (ereditarietà non è immediata su alcuni fs/driver)
    $fileRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        [System.Security.AccessControl.FileSystemRights]"WriteData,AppendData,Delete",
        [System.Security.AccessControl.InheritanceFlags]"None",
        [System.Security.AccessControl.PropagationFlags]"None",
        [System.Security.AccessControl.AuditFlags]"Success"
    )
    foreach ($fp in $CanaryFiles) {
        if (-not (Test-Path $fp)) { continue }
        try {
            $acl = Get-Acl -Path $fp -Audit
            $acl.AddAuditRule($fileRule)
            Set-Acl -Path $fp -AclObject $acl
        } catch {
            Write-Log "SACL file $fp : $_" "WARN"
        }
    }
}

# ---------------------------------------------------------------------------
# Registra Task pianificato Windows
# Trigger AtStartup (+30s), gira come SYSTEM, argomento --watch.
# Auto-restart in caso di crash: max 5 volte ogni 1 minuto.
# ---------------------------------------------------------------------------
function Register-RGScheduledTask {
    param($Cfg)
    $taskName = "RansomwareGuard_Monitor"
    $psExe    = "powershell.exe"

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
        Write-Log "ERRORE: impossibile determinare il percorso dello script. Path rilevato: $scriptPath" "ERROR"
        Write-Host "  !! Task NON registrato: percorso script non trovato." -ForegroundColor Red
        return
    }

    Write-Log "Script per Task pianificato: $scriptPath"

    # Registrazione tramite XML diretto: niente cmdlet, niente COM, niente sorprese.
    # Lo schema e' quello validato manualmente dall'utente.
    # L'unica parte dinamica e' il percorso dello script.
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\$taskName</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>5</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$psExe</Command>
      <Arguments>-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$scriptPath" --watch</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $taskName -Xml $taskXml -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "Impossibile registrare il task (richiede privilegi admin): $_" "WARN"
        Write-Host "  !! Task NON registrato (servono privilegi amministratore): $_" -ForegroundColor Yellow
        return
    }

    # Verifica finale: il task esiste davvero?
    $verifyTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($verifyTask) {
        Write-Log "Task $taskName registrato con successo -> AtStartup, SYSTEM, --watch"
        Write-Host "  OK Task registrato: $taskName" -ForegroundColor Green
    } else {
        Write-Log "Task $taskName non trovato dopo la registrazione." "ERROR"
        Write-Host "  !! Task NON registrato: verifica i log per dettagli." -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# Legge il Security log per identificare il processo che ha modificato il
# file canary. Strategia a due livelli:
#   1. EventId 4663 (accesso effettuato) -> ProcessId hex + ProcessName
#   2. Se ProcessName vuoto (Win11): cerca EventId 4656 con stesso HandleId
#      -> 4656 ha SEMPRE ProcessName pieno (richiede Handle Manipulation)
# Attende 500ms prima di leggere il log per garantire che gli eventi siano
# gia scritti (il log e scritto in modo sincrono dal kernel ma con micro-lag).
# ---------------------------------------------------------------------------
function Get-FileAccessorFromLog {
    param([string]$FilePath, [int]$LookbackSeconds = 45)

    if (-not $script:CanUseSecLog) { return $null }

    # Attende che il kernel finisca di scrivere gli eventi nel log
    Start-Sleep -Milliseconds 500

    $fileName  = Split-Path $FilePath -Leaf
    $startTime = (Get-Date).AddSeconds(-$LookbackSeconds)

    try {
        $rawEvts = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = @(4663, 4656)
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        if (-not $rawEvts) { return $null }

        # Parsa tutti gli eventi in dizionari nome->valore
        $parsed = @($rawEvts | ForEach-Object {
            $ev  = $_
            $xml = [xml]$ev.ToXml()
            $d   = @{ _id = $ev.Id; _time = $ev.TimeCreated }
            $xml.Event.EventData.Data | ForEach-Object {
                $d[$_.Name] = if ($_."#text") { $_."#text" } else { "" }
            }
            $d
        })

        # Filtra 4663 che riguardano il nostro file (ObjectName in NT path)
        $ev4663 = @($parsed |
            Where-Object { $_["_id"] -eq 4663 -and $_["ObjectName"] -like "*$fileName" } |
            Sort-Object { $_["_time"] } -Descending)

        if ($ev4663.Count -eq 0) {
            Write-Log "Get-FileAccessorFromLog: nessun evento 4663 trovato per $fileName" "WARN"
            return $null
        }

        $ev = $ev4663[0]
        $pidHex  = $ev["ProcessId"]
        $pidDec  = try { [Convert]::ToInt32($pidHex.Replace("0x","").Replace("0X",""), 16) } catch { 0 }
        $procName = $ev["ProcessName"]
        $handleId = $ev["HandleId"]
        $user     = "$($ev["SubjectDomainName"])\$($ev["SubjectUserName"])"

        Write-Log "4663 trovato: PID=$pidDec procName=$procName handle=$handleId user=$user"

        # Se ProcessName e vuoto -> cerca 4656 con stesso HandleId
        if (-not $procName -or $procName -eq "-") {
            $ev4656 = @($parsed |
                Where-Object {
                    $_["_id"] -eq 4656 -and
                    $_["HandleId"] -eq $handleId -and
                    $_["ObjectName"] -like "*$fileName"
                })
            if ($ev4656.Count -gt 0 -and $ev4656[0]["ProcessName"]) {
                $procName = $ev4656[0]["ProcessName"]
                Write-Log "ProcessName recuperato da 4656: $procName"
            }
        }

        # Ultimo fallback: risolvi PID -> processo ancora in vita
        if ((!$procName -or $procName -eq "-") -and $pidDec -gt 0) {
            $proc = Get-Process -Id $pidDec -ErrorAction SilentlyContinue
            if ($proc) {
                $procName = try { $proc.Path } catch { $proc.Name }
                Write-Log "ProcessName da Get-Process: $procName"
            }
        }

        return [PSCustomObject]@{
            PID         = $pidDec
            ProcessName = if ($procName) { $procName } else { "PID:$pidDec" }
            User        = $user
            HandleId    = $handleId
            ObjectName  = $ev["ObjectName"]
            EventTime   = $ev["_time"]
        }
    } catch {
        Write-Log "Get-FileAccessorFromLog errore: $_" "WARN"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Coda persistente degli alert (rg_pending.json)
#
# Ogni evento canary viene accodato immediatamente con snapshot processi.
# Send-PendingAlerts tenta di inviare tutti gli entry non ancora inviati
# ad ogni ciclo del watcher. Gli entry gia inviati vengono rimossi dopo
# 1 ora per non far crescere il file.
# Deduplication: stesso file + stesso tipo entro 5 minuti = non accodare.
# ---------------------------------------------------------------------------
function Add-PendingAlert {
    param(
        [string]$FilePath,
        [string]$EvType,
        [string]$OldName,
        [array]$Snapshot,
        $Cfg # --- MODIFICA: Passata la configurazione per la funzione di Kill ---
    )

    # ── Calcola l'hash dello stato del file al momento dell'evento ─────────
    # Usato per la deduplication: se arriva un secondo evento con lo STESSO
    # hash -> gia' notificato, ignora. Se l'hash e' cambiato -> notifica di nuovo.
    $eventFileHash = switch ($EvType) {
        "ELIMINATO"  { "DELETED" }
        "RINOMINATO" { "RENAMED:$OldName" }
        default {
            # MODIFICATO: hash SHA256 del contenuto attuale.
            # Se il file e' locked (ransomware lo tiene aperto), Get-FileSHA256
            # restituisce null. In quel caso usiamo LastWriteTimeUtc + GUID:
            # - LastWriteTime cambia ad ogni scrittura -> eventi diversi nel tempo
            # - GUID garantisce unicita' anche se due write hanno stesso timestamp
            # Questo evita che "MODIFIED_UNREADABLE" costante blocchi il dedup
            # su modifiche successive, impedendo processo-lookup e kill.
            if (Test-Path $FilePath) {
                $h = Get-FileSHA256 -Path $FilePath
                if ($h) {
                    $h
                } else {
                    $lwt = try { (Get-Item $FilePath -ErrorAction Stop).LastWriteTimeUtc.Ticks } catch { 0 }
                    "MODIFIED_LOCKED:${lwt}:$([System.Guid]::NewGuid())"
                }
            } else { "MODIFIED_GONE:$([System.Guid]::NewGuid())" }
        }
    }

    # ── Carica coda corrente ──────────────────────────────────────────────
    $pending = @()
    if (Test-Path $PendingFile) {
        try {
            $raw = Get-Content $PendingFile -Raw -ErrorAction Stop
            $pending = @($raw | ConvertFrom-Json | ForEach-Object { $_ })
        } catch {
            $pending = @()
        }
    }

    # ── Dedup basata su hash ──────────────────────────────────────────────
    # Considera SOLO entry non ancora inviate, o inviate da meno di 5 minuti.
    # Le entry gia' inviate e "vecchie" non bloccano future notifiche:
    # questo garantisce che eventi successivi sullo stesso file vengano
    # sempre notificati, anche se il contenuto torna identico.
    $dedupCutoff = (Get-Date).AddMinutes(-5)
    $dup = $pending | Where-Object {
        $_.FilePath -eq $FilePath -and
        $_.EvType   -eq $EvType   -and
        ($_.EventFileHash -as [string]) -eq ($eventFileHash -as [string]) -and
        (
            $_.Sent -ne $true -or
            (
                $_.SentAt -and
                ( [datetime]($_.SentAt -as [string]) ) -gt $dedupCutoff
            )
        )
    }
    if ($dup) {
        Write-Log "Evento ignorato (hash invariato, gia' notificato di recente [$($eventFileHash.Substring(0,[Math]::Min(16,$eventFileHash.Length)))...]): $EvType $FilePath"
        return
    }

    # ── Identifica processo via Security log (4663/4656) ──────────────────
    # Viene fatto DOPO il dedup per non sprecare i 500ms di attesa su duplicati
    $accessor = Get-FileAccessorFromLog -FilePath $FilePath -LookbackSeconds 45
    if ($accessor) {
        Write-Log "Accessor identificato: $($accessor.ProcessName) PID:$($accessor.PID) User:$($accessor.User)" "WARN"
        
        # --- INIZIO MODIFICA: Kill del processo se abilitato in config ---
        $doKill = if ($Cfg.ContainsKey("EnableProcessKill")) { [bool]$Cfg.EnableProcessKill } else { $false }
        if ($doKill -and $accessor.PID -gt 0) {
            try {
                Stop-Process -Id $accessor.PID -Force -ErrorAction Stop
                Write-Log "PROCESSO TERMINATO: PID $($accessor.PID) ($($accessor.ProcessName)) è stato terminato." "WARN"
            } catch {
                Write-Log "Impossibile terminare il processo PID $($accessor.PID): $_" "WARN"
            }
        }
        # --- FINE MODIFICA ---

    } else {
        Write-Log "Accessor non identificato dal Security log per $FilePath" "WARN"
    }

    $entry = [PSCustomObject]@{
        Id            = [System.Guid]::NewGuid().ToString()
        Timestamp     = (Get-Date).ToString("o")
        FilePath      = $FilePath
        EvType        = $EvType
        OldName       = $OldName
        EventFileHash = $eventFileHash   # hash stato file al momento evento
        Sent          = $false
        SentAt        = $null
        Accessor      = $accessor
        Snapshot      = $Snapshot
    }
    $pending += $entry
    try {
        $pending | ConvertTo-Json -Depth 8 | Set-Content $PendingFile -Encoding UTF8
        Write-Log "Evento accodato: $EvType $FilePath [hash:$($eventFileHash.Substring(0,[Math]::Min(16,$eventFileHash.Length)))...] (pending: $($pending.Count))"
    } catch {
        Write-Log "Impossibile scrivere rg_pending.json: $_" "WARN"
    }
}

function Send-PendingAlerts {
    param($Cfg)
    if (-not (Test-Path $PendingFile)) { return }

    $pending = $null
    try {
        $raw = Get-Content $PendingFile -Raw -ErrorAction Stop
        # ForEach garantisce sempre un array anche su PS5.1 con 1 solo elemento
        $pending = @($raw | ConvertFrom-Json | ForEach-Object { $_ })
    } catch { return }
    if (-not $pending -or $pending.Count -eq 0) { return }

    $unsent = @($pending | Where-Object { $_.Sent -ne $true })
    if ($unsent.Count -eq 0) {
        # Pulisci entry gia inviati da piu di 1 ora - cast difensivo
        $cutoffClean = (Get-Date).AddHours(-1)
        $keep = @($pending | Where-Object {
            if ($_.Sent -ne $true) { return $true }   # non-sent: tieni
            $sentAt = try { [datetime]($_.SentAt -as [string]) } catch { $null }
            return ($sentAt -ne $null -and $sentAt -gt $cutoffClean)
        })
        if ($keep.Count -ne $pending.Count) {
            try { $keep | ConvertTo-Json -Depth 8 | Set-Content $PendingFile -Encoding UTF8 } catch { }
        }
        return
    }

    # Costruisci un alert unico per tutti gli unsent
    $hostnameForAlert = try { $script:Hostname } catch { $env:COMPUTERNAME }
    $alertMsg  = "POSSIBILE RANSOMWARE rilevato su $hostnameForAlert`n"
    $alertMsg  = "🚨 $alertMsg"
    $alertMsg += "Ora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')`n"

    foreach ($entry in $unsent) {
        $evLabel = switch ($entry.EvType) {
            "MODIFICATO" { "⚠️ MODIFICATO" }
            "ELIMINATO"  { "❌ ELIMINATO"  }
            "RINOMINATO" { "🔄 RINOMINATO" }
            default      { "⚠️ $($entry.EvType)" }
        }
        $fname   = try { Split-Path ($entry.FilePath -as [string]) -Leaf } catch { $entry.FilePath }
        $fparent = try { Split-Path ($entry.FilePath -as [string]) -Parent } catch { "" }
        $tstamp  = try { [datetime]($entry.Timestamp -as [string]) | Get-Date -Format 'HH:mm:ss' } catch { "?" }
        $oldname = if ($entry.OldName) { [string]$entry.OldName } else { "" }

        $alertMsg += "`n$evLabel : $fname$oldname`n"
        $alertMsg += "Cartella : $fparent`n"
        $alertMsg += "Rilevato : $tstamp`n"

        # Hash stato file al momento del rilevamento (solo per MODIFICATO)
        $evHash = $entry.EventFileHash -as [string]
        if ($evHash -and $entry.EvType -eq "MODIFICATO" -and $evHash.Length -ge 16) {
            $alertMsg += "🔑 Hash    : $($evHash.Substring(0,16))...$($evHash.Substring($evHash.Length - 8))`n"
        }

        # Accessor da Security log (4663/4656)
        $acc = $entry.Accessor
        if ($acc -and ($acc.ProcessName -as [string])) {
            $procID = if ($acc.PID -gt 0) { "(PID:$($acc.PID))" } else { "" }
            $alertMsg += "🎯 Processo : $($acc.ProcessName) $procID`n"
            $alertMsg += "👤 Utente   : $($acc.User)`n"
        } else {
            $alertMsg += "🎯 Processo : non identificato dal Security log`n"
        }

        # Snapshot processi
        $snap = @($entry.Snapshot | ForEach-Object { $_ })
        if ($snap.Count -gt 0) {
            $alertMsg += "🔍 Processi al rilevamento (top $($snap.Count)):`n"
            foreach ($p in $snap) {
                $ppath = if ($p.Path -as [string]) { " [$($p.Path)]" } else { "" }
                $alertMsg += "  • $($p.Name) (PID:$($p.PID)) avviato $($p.StartTime)$ppath`n"
            }
        }
    }

    try {
        Send-AllAlerts -Cfg $Cfg `
            -Subject "🚨 [$hostnameForAlert] RansomwareGuard ALERT ($($unsent.Count) evento/i)" `
            -Body $alertMsg

        $now = (Get-Date).ToString("o")
        foreach ($entry in $pending) {
            if ($entry.Sent -ne $true) {
                $entry.Sent   = $true
                $entry.SentAt = $now
            }
        }
        $pending | ConvertTo-Json -Depth 8 | Set-Content $PendingFile -Encoding UTF8
        Write-Log "Inviati $($unsent.Count) alert pending, segnati come inviati."
    } catch {
        Write-Log "Invio alert pending fallito (ritentero al prossimo ciclo): $_" "WARN"
    }
}


# ---------------------------------------------------------------------------
# Snapshot COMPLETO di tutti i processi in esecuzione al momento del
# rilevamento. Nessun filtro: il ransomware puo girare come SYSTEM.
# Ordina per StartTime decrescente (piu recenti prima).
# ---------------------------------------------------------------------------
function Get-ProcessSnapshot {
    param([int]$TopN = 10)
    try {
        return @(
            Get-Process -ErrorAction SilentlyContinue |
            Sort-Object StartTime -Descending |
            Select-Object -First $TopN |
            ForEach-Object {
                $ppath = try { $_.Path } catch { "" }
                $ptime = try { $_.StartTime.ToString("HH:mm:ss") } catch { "?" }
                [PSCustomObject]@{
                    PID       = $_.Id
                    Name      = $_.Name
                    Path      = $ppath
                    StartTime = $ptime
                }
            }
        )
    } catch {
        return @()
    }
}

# ---------------------------------------------------------------------------
# Watcher continuo con FileSystemWatcher
#
# - Un FileSystemWatcher per ogni cartella monitorata.
# - Changed, Deleted, Renamed messi in coda e raccolti con Get-Event.
# - Filtro: solo i file nel DB hash (canary files).
# - Throttle: max 1 alert per file ogni 5 minuti.
# - Hash check periodico ogni CheckInterval minuti (belt-and-suspenders).
# - Carico a riposo: ~0% CPU, 0 scritture disco.
# - Compatibile: Windows 10, 11, Server 2016+
# ---------------------------------------------------------------------------
function Start-CanaryWatcher {
    param($Cfg)

    if (-not (Test-Path $HashDb)) {
        Write-Log "Hash database non trovato -- eseguire prima il setup." "ERROR"
        return
    }

    $paths_    = @(if ($Cfg -is [hashtable]) { $Cfg["MonitorPaths"] } else { $Cfg.MonitorPaths })
    $checkMins = if ($Cfg -is [hashtable]) { [int]$Cfg["CheckInterval"] } else { [int]$Cfg.CheckInterval }
    if ($checkMins -lt 5) { $checkMins = 15 }

    $baseline    = Get-Content $HashDb -Raw | ConvertFrom-Json
    $canaryNames = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($baseline.PSObject.Properties | ForEach-Object { Split-Path $_.Name -Leaf }),
        [System.StringComparer]::OrdinalIgnoreCase
    )

    Write-Log "=== Watcher avviato | cartelle: $($paths_.Count) | hash check ogni $checkMins min ==="
    Write-Log "Canary monitorati: $($canaryNames -join ", ")"

    # Riabilita le policy di auditing al riavvio del watcher.
    # Windows/Group Policy le azzera al boot -- questo garantisce che 4663/4656
    # siano sempre attivi anche dopo un riavvio del sistema.
    Write-Log "Verifica e riabilitazione audit policy (File System + Handle Manipulation)..."
    foreach ($guid in @("{0CCE921F-69AE-11D9-BED3-505054503030}",
                        "{0CCE9223-69AE-11D9-BED3-505054503030}")) {
        try {
            & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable 2>$null | Out-Null
            Write-Log "Audit policy OK: $guid"
        } catch {
            Write-Log "auditpol al watcher-start fallita per $guid : $_" "WARN"
        }
    }

    $watchers = [System.Collections.Generic.List[System.IO.FileSystemWatcher]]::new()
    $srcIds   = [System.Collections.Generic.List[string]]::new()
    $i = 0

    foreach ($dir in $paths_) {
        if (-not (Test-Path $dir -PathType Container)) {
            Write-Log "Cartella non trovata, saltata: $dir" "WARN"
            $i++; continue
        }
        try {
            $fsw = New-Object System.IO.FileSystemWatcher
            $fsw.Path                  = $dir
            $fsw.Filter                = "*.*"
            $fsw.NotifyFilter          = [System.IO.NotifyFilters]"FileName,LastWrite,Size"
            $fsw.IncludeSubdirectories = $false
            # Buffer 64KB (default 8KB): riduce il rischio di overflow silenziosi
            # sotto SYSTEM/Task dove gli eventi possono accumularsi prima di essere letti
            $fsw.InternalBufferSize    = 65536
            $fsw.EnableRaisingEvents   = $true

            $sid = "RG_$i"
            Register-ObjectEvent -InputObject $fsw -EventName Changed -SourceIdentifier "${sid}_C" | Out-Null
            Register-ObjectEvent -InputObject $fsw -EventName Deleted -SourceIdentifier "${sid}_D" | Out-Null
            Register-ObjectEvent -InputObject $fsw -EventName Renamed -SourceIdentifier "${sid}_R" | Out-Null
            # Error event: overflow o errore I/O del watcher -> loggato, il ciclo
            # principale se ne accorge al prossimo health-check (ogni 60s)
            Register-ObjectEvent -InputObject $fsw -EventName Error   -SourceIdentifier "${sid}_E" | Out-Null

            $watchers.Add($fsw)
            $srcIds.Add("${sid}_C")
            $srcIds.Add("${sid}_D")
            $srcIds.Add("${sid}_R")
            $srcIds.Add("${sid}_E")
            Write-Log "Watcher attivo: $dir (buffer 64KB)"
        } catch {
            Write-Log "Impossibile creare watcher per $dir : $_" "WARN"
        }
        $i++
    }

    if ($watchers.Count -eq 0) {
        Write-Log "Nessun watcher attivo -- uscita." "ERROR"
        return
    }

    $lastHashCheck = Get-Date

    try {
        while ($true) {

            # ── Elabora eventi FSW ───────────────────────────────────────────
            $evts = @(Get-Event -ErrorAction SilentlyContinue |
                      Where-Object { $_.SourceIdentifier -like "RG_*" })

            foreach ($evt in $evts) {
                Remove-Event -EventIdentifier $evt.EventIdentifier -ErrorAction SilentlyContinue

                # Gestisci Error event del FSW (buffer overflow o errore I/O)
                if ($evt.SourceIdentifier -like "*_E") {
                    $errMsg = try { $evt.SourceEventArgs.GetException().Message } catch { "sconosciuto" }
                    Write-Log "FSW ERROR event su $($evt.SourceIdentifier): $errMsg" "WARN"
                    continue
                }

                $evArgs   = $evt.SourceEventArgs
                $fullPath = $evArgs.FullPath
                $fileName = Split-Path $fullPath -Leaf

                if (-not $canaryNames.Contains($fileName)) { continue }

                $suffix  = $evt.SourceIdentifier[-1]
                $evType  = switch ($suffix) {
                    "C" { "MODIFICATO" }
                    "D" { "ELIMINATO"  }
                    "R" { "RINOMINATO" }
                    default { "MODIFICATO" }
                }

                # --- INIZIO MODIFICA: Verifica Hash in tempo reale per evitare falsi positivi ---
                if ($evType -eq "MODIFICATO") {
                    # L'operatore .psobject permette di accedere a proprietà con caratteri speciali (es. percorsi con spazi)
                    $expectedHash = $baseline.PSObject.Properties[$fullPath].Value
                    if ($expectedHash) {
                        $currentHash = Get-FileSHA256 -Path $fullPath
                        # Se l'hash è null (file bloccato/cancellato nel frattempo) o diverso, procedi. Se è uguale, ignora.
                        if ($currentHash -and $currentHash -eq $expectedHash) {
                            Write-Log "Evento di modifica per '$fileName' ma l'hash è invariato. Ignoro."
                            continue # Salta l'allarme, era un falso positivo
                        }
                    }
                }
                # --- FINE MODIFICA ---

                $oldName = try {
                    $on = $evArgs.OldFullPath
                    if ($on) { " (era: $(Split-Path $on -Leaf))" } else { "" }
                } catch { "" }

                Write-Log "EVENTO CANARY: $evType -> $fullPath$oldName" "WARN"

                # Snapshot IMMEDIATO di tutti i processi - nessun filtro
                $snap = @(Get-ProcessSnapshot -TopN 10)

                # Accoda in rg_pending.json (persistente: sopravvive a crash e
                # invii falliti; la coda viene svuotata nel ciclo successivo)
                Add-PendingAlert -FilePath $fullPath -EvType $evType `
                    -OldName $oldName -Snapshot $snap -Cfg $Cfg
            }

            # ── Svuota coda pending ──────────────────────────────────────────
            Send-PendingAlerts -Cfg $Cfg

            # ── Health check watcher (ogni 60s) ─────────────────────────────
            # Sotto SYSTEM/Task il FSW puo' smettere di notificare silenziosamente.
            # Verifica che EnableRaisingEvents sia ancora true; se no, lo riattiva.
            if (((Get-Date) - $lastHashCheck).TotalSeconds -ge 60) {
                foreach ($fsw in $watchers) {
                    if (-not $fsw.EnableRaisingEvents) {
                        Write-Log "FSW disattivato rilevato per '$($fsw.Path)' -- riattivazione..." "WARN"
                        try {
                            $fsw.EnableRaisingEvents = $true
                            Write-Log "FSW riattivato: $($fsw.Path)"
                        } catch {
                            Write-Log "Impossibile riattivare FSW per $($fsw.Path): $_" "WARN"
                        }
                    }
                }
            }

            # ── Hash check periodico ─────────────────────────────────────────
            if (((Get-Date) - $lastHashCheck).TotalMinutes -ge $checkMins) {
                Invoke-HashCheck -Cfg $Cfg
                $lastHashCheck = Get-Date
            }

            Start-Sleep -Seconds 3
        }
    } finally {
        foreach ($sid in $srcIds) {
            Unregister-Event -SourceIdentifier $sid -ErrorAction SilentlyContinue
            Remove-Event     -SourceIdentifier $sid -ErrorAction SilentlyContinue
        }
        foreach ($fsw in $watchers) {
            $fsw.EnableRaisingEvents = $false
            $fsw.Dispose()
        }
        Write-Log "=== Watcher fermato ==="
    }
}

# ---------------------------------------------------------------------------
# VERIFICA HASH (singola esecuzione / check periodico nel watcher)
# ---------------------------------------------------------------------------
function Invoke-HashCheck {
    param($Cfg)

    Write-Log "Avvio verifica canary files..."

    if (-not (Test-Path $HashDb)) {
        Write-Log "Hash database non trovato: $HashDb" "ERROR"
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
            Write-Log "FILE MANCANTE: $filePath" "WARN"
            continue
        }

        $currentHash = Get-FileSHA256 -Path $filePath
        if ($currentHash -ne $expectedHash) {
            $alerts += [PSCustomObject]@{
                File     = $filePath
                Expected = if ($expectedHash) { $expectedHash.Substring(0,16) + "..." } else { "N/A" }
                Current  = if ($currentHash) { $currentHash.Substring(0,16) + "..." } else { "N/A" }
            }
            Write-Log "MODIFICA RILEVATA: $filePath" "WARN"
            Write-Log "  Atteso : $expectedHash" "WARN"
            Write-Log "  Trovato: $currentHash" "WARN"
        }
    }

    if ($alerts.Count -gt 0 -or $missingFiles.Count -gt 0) {
        $hostnameForAlert = try { $script:Hostname } catch { $env:COMPUTERNAME }
        $alertMsg  = "🚨 POSSIBILE RANSOMWARE rilevato su $hostnameForAlert`n"
        $alertMsg += "Ora: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")`n"
        $pathList_ = if ($Cfg -is [hashtable]) { $Cfg["MonitorPaths"] } else { $Cfg.MonitorPaths }
        $alertMsg += "Path monitorati: $($pathList_ -join ", ")`n"
        $alertMsg += "(rilevamento da hash check periodico)`n"

        if ($alerts.Count -gt 0) {
            $alertMsg += "`n⚠️ File modificati ($($alerts.Count)):`n"
            foreach ($a in $alerts) {
                $alertMsg += "  • $(Split-Path $a.File -Leaf)`n"
            }
        }
        if ($missingFiles.Count -gt 0) {
            $alertMsg += "`n❌ File cancellati ($($missingFiles.Count)):`n"
            foreach ($f in $missingFiles) {
                $alertMsg += "  • $(Split-Path $f -Leaf)`n"
            }
        }

        Send-AllAlerts -Cfg $Cfg -Subject "🚨 [$hostnameForAlert] RansomwareGuard ALERT (hash check)" -Body $alertMsg
        Write-Log "ALERT inviato: $($alerts.Count) modifiche, $($missingFiles.Count) cancellazioni" "WARN"
    } else {
        $fileCount = @($baseline.PSObject.Properties).Count
        Write-Log "Verifica OK - nessuna modifica rilevata ($fileCount file)."
    }
}

# ---------------------------------------------------------------------------
# MENU GESTIONE (argomento --manage)
# ---------------------------------------------------------------------------
function Invoke-ManageMenu {
    param($Cfg)
    while ($true) {
        Write-Host "`n+=========================================+" -ForegroundColor Cyan
        Write-Host "||       RansomwareGuard - Gestione      ||" -ForegroundColor Cyan
        Write-Host "+=========================================+" -ForegroundColor Cyan
        Write-Host "  1. Ricalcola hash baseline (dopo update legittimi)"
        Write-Host "  2. Invia notifica di test"
        Write-Host "  3. Mostra configurazione corrente"
        Write-Host "  4. Riconfigura da zero"
        Write-Host "  5. Stato e riavvio Task pianificato"
        Write-Host "  6. Reimposta SACL audit sulle cartelle"
        Write-Host "  7. Esci"
        $choice = Read-Host "`nScelta"
        switch ($choice) {
            "1" {
                $hashes = @{}
                $paths_ = @(if ($Cfg -is [hashtable]) { $Cfg["MonitorPaths"] } else { $Cfg.MonitorPaths })
                foreach ($dir in $paths_) {
                    Write-Host "`n  -- $dir" -ForegroundColor Cyan
                    Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notmatch "^rg_" } | ForEach-Object {
                        $h = Get-FileSHA256 -Path $_.FullName
                        if ($h) {
                            $hashes[$_.FullName] = $h
                            Write-Host "  OK $($_.Name) [$($h.Substring(0,16))...]" -ForegroundColor Green
                        } else {
                            Write-Host "  !! $($_.Name) [hash fallito]" -ForegroundColor Red
                        }
                    }
                }
                $hashes | ConvertTo-Json | Set-Content -Path $HashDb -Encoding UTF8
                $pathCount_ = @($paths_).Count
                Write-Log "Hash baseline ricalcolati su $pathCount_ cartelle, $($hashes.Count) file."
                Write-Host "`nOK. Hash ricalcolati." -ForegroundColor Green
            }
            "2" {
                $hostnameForAlert = try { $script:Hostname } catch { $env:COMPUTERNAME }
                Send-AllAlerts -Cfg $Cfg -Subject "[$hostnameForAlert] RansomwareGuard Test" `
                    -Body "Notifica di test da $hostnameForAlert"
            }
            "3" { $Cfg | Format-List }
            "4" {
                $confirm = Read-Host "Sei sicuro di voler cancellare tutta la configurazione e ricominciare? (s/N)"
                if ($confirm -match "^[sS]$") {
                    Remove-Item $ConfigFile -Force -ErrorAction SilentlyContinue
                    Remove-Item $HashDb     -Force -ErrorAction SilentlyContinue
                    Invoke-FirstSetup
                }
                return # Esce dal menu di gestione
            }
            "5" {
                $taskName = "RansomwareGuard_Monitor"
                try {
                    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($task) {
                        $info  = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                        $color = if ($task.State -eq "Running") { "Green" } else { "Yellow" }
                        Write-Host "  Stato        : $($task.State)" -ForegroundColor $color
                        if ($info) {
                            Write-Host "  Ultimo run   : $($info.LastRunTime)"
                            Write-Host "  Ultimo result: $($info.LastTaskResult)"
                        }
                        $restart = Read-Host "`n  Vuoi riavviare il task? (s/N)"
                        if ($restart -match "^[sS]$") {
                            Stop-ScheduledTask  -TaskName $taskName -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2
                            Start-ScheduledTask -TaskName $taskName
                            Write-Host "  OK Task riavviato." -ForegroundColor Green
                            Write-Log "Task $taskName riavviato manualmente."
                        }
                    } else {
                        Write-Host "  !! Task non trovato. Usa opzione 4 per riconfigurare." -ForegroundColor Red
                    }
                } catch {
                    Write-Log "Errore verifica task: $_" "WARN"
                }
            }
            "6" {
                $paths_ = @(if ($Cfg -is [hashtable]) { $Cfg["MonitorPaths"] } else { $Cfg.MonitorPaths })
                $canaryFiles = @()
                if (Test-Path $HashDb) {
                    $bl = Get-Content $HashDb -Raw | ConvertFrom-Json
                    $canaryFiles = @($bl.PSObject.Properties | ForEach-Object { $_.Name })
                }
                Write-Host "`n  Reimpostazione SACL + Handle Manipulation..." -ForegroundColor Cyan
                Enable-FolderAuditing -Paths $paths_ -CanaryFiles $canaryFiles
                Write-Host "  OK fatto." -ForegroundColor Green
            }
            "7"     { Write-Host "Uscita."; return }
            default { Write-Host "Scelta non valida." -ForegroundColor Yellow }
        }
        Read-Host "Premi INVIO per tornare al menu..."
    }
}

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
try {
    $script:Hostname = [System.Net.Dns]::GetHostName()
} catch {
    $script:Hostname = $env:COMPUTERNAME
}
Write-Log "=== RansomwareGuard avviato (utente: $env:USERNAME, host: $script:Hostname) ==="

if ($args -contains "--manage") {
    if (Test-Path $ConfigFile) {
        $cfgRaw = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        $cfg = @{}
        $cfgRaw.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
        Invoke-ManageMenu -Cfg $cfg
    } else {
        Write-Host "Nessuna configurazione trovata. Avvia lo script senza argomenti per il setup." -ForegroundColor Yellow
    }
    exit 0
}

if ($args -contains "--watch") {
    if (-not (Test-Path $ConfigFile)) {
        Write-Log "Nessuna configurazione trovata. Avviare lo script senza argomenti per il setup." "ERROR"
        exit 1
    }
    $cfgRaw = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $cfg = @{}
    $cfgRaw.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
    Start-CanaryWatcher -Cfg $cfg
    exit 0
}

if (-not (Test-Path $ConfigFile)) {
    Write-Log "Primo avvio rilevato - avvio configurazione interattiva."
    Invoke-FirstSetup
    exit 0
}

# Senza argomenti con config esistente: singolo hash check manuale
$cfgRaw = Get-Content $ConfigFile -Raw | ConvertFrom-Json
$cfg = @{}
$cfgRaw.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }

Invoke-HashCheck -Cfg $cfg

Write-Log "=== RansomwareGuard terminato ==="

