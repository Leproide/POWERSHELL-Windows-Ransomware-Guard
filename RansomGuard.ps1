#Requires -Version 5.1
<#

https://github.com/Leproide/POWERSHELL-Windows-Ransomware-Guard

.SYNOPSIS
    RansomwareGuard - Honeypot file monitor con notifiche multi-canale
.DESCRIPTION
    Crea file "esca" (canary files) in cartelle monitorate.
    Calcola SHA256 ad ogni avvio e notifica via Telegram, Gotify e MSG
    se rileva modifiche (potenziale cifratura da ransomware).
.NOTES
    Primo avvio: configurazione interattiva -> salva config.json
    Avvii successivi: solo verifica hash
#>

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# PERCORSI
# $PSScriptRoot e $PSCommandPath sono variabili automatiche sempre definite
# (stringa vuota se non applicabile) — sicure con StrictMode.
# $MyInvocation.MyCommand.Path viene EVITATO: sotto SYSTEM/Task Scheduler
# la proprieta' .Path puo' essere assente e StrictMode lancia eccezione.
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
$ConfigFile  = Join-Path $ScriptDir "rg_config.json"
$HashDb      = Join-Path $ScriptDir "rg_hashes.json"
$LogFile     = Join-Path $ScriptDir "rg_log.txt"

# ---------------------------------------------------------------------------
# NOMI VEROSIMILI PER I FILE ESCA
# Mescolano estensioni Office, testo, backup — appetibili per un ransomware
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
        # ConvertTo-Json + encoding esplicito UTF-8 per preservare le emoji
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
    # MSG * funziona in sessione interattiva; come fallback usiamo
    # un toast via BurntToast (se presente) o una finestra WScript
    try {
        # Prova MSG * (funziona su Pro/Server con sessioni RDP/console attive)
        $msgExe = "$env:SystemRoot\System32\msg.exe"
        if (Test-Path $msgExe) {
            & $msgExe * /TIME:60 $Message 2>$null
        }
    } catch { }

    # Fallback 1: Toast Notification nativo Windows 10/11 (non richiede moduli extra)
    try {
        $xml = @"
<?xml version="1.0"?>
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>⚠️ RansomwareGuard ALERT</text>
      <text>$Message</text>
    </binding>
  </visual>
</toast>
"@
        [Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom,ContentType=WindowsRuntime] | Out-Null
        $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xmlDoc.LoadXml($xml)
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

    # Legge i flag; se assenti nel config (retrocompatibilità) assume true
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
    Write-Host "`n╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║        RansomwareGuard - Setup iniziale      ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    # --- Percorsi da monitorare (uno o più) ---
    $monitorPaths = [System.Collections.Generic.List[string]]::new()
    Write-Host "`n[Cartelle da monitorare]" -ForegroundColor Cyan
    Write-Host "  Inserisci i percorsi uno alla volta." -ForegroundColor Gray
    Write-Host "  Premi INVIO senza scrivere nulla per terminare (minimo 1)." -ForegroundColor Gray

    while ($true) {
        $idx = $monitorPaths.Count + 1
        $prompt = if ($monitorPaths.Count -eq 0) { "  Percorso #$idx (obbligatorio)" } `
                  else                            { "  Percorso #$idx (o INVIO per finire)" }
        $input_ = (Read-Host $prompt).Trim()

        # INVIO vuoto -> fine inserimento (solo se abbiamo almeno 1 path)
        if ($input_ -eq '') {
            if ($monitorPaths.Count -eq 0) {
                Write-Host "  ✗ Devi inserire almeno un percorso." -ForegroundColor Red
                continue
            }
            break
        }

        if (-not (Test-Path $input_ -PathType Container)) {
            $create = Read-Host "  ✗ Percorso non trovato. Creare la cartella? (s/N)"
            if ($create -match '^[sS]$') {
                try {
                    New-Item -ItemType Directory -Path $input_ -Force | Out-Null
                    Write-Host "  ✓ Cartella creata." -ForegroundColor Green
                } catch {
                    Write-Host "  ✗ Impossibile creare la cartella: $_" -ForegroundColor Red
                    continue
                }
            } else {
                continue
            }
        }

        if ($monitorPaths.Contains($input_)) {
            Write-Host "  ⚠ Percorso già inserito, ignorato." -ForegroundColor Yellow
            continue
        }

        $monitorPaths.Add($input_)
        Write-Host "  ✓ Aggiunto: $input_" -ForegroundColor Green
    }

    # Riepilogo e conferma
    Write-Host "`n  ┌─ Riepilogo cartelle selezionate ─────────────────" -ForegroundColor Cyan
    for ($i = 0; $i -lt $monitorPaths.Count; $i++) {
        Write-Host "  │  $($i+1). $($monitorPaths[$i])" -ForegroundColor White
    }
    Write-Host "  └────────────────────────────────────────────────" -ForegroundColor Cyan
    $confirm = Read-Host "`n  Confermi questi $($monitorPaths.Count) percorsi? (S/n)"
    if ($confirm -match '^[nN]$') {
        Write-Host "  Configurazione annullata. Riavvia lo script per ricominciare." -ForegroundColor Yellow
        exit 0
    }

    # --- Telegram ---
    Write-Host "`n[Telegram Bot]"
    $tgToken  = Read-Host "  Token bot Telegram (es. 123456:ABC...)"
    $tgChatId = Read-Host "  Chat ID destinatario (es. -100123456789)"

    # --- Gotify ---
    Write-Host "`n[Gotify]"
    $gotifyHost  = Read-Host "  Host Gotify (es. https://push.example.com)"
    $gotifyPort  = Read-Host "  Porta Gotify (lascia vuoto per default 80/443)"
    $gotifyToken = Read-Host "  App Token Gotify"
    # Costruisce URL: aggiunge la porta solo se specificata
    $gotifyUrl = if ($gotifyPort -match '^\d+$') {
        "$($gotifyHost.TrimEnd('/'))`:$gotifyPort"
    } else {
        $gotifyHost.TrimEnd('/')
    }

    # --- Abilitazione notifiche ---
    Write-Host "`n[Notifiche - abilita/disabilita]"
    $enTelegram = Read-Host "  Abilita Telegram? (S/n)"
    $enGotify   = Read-Host "  Abilita Gotify?   (S/n)"
    $enPopup    = Read-Host "  Abilita Popup/MSG Windows? (S/n)"

    # --- Intervallo task (minuti) ---
    Write-Host "`n[Scheduler]"
    $interval = Read-Host "  Intervallo di controllo in minuti per il Task pianificato (default: 15)"
    if (-not $interval -or $interval -notmatch '^\d+$') { $interval = "15" }

    $cfg = @{
        MonitorPaths     = @($monitorPaths)   # array di percorsi
        TelegramToken    = $tgToken
        TelegramChatId   = $tgChatId
        GotifyUrl        = $gotifyUrl
        GotifyToken      = $gotifyToken
        CheckInterval    = [int]$interval
        SetupDone        = $true
        EnableTelegram   = ($enTelegram -notmatch '^[nN]$')
        EnableGotify     = ($enGotify   -notmatch '^[nN]$')
        EnablePopup      = ($enPopup    -notmatch '^[nN]$')
    }

    # --- Per ogni cartella: usa file esistenti oppure crea file esca ---
    $hashes = @{}
    $totalErrors = 0

    foreach ($canaryDir in $monitorPaths) {
        Write-Host "`n  ── $canaryDir ──" -ForegroundColor Cyan

        $existingFiles = @(Get-ChildItem -Path $canaryDir -File -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -notmatch '^rg_' })

        if ($existingFiles.Count -gt 0) {
            Write-Host "  Trovati $($existingFiles.Count) file esistenti — calcolo hash baseline..." -ForegroundColor Gray
            foreach ($f in $existingFiles) {
                $hash = Get-FileSHA256 -Path $f.FullName
                if ($hash) {
                    $hashes[$f.FullName] = $hash
                    Write-Host "    ✓ $($f.Name)  [$($hash.Substring(0,16))...]" -ForegroundColor Green
                } else {
                    Write-Host "    ✗ $($f.Name)  [hash fallito]" -ForegroundColor Red
                    $totalErrors++
                }
            }
        } else {
            Write-Host "  Cartella vuota — creazione file esca..." -ForegroundColor Gray
            foreach ($name in $CanaryNames) {
                $fullPath = Join-Path $canaryDir $name
                try {
                    $fileContent = New-CanaryContent -FileName $name
                    if ($fileContent -eq '__BINARY_OLE2__') {
                        # File binario OLE2 (header Word/tmp) — scritto come byte[]
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
                            Write-Host "    ✓ $name  [$($hash.Substring(0,16))...]" -ForegroundColor Green
                        } else {
                            Write-Host "    ✗ $name  [hash fallito]" -ForegroundColor Red
                            $totalErrors++
                        }
                    } else {
                        Write-Host "    ✗ $name  [NON creato su disco!]" -ForegroundColor Red
                        Write-Log "ERRORE: file non trovato dopo scrittura: $fullPath" "ERROR"
                        $totalErrors++
                    }
                } catch {
                    Write-Host "    ✗ $name  [errore: $_]" -ForegroundColor Red
                    Write-Log "ERRORE creazione '$name' in $canaryDir : $_" "ERROR"
                    $totalErrors++
                }
            }
        }
    }

    if ($totalErrors -gt 0) {
        Write-Host "`n  ⚠️  $totalErrors errori durante la preparazione file." -ForegroundColor Yellow
    } else {
        Write-Host "`n  ✓ Tutti i file pronti su $($monitorPaths.Count) cartelle ($($hashes.Count) hash totali)." -ForegroundColor Green
    }

    # --- Salva config ---
    $cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-Log "Configurazione salvata in $ConfigFile"

    # --- Salva hash baseline ---
    $hashes | ConvertTo-Json | Set-Content -Path $HashDb -Encoding UTF8
    Write-Log "Hash baseline salvati: $($hashes.Count) file"

    # --- Abilita audit SACL sulle cartelle monitorate ---
    Write-Host "`n[Audit SACL]" -ForegroundColor Cyan
    Enable-FolderAuditing -Paths @($monitorPaths)

    # --- Registra Task pianificato ---
    Register-RGScheduledTask -Cfg $cfg

    Write-Host "`n  ✅ Setup completato! Il task verrà eseguito ogni $interval minuti.`n" -ForegroundColor Green

    # Test notifiche
    $test = Read-Host "Vuoi inviare una notifica di test? (s/N)"
    if ($test -match '^[sS]$') {
        Send-AllAlerts -Cfg $cfg `
            -Subject "[$script:Hostname] RansomwareGuard - Setup OK" `
            -Body "Setup completato su $script:Hostname. Cartelle monitorate: $($monitorPaths -join ', ')"
    }
}

# ---------------------------------------------------------------------------
# Genera contenuto verosimile per ogni estensione.
# Nessun riferimento a script, monitoraggio o sicurezza nel contenuto.
# ---------------------------------------------------------------------------
function New-CanaryContent {
    param([string]$FileName)
    $ext  = [System.IO.Path]::GetExtension($FileName).ToLower()
    $base = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $rng  = [System.Random]::new()

    # Helper: stringa alfanumerica casuale
    function Get-RandStr { param([int]$Len)
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        -join (1..$Len | ForEach-Object { $chars[$rng.Next($chars.Length)] })
    }
    # Helper: numero random in range
    function Get-RandInt { param([int]$Min,[int]$Max) $rng.Next($Min,$Max) }

    $firstNames = @('Marco','Laura','Giovanni','Alessia','Roberto','Francesca','Luca','Sara','Andrea','Elena')
    $lastNames  = @('Rossi','Ferrari','Bianchi','Romano','Conti','Ricci','Marino','Greco','Bruno','Gallo')
    $depts      = @('Amministrazione','Commerciale','IT','Risorse Umane','Logistica','Marketing','Acquisti')
    $year       = (Get-Date).Year
    $month      = (Get-Date).ToString('MM')
    $day        = (Get-Date).ToString('dd')
    $host_      = $script:Hostname
    $user_      = $env:USERNAME

    switch ($ext) {

        ".txt" {
            # Aspetto: note interne o elenco credenziali rete
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
            # desktop.ini autentico di Windows
            return "[.ShellClassInfo]`r`nIconResource=C:\Windows\System32\imageres.dll,$(Get-RandInt 1 200)`r`nIconIndex=$(Get-RandInt 0 50)`r`n[ViewState]`r`nMode=`r`nVid={$(([System.Guid]::NewGuid()).ToString().ToUpper())}`r`nFolderType=Documents"
        }

        ".xml" {
            $entries = @()
            1..(Get-RandInt 4 9) | ForEach-Object {
                $fn = $firstNames[$rng.Next($firstNames.Length)]
                $ln = $lastNames[$rng.Next($lastNames.Length)]
                $id = Get-RandInt 1000 9999
                $sal= Get-RandInt 28000 95000
                $entries += "  <dipendente id=`"$id`"><nome>$fn</nome><cognome>$ln</cognome><reparto>$($depts[$rng.Next($depts.Length)])</reparto><ral>$sal</ral></dipendente>"
            }
            return "<?xml version=`"1.0`" encoding=`"utf-8`"?>`r`n<organico anno=`"$year`" societa=`"$(Get-RandStr 6) S.r.l.`" esportato=`"$day/$month/$year`">`r`n$($entries -join "`r`n")`r`n</organico>"
        }

        ".sql" {
            $table  = @('clienti','ordini','fatture','contratti','prodotti','dipendenti')[$rng.Next(6)]
            $rows   = @()
            1..(Get-RandInt 5 12) | ForEach-Object {
                $fn  = $firstNames[$rng.Next($firstNames.Length)]
                $ln  = $lastNames[$rng.Next($lastNames.Length)]
                $id  = Get-RandInt 1 9999
                $val = Get-RandInt 100 50000
                $rows += "INSERT INTO $table VALUES ($id, '$fn', '$ln', $val, '$year-$month-$day');"
            }
            return "-- $table export $day/$month/$year`r`n-- Host: $host_`r`nUSE [$(Get-RandStr 8)_db];`r`nGO`r`n`r`n$($rows -join "`r`n")"
        }

        ".xlsx" {
            # File XLSX reale minimo (ZIP con XML interno) — abbastanza da avere un hash stabile
            # Usiamo un CSV con intestazioni finanziarie: se aperto Excel lo mostra come foglio
            $headers = "Mese;Categoria;Importo;Centro di costo;Note"
            $cats    = @('Personale','Affitti','Utenze','Fornitori','Rimborsi','Ammortamenti')
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
            # RTF minimo con aspetto di verbale/contratto
            $fn1 = $firstNames[$rng.Next($firstNames.Length)]; $ln1 = $lastNames[$rng.Next($lastNames.Length)]
            $fn2 = $firstNames[$rng.Next($firstNames.Length)]; $ln2 = $lastNames[$rng.Next($lastNames.Length)]
            $art = Get-RandInt 3 12; $pag = Get-RandInt 2 8
            return "{\rtf1\ansi\deff0{\fonttbl{\f0 Times New Roman;}}\f0\fs24 " +
                   "Contratto di fornitura servizi - $day/$month/$year\par\par " +
                   "Tra $fn1 $ln1 (di seguito Committente) e $fn2 $ln2 (di seguito Fornitore).\par\par " +
                   "Art. 1 - Oggetto del contratto\par Il Fornitore si impegna a erogare i servizi descritti nell allegato A.\par\par " +
                   "Art. 2 - Durata\par Il presente contratto ha durata di $(Get-RandInt 12 36) mesi dalla data di sottoscrizione.\par\par " +
                   "Totale pagine: $pag - Articoli: $art\par}"
        }

        ".qbb" {
            # QuickBooks backup header (testo + rumore binario simulato)
            $magic  = "QBWIN`t$(Get-RandStr 4)`tBackup`t$year$month$day`tver=R$(Get-RandInt 10 30).$(Get-RandInt 0 9)"
            $noise  = -join (1..200 | ForEach-Object { [char]($rng.Next(32,126)) })
            return "$magic`r`n$noise"
        }

        ".tmp" {
            # Segnala che questo tipo va scritto come byte[] — gestito nel chiamante
            return "__BINARY_OLE2__"
        }

        default {
            # CSV generico con dati contabili
            $rows = @("ID;Descrizione;Quantita;Prezzo;Totale;Data")
            1..(Get-RandInt 6 15) | ForEach-Object {
                $id  = Get-RandInt 1000 9999
                $qty = Get-RandInt 1 100
                $prc = "{0:N2}" -f ($rng.NextDouble() * 500 + 10)
                $tot = "{0:N2}" -f ($qty * [double]$prc.Replace(',','.'))
                $rows += "$id;$(Get-RandStr 12);$qty;$prc;$tot;$day/$month/$year"
            }
            return $rows -join "`r`n"
        }
    }
}

# ---------------------------------------------------------------------------
# Registra Task pianificato Windows
# ---------------------------------------------------------------------------
function Register-RGScheduledTask {
    param($Cfg)
    $taskName = "RansomwareGuard_Monitor"
    $psExe    = "powershell.exe"

    # Risolve il percorso REALE dello script in esecuzione.
    # $PSCommandPath e' la variabile piu' affidabile in tutti i contesti PS3+.
    # $ScriptDir e' gia' risolto all'avvio e usato come fallback.
    $scriptPath = if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
        $PSCommandPath
    } elseif ($ScriptDir) {
        # Cerca uno .ps1 nella stessa cartella del config (unico file ps1 atteso)
        $found = Get-ChildItem -Path $ScriptDir -Filter "*.ps1" -File -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if ($found) { $found.FullName } else { $null }
    } else {
        $null
    }

    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        Write-Log "ERRORE: impossibile determinare il percorso dello script per il Task. Path rilevato: '$scriptPath'" "ERROR"
        Write-Host "  ✗ Task NON registrato: percorso script non trovato." -ForegroundColor Red
        Write-Host "    Registra manualmente il task puntando a questo script." -ForegroundColor Yellow
        return
    }

    Write-Log "Script per Task pianificato: $scriptPath"

    $action    = New-ScheduledTaskAction -Execute $psExe `
                     -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    # Accesso a CheckInterval sicuro con StrictMode: ContainsKey/Match prima di accedere
    $checkMins = 15
    if ($Cfg -is [hashtable] -and $Cfg.ContainsKey('CheckInterval') -and $null -ne $Cfg['CheckInterval']) {
        $checkMins = [int]$Cfg['CheckInterval']
    } elseif ($Cfg.PSObject.Properties.Match('CheckInterval').Count -gt 0) {
        $val = $Cfg.PSObject.Properties['CheckInterval'].Value
        if ($null -ne $val) { $checkMins = [int]$val }
    }
    Write-Log "CheckInterval letto: $checkMins min (tipo: $($Cfg.GetType().Name))"
    $trigger   = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes $checkMins) `
                     -Once -At (Get-Date)
    # Tutti i settings avanzati (batteria, StopExisting, no time limit) via COM
    $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $null = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal |
                Register-ScheduledTask -TaskName $taskName -Force

        # Imposta via COM le opzioni non disponibili nel cmdlet PS:
        #   MultipleInstances = 3 (StopExisting)
        #   DisallowStartIfOnBatteries = false
        #   StopIfGoingOnBatteries = false
        #   ExecutionTimeLimit = PT0S (nessun limite)
        $svc  = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $fold = $svc.GetFolder("\")
        $t    = $fold.GetTask($taskName)
        $def  = $t.Definition
        $def.Settings.MultipleInstances        = 3      # StopExisting
        $def.Settings.DisallowStartIfOnBatteries = $false
        $def.Settings.StopIfGoingOnBatteries     = $false
        $def.Settings.ExecutionTimeLimit         = "PT0S" # nessun limite
        $fold.RegisterTaskDefinition($taskName, $def, 4, $null, $null, 5) | Out-Null

        Write-Log "Task '$taskName' registrato -> ogni $checkMins min, SYSTEM, script: $scriptPath"
        Write-Host "  ✓ Task registrato: $taskName  (script: $scriptPath)" -ForegroundColor Green
    } catch {
        Write-Log "Impossibile registrare il task (richiede privilegi admin): $_" "WARN"
        Write-Host "  ✗ Task NON registrato (servono privilegi amministratore): $_" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Abilita auditing SACL sulle cartelle monitorate
# Richiede: auditpol (audit object access) + Set-Acl con audit rule
# ---------------------------------------------------------------------------
function Enable-FolderAuditing {
    param([string[]]$Paths)

    # 1. Abilita "File System" audit nel sottosistema Windows (solo successi)
    try {
        $null = & auditpol.exe /set /subcategory:"File System" /success:enable 2>&1
        Write-Log "Audit 'File System' abilitato via auditpol."
    } catch {
        Write-Log "Impossibile impostare auditpol: $_" "WARN"
    }

    # 2. Imposta SACL su ogni cartella monitorata
    foreach ($folder in $Paths) {
        if (-not (Test-Path $folder)) { continue }
        try {
            $acl = Get-Acl -Path $folder -Audit
            # Audit su Everyone per Write, Delete, DeleteSubdirectoriesAndFiles — solo Success
            $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                [System.Security.AccessControl.FileSystemRights]"Write,Delete,DeleteSubdirectoriesAndFiles",
                [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                [System.Security.AccessControl.PropagationFlags]"None",
                [System.Security.AccessControl.AuditFlags]"Success"
            )
            $acl.AddAuditRule($auditRule)
            Set-Acl -Path $folder -AclObject $acl
            Write-Log "SACL audit impostata su: $folder"
            Write-Host "  ✓ Audit SACL impostata: $folder" -ForegroundColor Green
        } catch {
            Write-Log "Impossibile impostare SACL su '$folder': $_" "WARN"
            Write-Host "  ✗ SACL fallita su $folder : $_" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# Interroga il Security Event Log per trovare chi ha modificato un file
# Event ID 4663 = tentativo accesso oggetto (scrittura/cancellazione)
# ---------------------------------------------------------------------------
function Get-FileModifierInfo {
    param([string]$FilePath, [int]$LookbackMinutes = 60)

    $results = @()
    try {
        $since = (Get-Date).AddMinutes(-$LookbackMinutes)
        $fileName = Split-Path $FilePath -Leaf

        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4663
            StartTime = $since
        } -ErrorAction SilentlyContinue

        foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()
            $ns  = @{ e = 'http://schemas.microsoft.com/win/2004/08/events/event' }
            $getData = { param($name)
                ($xml.SelectNodes("//e:Data[@Name='$name']", 
                    ([System.Xml.XmlNamespaceManager]([System.Xml.XmlDocument]::new()).let{
                        $_.SelectSingleNode('/') | Out-Null; 
                        $nsmgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                        $nsmgr.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
                        return $nsmgr
                    }))).InnerText
            }

            # Parsing diretto senza namespace per semplicità
            $objName    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectName'   }).'#text'
            $procName   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessName'  }).'#text'
            $subjectUser= ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            $subjectDom = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'
            $pid_raw    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId'    }).'#text'
            # Il log registra il PID in esadecimale (es. 0xab98) — converti in decimale
            $pid_       = if ($pid_raw -match '^0x[0-9a-fA-F]+$') { [Convert]::ToInt64($pid_raw, 16).ToString() } else { $pid_raw }
            $accesses   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'AccessList'   }).'#text'

            if ($objName -and $objName -like "*$fileName*") {
                $results += [PSCustomObject]@{
                    Time      = $ev.TimeCreated
                    File      = $objName
                    Process   = if ($procName)    { Split-Path $procName -Leaf } else { '?' }
                    ProcessPath = $procName
                    PID       = $pid_
                    User      = if ($subjectDom -and $subjectUser) { "$subjectDom\$subjectUser" } else { $subjectUser }
                    Access    = $accesses -replace '\s+', ' '
                }
            }
        }
    } catch {
        Write-Log "Errore lettura Security log per '$FilePath': $_" "WARN"
    }

    # Restituisce gli eventi più recenti deduplicati per processo
    return @($results | Sort-Object Time -Descending | Select-Object -First 5)
}

# ---------------------------------------------------------------------------
# VERIFICA HASH (esecuzione normale)
# ---------------------------------------------------------------------------
function Invoke-HashCheck {
    param($Cfg)

    Write-Log "Avvio verifica canary files..."

    if (-not (Test-Path $HashDb)) {
        Write-Log "Hash database non trovato: $HashDb" "ERROR"
        return
    }

    $baseline  = Get-Content $HashDb -Raw | ConvertFrom-Json
    $alerts    = @()
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
                Expected = $expectedHash.Substring(0,16) + "..."
                Current  = $currentHash.Substring(0,16) + "..."
            }
            Write-Log "MODIFICA RILEVATA: $filePath" "WARN"
            Write-Log "  Atteso : $expectedHash" "WARN"
            Write-Log "  Trovato: $currentHash" "WARN"
        }
    }

    if ($alerts.Count -gt 0 -or $missingFiles.Count -gt 0) {
        $alertMsg = "🚨 POSSIBILE RANSOMWARE rilevato su $script:Hostname`n"
        $alertMsg += "Ora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')`n"
        $pathList_ = if ($Cfg -is [hashtable]) { $Cfg['MonitorPaths'] } else { $Cfg.MonitorPaths }
        $alertMsg += "Path monitorati: $($pathList_ -join ', ')`n"

        if ($alerts.Count -gt 0) {
            $alertMsg += "`n⚠️ File modificati ($($alerts.Count)):`n"
            foreach ($a in $alerts) {
                $modInfo = Get-FileModifierInfo -FilePath $a.File -LookbackMinutes 120
            $who = if (@($modInfo).Count -gt 0) {
                $m = $modInfo[0]
                " [Processo: $($m.Process) PID:$($m.PID) Utente: $($m.User)]"
            } else { " [processo non rilevato nel log]" }
                $alertMsg += "  • $(Split-Path $a.File -Leaf)$who`n"
            }
        }
        if ($missingFiles.Count -gt 0) {
            $alertMsg += "`n❌ File cancellati ($($missingFiles.Count)):`n"
            foreach ($f in $missingFiles) {
                $delInfo = Get-FileModifierInfo -FilePath $f -LookbackMinutes 120
            $who = if (@($delInfo).Count -gt 0) {
                $m = $delInfo[0]
                " [Processo: $($m.Process) PID:$($m.PID) Utente: $($m.User)]"
            } else { " [processo non rilevato nel log]" }
                $alertMsg += "  • $(Split-Path $f -Leaf)$who`n"
            }
        }

        Send-AllAlerts -Cfg $Cfg -Subject "🚨 [$script:Hostname] RansomwareGuard ALERT" -Body $alertMsg
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
    Write-Host "`n╔══════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   RansomwareGuard - Gestione     ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  1. Ricalcola hash baseline (dopo update legittimi)"
    Write-Host "  2. Invia notifica di test"
    Write-Host "  3. Mostra configurazione corrente"
    Write-Host "  4. Riconfigura da zero"
    Write-Host "  5. Rimposta audit SACL sulle cartelle"
    Write-Host "  6. Esci"
    $choice = Read-Host "`nScelta"
    switch ($choice) {
        "1" {
            $hashes = @{}
            $paths_ = @(if ($Cfg -is [hashtable]) { $Cfg['MonitorPaths'] } else { $Cfg.MonitorPaths })
            foreach ($dir in $paths_) {
                Write-Host "`n  ── $dir" -ForegroundColor Cyan
                Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '^rg_' } | ForEach-Object {
                    $h = Get-FileSHA256 -Path $_.FullName
                    if ($h) {
                        $hashes[$_.FullName] = $h
                        Write-Host "  ✓ $($_.Name) [$($h.Substring(0,16))...]" -ForegroundColor Green
                    }
                }
            }
            $hashes | ConvertTo-Json | Set-Content -Path $HashDb -Encoding UTF8
            $pathCount_ = @($paths_).Count
            Write-Log "Hash baseline ricalcolati su $pathCount_ cartelle, $($hashes.Count) file."
        }
        "2" {
            Send-AllAlerts -Cfg $Cfg -Subject "[$script:Hostname] RansomwareGuard Test" `
                -Body "Notifica di test da $script:Hostname"
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
            Write-Host "`n  Reimpostazione SACL audit..." -ForegroundColor Cyan
            Enable-FolderAuditing -Paths $paths_
        }
        "6"     { Write-Host "Uscita." }
        default { Write-Host "Uscita." }
    }
}

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
# Hostname reale di rete (eventualmente FQDN), più affidabile di $env:COMPUTERNAME
$script:Hostname = [System.Net.Dns]::GetHostName()
Write-Log "=== RansomwareGuard avviato (utente: $env:USERNAME, host: $script:Hostname) ==="

# Argomento --manage per menu gestione
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

# Setup iniziale se non esiste il config
if (-not (Test-Path $ConfigFile)) {
    Write-Log "Primo avvio rilevato - avvio configurazione interattiva."
    Invoke-FirstSetup
    exit 0
}

# Avvio normale: carica config e verifica hash
$cfgRaw = Get-Content $ConfigFile -Raw | ConvertFrom-Json
$cfg = @{}
$cfgRaw.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }

Invoke-HashCheck -Cfg $cfg


Write-Log "=== RansomwareGuard terminato ==="
