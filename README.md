# 🛡️ RansomwareGuard

Strumento di monitoraggio basato su **canary file** per il rilevamento precoce di ransomware su sistemi Windows.  
Crea file esca in cartelle sensibili, ne calcola l'hash SHA-256 come baseline e notifica immediatamente via Telegram, Gotify e popup Windows se vengono modificati o cancellati.

---

## Come funziona

Il principio è semplice: un ransomware, prima di cifrare una cartella, **tocca tutti i file che trova**. RansomwareGuard piazza dei file esca dall'aspetto innocuo (documenti Office, SQL, TXT, backup) nelle cartelle che vuoi proteggere. Ad ogni esecuzione ricalcola gli hash SHA-256 e se anche uno solo è cambiato scatta l'allarme.

```
Avvio script
    │
    ├─ Prima volta → Setup interattivo
    │       ├─ Scegli una o più cartelle da monitorare
    │       ├─ Configura Telegram / Gotify / popup
    │       ├─ Se le cartelle hanno già file → hash su quelli
    │       ├─ Se vuote → crea file esca verosimili
    │       ├─ Imposta audit SACL per tracciare i processi
    │       └─ Registra Task pianificato (SYSTEM)
    │
    └─ Avvii successivi (dal task) → Verifica hash
            ├─ Nessuna modifica → log OK
            └─ Modifica/cancellazione → Cerca processo colpevole
                                      → Notifica Telegram + Gotify + Popup
```

---

## Requisiti

| Requisito | Dettaglio |
|---|---|
| Windows | 10 / 11 / Server 2016+ |
| PowerShell | 5.1 o superiore |
| Privilegi | **Amministratore** (per Task Scheduler, SACL e Security Log) |
| Rete | Accesso a `api.telegram.org` e/o al server Gotify |

---

## Installazione e primo avvio

1. Scarica `RansomGuard.ps1` e copialo in una cartella dedicata (es. `C:\RansomwareGuard\`)

2. Apri PowerShell **come Amministratore** e sblocca l'esecuzione se necessario:

```powershell
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
```

3. Avvia lo script:

```powershell
.\RansomGuard.ps1
```

Il setup interattivo guiderà attraverso tutti i passaggi.

---

## Setup interattivo — guida passo passo

### 1. Cartelle da monitorare

Lo script chiede i percorsi uno alla volta. Puoi inserirne quanti vuoi, su dischi diversi.  
Premi **Invio senza scrivere nulla** per terminare l'inserimento.

```
[Cartelle da monitorare]
  Percorso #1 (obbligatorio)       : C:\Condivisi\Ufficio
  ✓ Aggiunto: C:\Condivisi\Ufficio
  Percorso #2 (o INVIO per finire) : D:\Backup\Dati
  ✓ Aggiunto: D:\Backup\Dati
  Percorso #3 (o INVIO per finire) :

  ┌─ Riepilogo cartelle selezionate ──────────────
  │  1. C:\Condivisi\Ufficio
  │  2. D:\Backup\Dati
  └───────────────────────────────────────────────

  Confermi questi 2 percorsi? (S/n)
```

Se un percorso non esiste, lo script offre di crearlo.

### 2. Telegram

Servono:
- **Token del bot**: crealo con [@BotFather](https://t.me/BotFather) su Telegram
- **Chat ID**: il tuo ID personale o quello di un gruppo/canale. Puoi ottenerlo con [@userinfobot](https://t.me/userinfobot)

### 3. Gotify

Servono:
- **URL del server** (es. `https://push.example.com`)
- **Porta** (opzionale, lascia vuoto per 80/443)
- **App Token**: generato nella dashboard Gotify sotto *Apps → Create App*

### 4. Abilitazione notifiche

Ogni canale può essere abilitato o disabilitato indipendentemente:

```
Abilita Telegram?          (S/n)
Abilita Gotify?            (S/n)
Abilita Popup/MSG Windows? (S/n)
```

Queste impostazioni sono modificabili manualmente in `rg_config.json` in qualsiasi momento:

```json
"EnableTelegram": true,
"EnableGotify":   true,
"EnablePopup":    false
```

### 5. Intervallo di controllo

Definisce ogni quanti minuti il Task pianificato esegue la verifica. Default: **15 minuti**.

---

## File generati dallo script

Tutti nella stessa cartella dello script:

| File | Contenuto |
|---|---|
| `rg_config.json` | Configurazione completa (token, path, intervallo, flag notifiche) |
| `rg_hashes.json` | Database degli hash SHA-256 baseline di tutti i file monitorati |
| `rg_log.txt` | Log di ogni esecuzione con timestamp |

---

## File esca (canary files)

Se le cartelle monitorate sono **vuote**, lo script crea automaticamente file dall'aspetto credibile per non essere ignorati da ransomware evoluti che escludono file sospetti:

| File | Tipo apparente |
|---|---|
| `desktop.ini` | Metadati cartella Windows (autentico) |
| `~WRL0003.tmp` | Temp file di Word con header OLE2 binario |
| `Budget_2024_Final.xlsx` | CSV con dati finanziari (mesi, centri di costo) |
| `Contratto_Fornitura_Rev3.docx` | RTF con testo contrattuale |
| `passwords_backup.txt` | Note interne con server, share, ticket |
| `HR_Salaries_Confidential.xlsx` | CSV con RAL e reparti |
| `System_Backup_Config.xml` | Export organico aziendale XML |
| `network_credentials.txt` | Credenziali di rete fittizie |
| `QuickBooks_Backup.qbb` | Header QuickBooks reale + rumore |
| `DB_Export_20240115.sql` | INSERT su tabelle tipo `fatture`, `clienti` |

Se la cartella contiene **già dei file**, lo script li usa direttamente come baseline senza crearne di nuovi.

> ⚠️ I contenuti dei file esca **non contengono mai** riferimenti a monitoraggio, sicurezza o script.

---

## Task pianificato Windows

Il task viene registrato in **Utilità di pianificazione → Libreria** con il nome `RansomwareGuard_Monitor`.

| Impostazione | Valore |
|---|---|
| Utente | SYSTEM |
| Privilegi | Più elevati disponibili |
| Trigger | Ogni N minuti (configurabile) |
| Istanze multiple | Termina quella in esecuzione e riparte |
| Batteria | Gira anche a batteria |
| Limite di durata | Nessuno |

Per verificare che il task esista:
```powershell
Get-ScheduledTask -TaskName "RansomwareGuard_Monitor"
```

---

## Rilevamento del processo colpevole

RansomwareGuard usa il **Windows Security Event Log (ID 4663)** per identificare quale processo ha modificato o cancellato un file monitorato.

### Come funziona

Al setup vengono configurati automaticamente:

1. **`auditpol`** — abilita l'audit del File System a livello di sistema (solo successi, nessun impatto sulle performance)
2. **SACL** (Security ACL) — imposta una regola di audit su ogni cartella monitorata che registra operazioni di scrittura e cancellazione da parte di qualsiasi utente

La notifica include nome processo, PID (in decimale) e utente:

```
⚠️ File modificati (1):
  • passwords_backup.txt [Processo: notepad++.exe PID:43928 Utente: PC\Mario]

❌ File cancellati (1):
  • Budget_2024_Final.xlsx [Processo: explorer.exe PID:5120 Utente: PC\Mario]
```

> **Nota:** il log 4663 richiede che l'audit sia attivo *prima* della modifica. Se reimposti lo script su una macchina nuova, usa l'opzione 5 del menu di gestione per ripristinare le SACL.

---

## Menu di gestione

```powershell
.\RansomGuard.ps1 --manage
```

```
╔══════════════════════════════════╗
║   RansomwareGuard - Gestione     ║
╚══════════════════════════════════╝
  1. Ricalcola hash baseline (dopo update legittimi)
  2. Invia notifica di test
  3. Mostra configurazione corrente
  4. Riconfigura da zero
  5. Rimposta audit SACL sulle cartelle
  6. Esci
```

| Opzione | Quando usarla |
|---|---|
| **1** | Dopo aver modificato legittimamente dei file nelle cartelle monitorate (es. aggiornamento documenti). Ricalcola il baseline senza reinviare alert. |
| **2** | Per verificare che Telegram, Gotify e popup funzionino correttamente. |
| **3** | Per visualizzare la configurazione attuale salvata. |
| **4** | Per ricominciare da zero (cancella config e hash, riavvia il setup). |
| **5** | Per reimpostare le SACL di audit dopo aver aggiunto nuove cartelle o spostato lo script. |

---

## Configurazione manuale (rg_config.json)

Il file di configurazione è leggibile e modificabile direttamente:

```json
{
  "MonitorPaths":    ["C:\\Condivisi", "D:\\Backup"],
  "TelegramToken":   "123456:ABCdef...",
  "TelegramChatId":  "-100123456789",
  "GotifyUrl":       "https://push.example.com",
  "GotifyToken":     "AbCdEfGh",
  "CheckInterval":   15,
  "SetupDone":       true,
  "EnableTelegram":  true,
  "EnableGotify":    true,
  "EnablePopup":     true
}
```

Dopo ogni modifica manuale il task la rileverà automaticamente all'esecuzione successiva, senza bisogno di riavviare nulla.

---

## Deploy su più macchine

Lo script è progettato per funzionare su più PC o server in modo autonomo:

- L'hostname viene rilevato dinamicamente con `[System.Net.Dns]::GetHostName()`
- Il subject di ogni notifica include il nome macchina: `🚨 [SERVER-CONTABILITA] RansomwareGuard ALERT`
- Puoi distribuire lo stesso script su N macchine, ognuna con la propria `rg_config.json`

---

## Struttura file di progetto

```
RansomwareGuard/
├── RansomGuard.ps1      ← script principale
├── rg_config.json       ← generato al primo avvio
├── rg_hashes.json       ← generato al primo avvio
└── rg_log.txt           ← generato al primo avvio
```

---

## Limitazioni note

- Il rilevamento del processo colpevole richiede che il Security Event Log non sia stato ruotato tra la modifica e il controllo. Su sistemi ad alto traffico aumentare la dimensione massima del log `Security` in Event Viewer.
- I canary file proteggono le cartelle monitorate ma non l'intero filesystem. Scegliere cartelle ad alto valore (condivisioni di rete, backup, documenti critici).
- Il tool è un sistema di **early warning**, non un antivirus. Rileva l'attività *dopo* che è iniziata, non la previene.
- Buona norma prevede di modificare i permessi della cartella contenente lo script per dargli solo accesso da parte di System


## Screenshot

<p align="center">
  <img src="https://github.com/user-attachments/assets/2d5f0d97-39ab-4947-a631-27e1a434aad5" width="613">
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/29dac68f-8449-4184-88cc-801414976df7" width="762">
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/aa39de87-81c5-4611-8c4b-a870bf7b13e5" width="382">
</p>


