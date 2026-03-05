# 🛡️ RansomwareGuard

Monitor anti-ransomware basato su **canary files** (file esca) per Windows.  
Rileva in tempo reale modifiche, cancellazioni e rinomina di file sospetti, identifica il processo responsabile e invia notifiche istantanee su Telegram, Gotify e popup Windows.

---

## Indice

- [Come funziona](#come-funziona)
- [Requisiti](#requisiti)
- [Installazione e primo avvio](#installazione-e-primo-avvio)
- [Modalità di esecuzione](#modalità-di-esecuzione)
- [Configurazione](#configurazione)
- [Canali di notifica](#canali-di-notifica)
- [Risposta attiva (process kill)](#risposta-attiva-process-kill)
- [File generati](#file-generati)
- [Menu di gestione](#menu-di-gestione)
- [Hardening consigliato](#hardening-consigliato)
- [Note tecniche](#note-tecniche)

---

## Come funziona

RansomwareGuard utilizza due livelli di difesa complementari:

### 1. FileSystemWatcher (tempo reale)
All'avvio il watcher registra un listener su ogni cartella monitorata. Qualsiasi evento di **modifica**, **cancellazione** o **rinomina** su un canary file viene rilevato in millisecondi, senza polling e senza carico CPU a riposo.

Quando scatta un evento:
1. Viene letto il **Security log di Windows** (eventi `4663` e `4656`) per correlare il file toccato al processo che l'ha aperto, comprensivo di PID, percorso eseguibile e utente
2. Se abilitato, il processo viene **terminato immediatamente** (`Stop-Process -Force`)
3. L'evento viene accodato in `rg_pending.json` con tutti i dettagli (accessor, snapshot processi, hash del file al momento del rilevamento)
4. Al ciclo successivo l'alert viene inviato su tutti i canali configurati

### 2. Hash check periodico (doppio check)
Ogni N minuti (configurabile, default 15) viene ricalcolato l'SHA-256 di tutti i canary file e confrontato con il baseline salvato al setup. Rileva modifiche che possono essere sfuggite al watcher (es. eventi persi per overflow del buffer) e file scomparsi.

### Canary files
Se la cartella monitorata è vuota al momento del setup, vengono creati automaticamente 10 file esca con nomi e contenuti verosimili, appetibili per un ransomware:

| File | Tipo |
|------|------|
| `desktop.ini` | Configurazione cartella |
| `~WRL0003.tmp` | Temp Office (OLE2 binario) |
| `Budget_2024_Final.xlsx` | CSV con dati budget fittizi |
| `Contratto_Fornitura_Rev3.docx` | RTF con contratto fittizio |
| `passwords_backup.txt` | Testo con credenziali false |
| `HR_Salaries_Confidential.xlsx` | CSV con stipendi fittizi |
| `System_Backup_Config.xml` | XML con dati organico fittizio |
| `network_credentials.txt` | Testo con credenziali di rete false |
| `QuickBooks_Backup.qbb` | File backup contabilità fittizio |
| `DB_Export_20240115.sql` | Dump SQL fittizio |

Se la cartella contiene già dei file, viene calcolato l'hash baseline su quelli esistenti senza crearne di nuovi.

### Deduplicazione intelligente
Per evitare spam di notifiche, ogni evento viene confrontato con quelli già inviati tramite **hash del contenuto del file al momento del rilevamento**. Se il file viene modificato di nuovo con un contenuto diverso, la notifica viene inviata nuovamente. Se il file è locked (tipico comportamento ransomware), viene usato `LastWriteTimeUtc + GUID` come identificatore univoco, garantendo che ogni scrittura venga sempre notificata.

---

## Requisiti

- **Windows 10 / 11** o **Windows Server 2016+**
- **PowerShell 5.1** o superiore
- Eseguire come **Amministratore** (richiesto per SACL, Security log e Task Scheduler)
- Audit policy abilitata (configurata automaticamente dallo script):
  - *File System* — eventi `4663`
  - *Handle Manipulation* — eventi `4656`

---

## Installazione e primo avvio

1. Copiare `RansomGuard.ps1` nella cartella desiderata (es. `C:\RansomwareGuard\`)
2. Aprire PowerShell **come Amministratore**
3. Eseguire:

```powershell
.\RansomGuard.ps1
```

Il wizard interattivo guiderà attraverso:

- Selezione delle cartelle da monitorare (una o più)
- Configurazione Telegram (token bot + chat ID)
- Configurazione Gotify (host + porta + app token)
- Abilitazione/disabilitazione dei singoli canali di notifica
- Intervallo dell'hash check periodico (minimo 5 minuti, default 15)
- Abilitazione della risposta attiva (kill del processo)

Al termine il wizard:
- Crea i canary files nelle cartelle vuote
- Salva il baseline degli hash
- Imposta le SACL di auditing sulle cartelle
- Registra il **Task pianificato** `RansomwareGuard_Monitor` (avvio automatico al boot, eseguito come SYSTEM)
- Offre l'invio di una notifica di test

Per avviare il watcher immediatamente senza riavviare lanciare il task manualmente, altrimenti per test e visualizzare l'output:

```powershell
.\RansomGuard.ps1 --watch
```

---

## Modalità di esecuzione

| Comando | Descrizione |
|---------|-------------|
| `.\RansomGuard.ps1` | Primo avvio: wizard di configurazione. Con config esistente: singolo hash check manuale |
| `.\RansomGuard.ps1 --watch` | Avvia il watcher continuo (usato dal Task Scheduler) |
| `.\RansomGuard.ps1 --manage` | Apre il menu di gestione interattivo |

---

## Configurazione

La configurazione viene salvata in `rg_config.json` nella stessa cartella dello script. Viene creato automaticamente dal wizard e non è necessario modificarlo a mano, ma i campi sono i seguenti:

```json
{
  "MonitorPaths":      ["C:\\Documenti", "D:\\Condivisione"],
  "TelegramToken":     "123456:ABC...",
  "TelegramChatId":    "-100123456789",
  "GotifyUrl":         "https://push.example.com",
  "GotifyToken":       "AppTokenGotify",
  "CheckInterval":     15,
  "EnableTelegram":    true,
  "EnableGotify":      true,
  "EnablePopup":       true,
  "EnableProcessKill": false,
  "SetupDone":         true
}
```

| Campo | Descrizione |
|-------|-------------|
| `MonitorPaths` | Array di percorsi assoluti da monitorare |
| `TelegramToken` | Token del bot Telegram ottenuto da @BotFather |
| `TelegramChatId` | ID della chat/canale destinatario degli alert |
| `GotifyUrl` | URL base del server Gotify (con protocollo, senza slash finale) |
| `GotifyToken` | App token dell'applicazione Gotify |
| `CheckInterval` | Intervallo in minuti tra gli hash check periodici (minimo 5) |
| `EnableTelegram` | Abilita/disabilita le notifiche Telegram |
| `EnableGotify` | Abilita/disabilita le notifiche Gotify |
| `EnablePopup` | Abilita/disabilita popup `msg.exe` e Toast notification Windows |
| `EnableProcessKill` | Abilita la terminazione automatica del processo sospetto |

---

## Canali di notifica

### Telegram
Richiede un bot Telegram creato tramite [@BotFather](https://t.me/BotFather). Il token ha il formato `123456789:AABBccdd...`. Il Chat ID può essere un utente, un gruppo o un canale (in questo caso inizia con `-100`).

### Gotify
[Gotify](https://gotify.net/) è un server di notifiche self-hosted. Inserire l'URL del server e il token dell'applicazione creata nel pannello di controllo. La porta può essere specificata separatamente durante il setup.

### Popup Windows
Tenta tre metodi in cascata:
1. `msg.exe` — messaggio di sessione (funziona su Pro/Server con sessioni attive)
2. **Toast notification** nativa Windows 10/11
3. **WScript.Shell Popup** — visibile anche da sessioni SYSTEM

---

## Risposta attiva (process kill)

Se `EnableProcessKill` è abilitato, nel momento in cui viene rilevato un evento su un canary file lo script:

1. Legge il Security log per identificare il PID del processo che ha toccato il file
2. Esegue `Stop-Process -Force` su quel PID
3. Registra nel log la terminazione con PID, nome processo e utente

> ⚠️ **Attenzione**: la risposta attiva è efficace contro ransomware che operano in userspace. Non può fermare processi con privilegi superiori a SYSTEM. Valutare attentamente in ambienti con software di backup o antivirus che accedono legittimamente ai file monitorati.

---

## File generati

Tutti i file vengono creati nella stessa cartella dello script:

| File | Contenuto |
|------|-----------|
| `rg_config.json` | Configurazione completa |
| `rg_hashes.json` | Baseline SHA-256 di tutti i canary file |
| `rg_log.txt` | Log completo di tutti gli eventi |
| `rg_pending.json` | Coda persistente degli alert (sopravvive ai crash) |

> I file `rg_*` sono esclusi automaticamente dal monitoraggio e dal calcolo dell'hash baseline.

---

## Menu di gestione

```powershell
.\RansomGuard.ps1 --manage
```

| Opzione | Descrizione |
|---------|-------------|
| `1` Ricalcola hash baseline | Da eseguire dopo modifiche legittime ai file monitorati (aggiornamenti, sostituzioni) per evitare falsi positivi |
| `2` Invia notifica di test | Verifica che tutti i canali di notifica configurati funzionino correttamente |
| `3` Mostra configurazione | Stampa il contenuto di `rg_config.json` |
| `4` Riconfigura da zero | Cancella configurazione e hash baseline, rilancia il wizard |
| `5` Stato e riavvio Task | Mostra stato, ultimo run e ultimo risultato del Task pianificato; permette il riavvio manuale |
| `6` Reimposta SACL audit | Riscrive le audit SACL sulle cartelle e sui canary file (utile se le policy vengono reimpostate da Group Policy) |

---

## Hardening consigliato

- **Cartella script**: accesso limitato a SYSTEM
- **Cartelle monitorate**: le SACL vengono impostate automaticamente; non rimuoverle
- **Group Policy**: se la macchina è in dominio, verificare che la GPO non sovrascriva le audit policy. In tal caso richiedere all'amministratore di dominio di abilitare le sottocategorie *File System* e *Handle Manipulation* a livello di GPO. L'opzione `6` del menu di gestione può essere usata come workaround temporaneo
- **Credenziali**: i token Telegram e Gotify sono salvati in chiaro in `rg_config.json`. Limitare i permessi di lettura del file come descritto sopra
- **Test periodico**: usare l'opzione `2` del menu di gestione dopo ogni aggiornamento del sistema per verificare che le notifiche funzionino ancora

---

## Note tecniche

- **Compatibilità**: Windows 10 build 10240+, Windows 11, Windows Server 2016+. Su sistemi più vecchi il rilevamento del processo via Security log è disabilitato automaticamente e viene usato solo lo snapshot dei processi attivi
- **Carico a riposo**: ~0% CPU, 0 scritture su disco. Il watcher usa eventi asincroni .NET (`FileSystemWatcher`) e dorme 3 secondi tra un ciclo e l'altro
- **Buffer FSW**: il buffer interno del `FileSystemWatcher` è configurato a 64KB (default 8KB) per ridurre il rischio di overflow silenzioso nelle sessioni SYSTEM
- **Persistenza alert**: la coda `rg_pending.json` sopravvive a crash e riavvii. Gli alert non inviati per problemi di rete vengono ritentati al ciclo successivo
- **Task Scheduler**: il task `RansomwareGuard_Monitor` gira come SYSTEM con riavvio automatico fino a 5 volte ogni minuto in caso di crash
