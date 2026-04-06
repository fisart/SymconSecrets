# 🔐 SymconSecrets – Dokumentation (V 3.0)

## 1. Warum benötigt man dieses Modul in IP-Symcon?

Standardmäßig speichert IP-Symcon alle Variableninhalte, Skripte und Konfigurationen im Klartext in der Datei `settings.json`. Daraus ergeben sich folgende Sicherheitsprobleme:

- **Klartext-Speicherung:** Passwörter für Dienste (Spotify, MQTT, Datenbanken, Kameras) stehen im Klartext in der Einstellungsdatei.
- **Unsichere Backups:** Ein Backup des Systems enthält automatisch alle Passwörter. Wer Zugriff auf das Backup hat, hat Zugriff auf alle Ihre Konten.
- **Sichtbarkeit:** Jeder Benutzer mit Zugriff auf die IP-Symcon Verwaltungskonsole kann die Passwörter in den Skripten oder Variablen lesen.
- **Verwaltungsaufwand:** Bei verteilten Systemen müssen Passwörter auf jedem System manuell gepflegt werden.

## 2. Wie werden diese Probleme beseitigt? (Zero-Knowledge-Konzept)

Das Modul SymconSecrets adressiert diese Risiken durch ein konsequentes Sicherheitsdesign und bietet signifikante Vorteile im Betrieb:

- **Verschlüsselung (AES-128-GCM):** Alle Geheimnisse werden mit AES-128-GCM verschlüsselt (Authenticated Encryption). In der Datenbank liegt nur unlesbarer Datensalat („Blob“). Der Klartext landet niemals auf der Festplatte.
- **Hardware-Trennung (Schlüssel-Isolation):** Der Entschlüsselungs-Key (`master.key`) liegt als physische Datei auf dem Betriebssystem (z.B. USB-Stick oder geschützter Ordner), getrennt von der Symcon-Datenbank.
- **Stateless Editor (Zustandslosigkeit):** Im Gegensatz zu herkömmlichen Modulen speichert SymconSecrets die Passwörter während der Eingabe nicht in den Instanz-Eigenschaften ab. Die Daten werden direkt vom Browser in den Arbeitsspeicher (RAM) des Servers übertragen. Dadurch landen Passwörter zu keinem Zeitpunkt unverschlüsselt in der `settings.json`.
- **Zentralisierte Verwaltung:** Änderungen (z. B. Passwort-Updates) werden an einer einzigen Stelle (Master) vorgenommen und stehen durch die automatische Synchronisation **sofort systemweit** auf allen Slaves zur Verfügung. Dies eliminiert manuelle Pflegeaufwände und verhindert Inkonsistenzen in verteilten Umgebungen.
- **Zero-Convention Import:** Automatische Erkennung von Ordnern ohne technische Metadaten oder spezielle Syntax. Das Modul analysiert die Form Ihres JSONs eigenständig.

## 3. Wie funktioniert das Modul? (Funktionsweise)

Das Modul arbeitet nach dem Tresor-Prinzip:

- **Der Tresor (Vault):** Eine String-Variable in IP-Symcon, die das verschlüsselte JSON-Paket enthält.
- **Der Schlüssel (Master Key):** Eine Datei (`master.key`), die lokal auf dem Server liegt.
- **Der Zugriff (In-Memory):** Die Entschlüsselung findet ausschließlich im Arbeitsspeicher (RAM) statt.
- **Stateless UI:** Wenn Sie den Editor öffnen, wird das JSON-Objekt im Browser angezeigt. Sobald Sie die Konsole schließen, wird der Klartext im RAM gelöscht. Es erfolgt keine Speicherung auf der Festplatte, solange die Daten nicht verschlüsselt wurden.
- **Synchronisation (Master -> Slave):** Der Master sendet das verschlüsselte Paket über einen WebHook an die Slaves (abgesichert via HTTPS, Sync Token und optional Basic Auth).

## 4. Systemrollen (Operation Modes)

- **Master (Sender):** Die zentrale Instanz ("Single Source of Truth"). Hier werden Daten verwaltet und sicher an Slaves verteilt.
- **Slave (Receiver):** Empfängt verschlüsselte Updates. Lokale Änderungen am Tresor sind nicht vorgesehen und werden beim nächsten Sync überschrieben.
- **Standalone:** Isolierter lokaler Tresor ohne Netzwerkfunktionen. Alle Synchronisations-Optionen (Token, Slaves) werden automatisch ausgeblendet.

## 5. Konfigurations-Leitfaden (Formular-Referenz)

### 5.1 Sicherheitskonfiguration & Basis-Setup

1.  **System Role:** Auswahl der Rolle (Master/Slave/Standalone).
2.  **Directory Path:** Absoluter Pfad zum Verzeichnis des `master.key` (z. B. `/var/lib/symcon_keys/` oder `/secrets`).
3.  **Check Directory Permissions:** Validiert, ob der Symcon-Dienst Lese- und Schreibrechte im Zielverzeichnis hat. Dies ist für die automatische Schlüsselerstellung zwingend erforderlich.
4.  **Initialisierung:** Auf „Übernehmen“ klicken, um den `master.key` zu initialisieren.

### 5.2 Synchronisation & Verknüpfung (Nur Master)

- **Sync Token (Shared Secret):** Der "Hausschlüssel" für die Kommunikation zwischen Master und Slave.
  - **Generate Random Token:** Erzeugt ein sicheres, zufälliges 32-Byte Token.
  - **Show/Copy Token:** Zeigt das Token im Klartext an, um es in der Slave-Instanz zu hinterlegen.
  - **Save Token (Encrypted):** Speichert das Token verschlüsselt in der Datei `system.vault`. **Wichtig:** Ohne diesen Schritt ist keine Synchronisation möglich.
- **Slave WebHooks (Tabelle):**
  - **Server (Label):** Anzeigename für Ihre Übersicht (z. B. "Ferienhaus").
  - **URL:** Ziel-WebHook des Slaves (Format: `https://[IP-oder-DNS]/hook/secrets_[ID]`).
  - **TLS Mode:** _Strict_ (CA-validiert) oder _Pinned_ (validiert via SHA-256 Fingerprint, ideal für selbstsignierte Zertifikate im LAN).
  - **Key Provisioning:** Legt fest, ob der `master.key` bei jedem Sync mitgesendet wird (_Sync Payload_).
- **Basic-Auth Passwords:** Im ausklappbaren Bereich können Passwörter für die Slave-WebHooks verschlüsselt hinterlegt werden (integrierter Passwort-Manager für Slaves).

### 5.3 Actions & Wartung

- **Manually Sync to Slaves:** Stößt sofort eine Übertragung an alle Slaves in der Liste an.
- **Rotate Encryption Key:** Erzeugt einen neuen Master-Key und verschlüsselt den gesamten Tresor sowie alle System-Geheimnisse mit dem neuen Schlüssel um.

## 6. Tresor-Explorer (Bedienung)

### 6.1 Navigation & Hybride Strukturen

Das Modul erkennt automatisch die Struktur Ihrer Daten:

- **Ordner (📁):** Knoten, die Unterelemente (Arrays) enthalten. Gruppieren von Zusammenhängen (z.B. Standorte, Gerätetypen).
- **Datensätze (🔑):** Knoten mit reinen Datenfeldern (User, PW, IP, URL, etc.).
- **Hybrid-Modus:** Ein Ordner kann eigene Felder besitzen (z. B. Standort-Informationen) **und** gleichzeitig Unterordner enthalten. Diese Felder erscheinen oben unter dem Bereich „🔑 FELDER DIESES ORDNER“.
- **Navigation:** Per Klick auf Zeilen „hineinzoomen“ und per „ZURÜCK“-Button navigieren.
- **⚙️ / 🗑️:** Symbole zum Öffnen des Detail-Editors (Popup) oder zum Löschen eines Elements.

### 6.2 Erstellung & Import

- **NEU AN DIESER POSITION:** Name für das Element eingeben und Typ wählen (+ UNTERORDNER oder + RECORD). Schrägstriche (/) sind im Namen verboten.
- **JSON-Import:** Große Strukturen können über das Feld „JSON IMPORT“ direkt als String eingelesen werden. Dies setzt den Explorer automatisch auf „root“ zurück. Die Struktur wird automatisch analysiert und im Explorer korrekt "hydriert".

## 7. 🔐 Biometrische Authentifizierung (Passkeys)

### 7.1 Übersicht

Die Passkey-Funktion ermöglicht es Ihnen, den Zugriff auf den Tresor oder eigene WebHook-Skripte durch biometrische Merkmale (Fingerabdruck, Gesichtserkennung oder Windows Hello) zu schützen. Dies ersetzt die manuelle Eingabe von Passwörtern durch einen sicheren kryptografischen Handshake (WebAuthn/FIDO2).

**Sicherheitsmerkmale:**

- **Hardware-gebunden:** Der private Schlüssel verlässt niemals Ihr Gerät (Smartphone oder PC).
- **Zero-Knowledge:** Im Tresor wird lediglich der öffentliche Schlüssel im versteckten Ordner `__AUTH__` gespeichert.
- **Zustandslos:** Die Authentifizierung erfolgt im RAM-Buffer und ist an Ihre IP-Adresse und Ihren Browser gebunden.

### 7.2 Einrichtung (Registrierung)

Bevor Sie ein Gerät nutzen können, muss es einmalig verknüpft werden. Dieser Vorgang ist durch ein spezielles Passwort geschützt, das Sie selbst im Tresor festlegen.

**Schritt 1: Registrierungs-Passwort festlegen**

1. Öffnen Sie den Tresor-Explorer in IP-Symcon.
2. Erstellen Sie auf der obersten Ebene (root) einen neuen Record mit dem Namen: `RegistrationPassword`.
3. Öffnen Sie diesen Record (⚙️) und fügen Sie ein Feld hinzu: Name: `PW`, Wert: Ein starkes Passwort Ihrer Wahl.
4. Klicken Sie auf **💾 Speichern**.

**Schritt 2: Gerät verknüpfen**
Rufen Sie die Registrierungs-URL auf dem Gerät auf, das Sie hinzufügen möchten (Smartphone oder PC). **Wichtig: Dies funktioniert nur über eine verschlüsselte HTTPS-Verbindung!**

- **URL-Format:** `https://[Ihre-Symcon-URL]/hook/secrets_[ID]?register=1&pass=[Ihr-PW]`
- **Beispiel:** `https://08a32d3d...ipmagic.de/hook/secrets_59597?register=1&pass=mein-sicherer-schluessel`
  Folgen Sie den Anweisungen im Browser und berühren Sie den Sensor Ihres Geräts. Nach der Meldung „✅ Gerät erfolgreich registriert!“ ist das Gerät hinterlegt.

### 7.3 Nutzung im Alltag

- **Login-Portal:** Sie können das Portal nutzen, um eine Sitzung für Ihren Browser zu starten. URL: `https://[Ihre-Symcon-URL]/hook/secrets_[ID]?portal=1`. Nach erfolgreichem Scan ist Ihr Browser für 60 Minuten autorisiert.
- **Integration in eigene Skripte:** Sie können die biometrische Prüfung in jedes WebHook-Skript einbauen:

```php
<?php
$instanceID = 59597; // ID Ihrer SecretsManager Instanz
if (!SEC_IsPortalAuthenticated($instanceID)) {
    $currentUrl = $_SERVER['REQUEST_URI'];
    $loginUrl = "/hook/secrets_" . $instanceID . "?portal=1&return=" . urlencode($currentUrl);
    header("Location: " . $loginUrl);
    exit;
}
echo "Willkommen! Ihr Zugriff wurde biometrisch verifiziert.";
```

## 8. 🛠️ Fortgeschrittene Administration & Biometrie-Verbund

### 8.1 Das Admin-Dashboard

Das Admin-Dashboard ist eine zentrale Steuerseite, die über den WebHook aufgerufen werden kann. Es dient dazu, Registrierungs-Links für alle im System befindlichen Master- und Slave-Instanzen automatisch zu generieren.

**Zugriffsschutz (Zweistufig):**

- **Erst-Login:** Erfolgt über ein spezielles Admin-Passwort in der URL: `?admin=1&pass=[AdminPortal-Passwort]`
- **Folge-Logins:** Sobald ein Gerät einmal per Passwort autorisiert wurde, erkennt das Modul die biometrische Sitzung. Zukünftige Aufrufe benötigen nur noch den Fingerabdruck/Passkey über `?admin=1`.

### 8.2 Sicherheits-Architektur (Zwei-Passwort-Konzept)

Um maximale Sicherheit zu gewährleisten, nutzt das System zwei getrennte Passwörter im Tresor:

1.  **AdminPortal (Record `AdminPortal` -> Feld `PW`):** Schützt das Dashboard. Sollte niemals geteilt werden. Ermöglicht den Zugriff auf alle System-Links.
2.  **RegistrationPassword (Record `RegistrationPassword` -> Feld `PW`):** Schützt den eigentlichen Registrierungs-Vorgang (`?register=1&pass=...`).

### 8.3 Passkeys in verteilten Systemen (Master/Slave)

- **Das Multi-Domain-Prinzip:** Passkeys sind kryptografisch an eine exakte Domain (URL) gebunden. Ein Gerät muss für jede URL einmal registriert werden. Ein Key für `master.com` wird niemals für `slave.com` funktionieren.
- **Intelligente Synchronisation (Merging):** Damit der Master beim Synchronisieren nicht die mühsam registrierten Passkeys auf den Slaves löscht, verfügt das Modul über eine Merging-Logik. Lokale biometrische Schlüssel bleiben auf dem jeweiligen System erhalten, auch wenn der Master ein Update sendet.

## 9. PHP API (Nutzung in Skripten)

```php
$id = 59597;
// 1. Einfaches Secret auslesen (flache Struktur)
$pw = SEC_GetSecret($id, "Spotify");
// 2. Tief verschachteltes Secret auslesen (Pfad-Logik)
$ip = SEC_GetSecret($id, "Standorte/Produktion/SPS_Passwort");
// 3. Alle verfügbaren Schlüssel der aktuellen Ebene auflisten
$keys = json_decode(SEC_GetKeys($id), true);
```

---

---

# 🔐 SymconSecrets – Documentation (V 3.0)

## 1. Why do you need this module in IP-Symcon?

By default, IP-Symcon stores all variable contents, scripts, and configurations in plaintext within the `settings.json` file. This leads to several security issues:

- **Plaintext Storage:** Passwords for services (Spotify, MQTT, databases, cameras) are stored in plaintext in the configuration file.
- **Unsafe Backups:** A system backup automatically contains all passwords. Anyone with access to the backup has access to all your accounts.
- **Visibility:** Any user with access to the IP-Symcon management console can read passwords in scripts or variables.
- **Maintenance Effort:** In distributed systems, passwords must be manually maintained on each system.

## 2. Solutions Provided (Zero-Knowledge Concept)

The SymconSecrets module addresses these risks through a consistent security-by-design approach and offers significant operational advantages:

- **Encryption (AES-128-GCM):** All secrets are encrypted using AES-128-GCM (Authenticated Encryption). The database contains only unreadable "blob" data. Plaintext never hits the disk.
- **Hardware Separation (Key Isolation):** The decryption key (`master.key`) is stored as a physical file on the operating system (e.g., USB stick or protected folder), separate from the Symcon database.
- **Stateless Editor (Security Update):** Unlike traditional modules, SymconSecrets does not store passwords in the instance properties during input. Data is transmitted directly from the browser to the server's RAM. As a result, passwords never end up unencrypted in the `settings.json`.
- **Centralized Management:** Changes (e.g., password updates) are made at a single point (Master) and are **immediately available system-wide** on all Slaves through automatic synchronization. This eliminates manual maintenance and prevents inconsistencies in distributed environments.
- **Zero-Convention Import:** Automatic folder detection without technical metadata or special syntax. The module analyzes the shape of your JSON independently.

## 3. How does the module work? (Functionality)

The module operates according to the vault principle:

- **The Vault:** A string variable in IP-Symcon containing the encrypted JSON package.
- **The Master Key:** A file (`master.key`) located locally on the server.
- **In-Memory Access:** Decryption takes place exclusively in the random access memory (RAM).
- **Stateless UI:** When the editor is opened, the JSON object is displayed in the browser. As soon as the console is closed, the plaintext in the RAM is deleted. No storage takes place on the hard disk as long as the data has not been encrypted.
- **Synchronization (Master -> Slave):** The Master sends the encrypted package via a WebHook to the Slaves (secured via HTTPS, Sync Token, and optional Basic Auth).

## 4. System Roles (Operation Modes)

- **Master (Sender):** The central instance ("Single Source of Truth"). Manages data and pushes it securely to Slaves.
- **Slave (Receiver):** Receives encrypted updates. Local edits to the vault are not intended and will be overwritten during the next sync.
- **Standalone:** Isolated local vault without network features. All synchronization options (Token, Slaves) are automatically hidden.

## 5. Configuration Guide (Form Reference)

### 5.1 Security Configuration & Initial Setup

1.  **System Role:** Choose Master, Slave, or Standalone.
2.  **Directory Path:** Absolute OS path for the `master.key` (e.g., `/var/lib/symcon_keys/` or `/secrets`).
3.  **Check Directory Permissions:** Validates that the Symcon service has R/W access to the target directory. This is mandatory for automatic key generation.
4.  **Initialization:** Click "Apply" to initialize the `master.key`.

### 5.2 Synchronization & Linking (Master Only)

- **Sync Token (Shared Secret):** The "house key" for communication between Master and Slave.
  - **Generate Random Token:** Creates a secure, random 32-byte token.
  - **Show/Copy Token:** Displays the token in plaintext for entry into the Slave instance.
  - **Save Token (Encrypted):** Stores the token encrypted in the `system.vault` file. **Important:** Synchronization is not possible without this step.
- **Slave WebHooks (Table):** Define your remote targets.
  - **Server (Label):** Display name for your overview (e.g., "Holiday Home").
  - **URL:** The Slave's WebHook URL (Format: `https://[IP-or-DNS]/hook/secrets_[ID]`).
  - **TLS Mode:** _Strict_ (CA-validated) or _Pinned_ (validated via SHA-256 fingerprint, ideal for self-signed certificates in a local network).
  - **Key Provisioning:** Determines if the `master.key` is included in every sync (_Sync Payload_).
- **Basic-Auth Passwords:** Passwords for the Slave WebHooks can be stored encrypted in the expansion panel (integrated password manager for Slaves).

### 5.3 Actions & Maintenance

- **Manually Sync:** Immediate push to all configured slaves.
- **Rotate Encryption Key:** Generates a new master key and re-encrypts the entire vault and all system secrets with the new key.

## 6. Vault Explorer (Usage)

### 6.1 Navigation & Hybrid Structures

The module automatically detects the structure of your data:

- **Folders (📁):** Nodes containing sub-elements (arrays). For logical grouping (e.g., Locations, Categories).
- **Records (🔑):** Nodes containing only data fields (User, PW, etc.).
- **Hybrid Mode:** A folder can hold its own fields (e.g., location information) **and** simultaneously contain sub-folders. These fields appear at the top under the "🔑 FOLDER FIELDS" section.
- **Navigation:** Click rows to drill down; use the "BACK" button to navigate up.
- **⚙️ / 🗑️:** Icons to open the detail editor (popup) or delete an item.

### 6.2 Creation & Import

- **NEW AT THIS POSITION:** Enter a name for the element and select the type (+ FOLDER or + RECORD). Slashes (/) are forbidden in names.
- **JSON Import:** Paste standard JSON structures into the "JSON IMPORT" field to overwrite and automatically "hydrate" the vault. This automatically resets the Explorer to "root".

## 7. 🔐 Biometric Authentication (Passkeys)

### 7.1 Overview

Protect access to your vault or custom WebHook scripts using biometrics (fingerprint, face recognition, or Windows Hello). This replaces manual password entry with a secure cryptographic handshake (WebAuthn/FIDO2).

**Security Features:**

- **Hardware-Bound:** The private key never leaves your device (smartphone or PC).
- **Zero-Knowledge:** Only the public key is stored in your vault within the hidden `__AUTH__` folder.
- **Stateless:** Authentication is managed in a RAM buffer and is tied to your IP address and browser.

### 7.2 Setup (Registration)

Before you can use a device, it must be linked once. This process is protected by a special password that you define yourself within the vault.

**Step 1: Define the Registration Password**

1. Open the Vault Explorer in IP-Symcon.
2. At the top level (root), create a new record named: `RegistrationPassword`.
3. Open this record (⚙️) and add a field: Name: `PW`, Value: A strong password of your choice.
4. Click **💾 Save**.

**Step 2: Link your Device**
Open the registration URL on the device you want to add (HTTPS required).

- **URL Format:** `https://[Your-Symcon-URL]/hook/secrets_[ID]?register=1&pass=[Your-PW]`
- **Example:** `https://08a32d3d...ipmagic.de/hook/secrets_59597?register=1&pass=my-secure-key`
  Follow the instructions in the browser and touch your device's sensor. Once the message "✅ Device successfully registered!" appears, your device is linked.

### 7.3 Daily Usage

- **Login Portal:** `https://[Your-Symcon-URL]/hook/secrets_[ID]?portal=1`. After a successful scan, your browser is authorized for 60 minutes.
- **Integration into Custom Scripts:** You can integrate biometric verification into any WebHook script:

```php
<?php
$instanceID = 59597; // ID of your SecretsManager instance
if (!SEC_IsPortalAuthenticated($instanceID)) {
    $currentUrl = $_SERVER['REQUEST_URI'];
    $loginUrl = "/hook/secrets_" . $instanceID . "?portal=1&return=" . urlencode($currentUrl);
    header("Location: " . $loginUrl);
    exit;
}
echo "Welcome! Your access has been biometrically verified.";
```

## 8. 🛠️ Advanced Administration & Biometric Federation

### 8.1 The Admin Dashboard

The Admin Dashboard is a centralized management page accessible via WebHook (`?admin=1&pass=[AdminPortal-Password]`). It automatically generates registration links for all configured Master and Slave instances. After the first login, access is protected via Passkey biometrics via `?admin=1`.

### 8.2 Security Architecture (Two-Password Concept)

For maximum security, the system utilizes two distinct passwords stored within the vault:

1.  **AdminPortal (Record `AdminPortal` -> Field `PW`):** Protects the Admin Dashboard. Should never be shared. Grants access to all system-wide registration links.
2.  **RegistrationPassword (Record `RegistrationPassword` -> Field `PW`):** Protects the actual device enrollment process (`?register=1&pass=...`).

### 8.3 Passkeys in Distributed Environments (Master/Slave)

- **Multi-Domain Principle:** Passkeys are cryptographically bound to a specific Domain (URL). A device must be registered once for every URL. A key for `master.com` will never work for `slave.com`.
- **Intelligent Synchronization (Merging):** Merging Logic prevents the Master from overwriting locally registered Passkeys on Slaves during a sync. Local biometric keys are preserved on each system, even after a Master update.

## 9. PHP API Reference

````php
$id = 59597;
// 1. Access a simple secret
$pw = SEC_GetSecret($id, "Spotify");
// 2. Access a nested secret using path logic
$pass = SEC_GetSecret($id, "Locations/Production/PLC_Password");
// 3. List all identifiers at the current level
$keys = json_decode(SEC_GetKeys($id), true);


Hier ist eine kompakte Dokumentation der **neuen Funktionen** des `SecretsManager`-Moduls auf Basis des jetzt getesteten Stands `5.3.0`. Die neue Version ergänzt eine **scoped Write-API** sowie **Backup/Restore lokaler Secrets**, während bestehende Passkeys in `__AUTH__` und globale Secrets weiter kompatibel bleiben.

# SecretsManager 5.3.0 – Dokumentation der neuen Funktionen

## Überblick

Mit Version **5.3.0** wurden drei zentrale Erweiterungen eingeführt:

1. **Schreib-API mit Scope**

   * Secrets können jetzt gezielt als `global` oder `local` geschrieben werden.

2. **Backup/Restore lokaler Secrets**

   * Lokale Daten eines Systems können exportiert und wieder importiert werden.

3. **Slave-sicherer Sync**

   * Bei einem Master-Sync bleiben auf dem Slave die lokalen Bereiche

     * `__AUTH__`
     * `__LOCAL__`
       erhalten.

---

## Grundprinzip der Datenbereiche

### Globaler Bereich

Der normale Vault-Root bleibt der **globale replizierte Bereich**.

Beispiel:

```text
GoogleNest
└── SharedConnection
````

Dieser Bereich wird auf dem **Master** geschrieben und auf **Slaves** synchronisiert.

### Lokaler Bereich

Der neue Bereich `__LOCAL__` ist für **lokale Secrets**, die **nicht** repliziert werden.

Beispiel:

```text
__LOCAL__
└── GoogleNest
    └── SharedConnection
```

### Lokaler Auth-/Passkey-Bereich

Der bestehende Bereich `__AUTH__` bleibt unverändert und enthält lokale Passkeys / Auth-Daten. Dieser Bereich wird weiterhin bei Sync erhalten.

---

# Neue öffentliche Funktionen

## 1. `SetRecordFields`

### Signatur

```php id="18prkq"
SEC_SetRecordFields(int $instanceID, string $path, array $fields, string $scope): bool
```

Intern im Modul:

```php id="dju4yv"
public function SetRecordFields(string $path, array $fields, string $scope): bool
```

### Zweck

Schreibt flache Feldwerte in einen Record-Pfad.

### Parameter

#### `instanceID`

Instanz-ID des `SecretsManager`

#### `path`

Pfad des Ziel-Records, z. B.:

```text id="edphz8"
GoogleNest/SharedConnection
Camera/Zone1
Mail/Gmail
```

#### `fields`

Assoziatives Array mit flachen Feldwerten.

Beispiel:

```php id="95gu9d"
[
    'ClientID'     => 'abc',
    'ClientSecret' => 'xyz',
    'ProjectID'    => 'my-project'
]
```

#### `scope`

Erlaubte Werte:

- `global`
- `local`

### Verhalten je Scope

#### `scope = 'global'`

- **nur auf Master erlaubt**
- schreibt in den normalen globalen Vault-Bereich
- löst auf Master anschließend `SyncSlaves()` aus

#### `scope = 'local'`

- auf **Master**, **Standalone** und **Slave** erlaubt
- schreibt in den lokalen Bereich `__LOCAL__`
- löst **keinen** Sync aus

### Rückgabewert

- `true` bei Erfolg
- `false` bei Fehler oder unzulässiger Scope/Rollen-Kombination

---

## Beispiele für `SetRecordFields`

### Beispiel 1 – Globalen Datensatz auf Master schreiben

```php id="5fzv0q"
$result = SEC_SetRecordFields(12345, 'GoogleNest/SharedConnection', [
    'ClientID'     => 'MASTER_CLIENT_ID_001',
    'ClientSecret' => 'MASTER_CLIENT_SECRET_001',
    'ProjectID'    => 'MASTER_PROJECT_001',
    'AccountEmail' => 'master@example.com'
], 'global');
```

### Ergebnis

- Daten landen im **globalen Root-Bereich**
- nur auf **Master** erlaubt
- werden auf Slaves repliziert

---

### Beispiel 2 – Lokalen Datensatz auf Slave schreiben

```php id="6ec3dg"
$result = SEC_SetRecordFields(23456, 'GoogleNest/SharedConnection', [
    'RefreshToken' => 'SLAVE_LOCAL_REFRESH_001',
    'AccessToken'  => 'SLAVE_LOCAL_ACCESS_001',
    'UpdatedBy'    => 'slave-local-test'
], 'local');
```

### Ergebnis

- Daten landen unter `__LOCAL__/GoogleNest/SharedConnection`
- keine Replikation
- auf Slave erlaubt

---

### Beispiel 3 – Unerlaubter globaler Write auf Slave

```php id="0ixxpm"
$result = SEC_SetRecordFields(23456, 'GoogleNest/SharedConnection', [
    'ShouldFail' => 'yes'
], 'global');
```

### Ergebnis

- Rückgabewert `false`
- Änderung wird abgewiesen

---

# 2. `ExportLocalSecrets`

### Signatur

```php id="qex8bi"
SEC_ExportLocalSecrets(int $instanceID): string
```

Intern im Modul:

```php id="rr6gmf"
public function ExportLocalSecrets(): string
```

### Zweck

Exportiert die **lokalen** Daten eines Systems als JSON.

### Exportierte Bereiche

- `__AUTH__`
- `__LOCAL__`

### Nicht exportiert

- globaler replizierter Root-Bereich

### Rückgabe

- JSON-String
- leerer String bei Fehler

---

## Beispiel für `ExportLocalSecrets`

```php id="1v80jj"
$json = SEC_ExportLocalSecrets(23456);
echo $json;
```

### Beispielausgabe

```json id="1set69"
{
  "__AUTH__": {
    "device_1771079664": {
      "credentialId": "...",
      "attestation": "..."
    }
  },
  "__LOCAL__": {
    "GoogleNest": {
      "SharedConnection": {
        "RefreshToken": "SLAVE_LOCAL_REFRESH_001",
        "AccessToken": "SLAVE_LOCAL_ACCESS_001",
        "UpdatedBy": "slave-local-test"
      }
    }
  }
}
```

---

# 3. `ImportLocalSecrets`

### Signatur

```php id="762m4r"
SEC_ImportLocalSecrets(int $instanceID, string $json): bool
```

Intern im Modul:

```php id="pitk1j"
public function ImportLocalSecrets(string $json): bool
```

### Zweck

Importiert zuvor exportierte lokale Daten zurück in den Vault.

### Importierte Bereiche

- `__AUTH__`
- `__LOCAL__`

### Nicht verändert

- globaler replizierter Root-Bereich

### Sync-Verhalten

- löst **keinen** `SyncSlaves()` aus

### Rückgabewert

- `true` bei Erfolg
- `false` bei Fehler

---

## Beispiel für `ImportLocalSecrets`

```php id="732l8g"
$json = SEC_ExportLocalSecrets(23456);

$result = SEC_ImportLocalSecrets(23456, $json);
```

### Ergebnis

- lokale Passkeys in `__AUTH__` werden wiederhergestellt
- lokale Secrets in `__LOCAL__` werden wiederhergestellt
- globale Daten bleiben unangetastet

---

# Rollenlogik

## Master

### `global`

- erlaubt
- schreibt global
- repliziert

### `local`

- erlaubt
- schreibt nur lokal unter `__LOCAL__`
- keine Replikation

## Standalone

### `global`

- nicht erlaubt

### `local`

- erlaubt

## Slave

### `global`

- nicht erlaubt

### `local`

- erlaubt

Diese Rollenlogik ist in der neuen Scope-Validierung und Write-Logik implementiert.

---

# Sync-Verhalten

## Master → Slave

Wenn der Master globale Vault-Daten synchronisiert:

- normaler globaler Bereich wird aktualisiert
- auf dem Slave bleiben zusätzlich erhalten:
  - `__AUTH__`
  - `__LOCAL__`

Das wird durch die neue Preserve-Logik im Slave-Sync sichergestellt.

---

# UI-Funktionen

Zusätzlich zur API gibt es eine kleine UI-Erweiterung für manuelles Backup/Restore:

## Neue UI-Sektion

**LOCAL SECRETS BACKUP / RESTORE**

### Funktionen

- **Export Local Secrets**
- Anzeige des Export-JSON
- Eingabe eines JSON für Restore
- **Import Local Secrets**

### Zweck

Manuelle Sicherung und Wiederherstellung lokaler Daten ohne externes Script. Diese UI wurde als additive Erweiterung eingebaut und nutzt intern dieselbe API-Logik.

---

# Wichtige Hinweise

## 1. Feldstruktur

`SetRecordFields()` erwartet **flache Felder**:

- erlaubt: Strings, Zahlen, boolsche Werte, die zu String konvertiert werden
- nicht erlaubt: Arrays / Objekte als Feldwert

## 2. Interne Keys

Feldnamen mit internem Präfix wie `__...` dürfen nicht als normale Record-Felder gesetzt werden.

## 3. Upward Compatibility

Bestehende Passkeys und bestehende globale Secrets bleiben kompatibel:

- `__AUTH__` bleibt lokaler Auth-Bereich
- normaler Vault-Root bleibt globaler Bereich
- `__LOCAL__` ist neu und rein additiv

---

# Praktische Beispiele

## A. Gemeinsame globale Nest-Verbindung auf Master

```php id="07ah5r"
SEC_SetRecordFields(12345, 'GoogleNest/SharedConnection', [
    'ClientID'     => 'nest-client-id',
    'ClientSecret' => 'nest-client-secret',
    'ProjectID'    => 'nest-project',
    'AccountEmail' => 'admin@example.com'
], 'global');
```

## B. Lokaler Refresh-Token auf Slave

```php id="7j2jm9"
SEC_SetRecordFields(23456, 'GoogleNest/SharedConnection', [
    'RefreshToken' => 'local-refresh-token',
    'AccessToken'  => 'local-access-token'
], 'local');
```

## C. Lokale Daten sichern

```php id="8vazfc"
$backup = SEC_ExportLocalSecrets(23456);
file_put_contents('/tmp/slave_local_backup.json', $backup);
```

## D. Lokale Daten wiederherstellen

```php id="t0f7if"
$backup = file_get_contents('/tmp/slave_local_backup.json');
SEC_ImportLocalSecrets(23456, $backup);
```

---

# Zusammenfassung

## Neue Funktionen

- `SEC_SetRecordFields(..., $scope)`
- `SEC_ExportLocalSecrets(...)`
- `SEC_ImportLocalSecrets(...)`

## Neue Bereiche

- `__LOCAL__` für lokale Secrets
- `__AUTH__` bleibt für lokale Passkeys/Auth

## Zentrale Regeln

- `global` nur auf Master
- `local` lokal auf jeder Rolle
- Slave-Sync erhält `__AUTH__` und `__LOCAL__`

## Ergebnis

Das Modul unterstützt jetzt gleichzeitig:

- globale replizierte Secrets
- lokale slave-spezifische Secrets
- lokale Passkeys
- Backup/Restore lokaler Daten
