# 🔐 SymconSecrets - Dokumentation (V 2.5)

## 1. Das Problem & Die Lösung
Standardmäßig speichert IP-Symcon alle Konfigurationen und Variablen im Klartext in der `settings.json`. Dies führt zu erheblichen Sicherheitsrisiken bei Backups, unbefugtem Dateizugriff oder der Arbeit in verteilten Systemen.

**SymconSecrets** löst dies durch ein „Zero-Knowledge“-Prinzip und bietet signifikante Vorteile im Betrieb:
*   **Verschlüsselung (AES-128-GCM):** Alle Daten liegen nur verschlüsselt vor (Authenticated Encryption). Der Klartext landet niemals auf der Festplatte.
*   **Hardware-Schlüssel-Isolation:** Der `master.key` liegt außerhalb von Symcon auf dem Betriebssystem (z. B. auf einem USB-Stick oder einem geschützten Systemverzeichnis).
*   **Stateless UI:** Navigation und Bearbeitung finden ausschließlich im flüchtigen Arbeitsspeicher (RAM) statt. Es verbleiben keine Spuren Ihres Browser-Verlaufs in der Konfiguration.
*   **Zentralisierte Verwaltung:** Änderungen (z. B. Passwort-Updates) werden an einer einzigen Stelle (Master) vorgenommen und stehen durch die automatische Synchronisation **sofort systemweit** auf allen Slaves zur Verfügung. Dies eliminiert manuelle Pflegeaufwände und verhindert Inkonsistenzen in verteilten Umgebungen.
*   **Zero-Convention Import:** Automatische Erkennung von Ordnern ohne technische Metadaten oder spezielle Syntax. Das Modul analysiert die Form Ihres JSONs eigenständig.

---

## 2. Systemrollen (Operation Modes)
*   **Master (Sender):** Die zentrale Instanz ("Single Source of Truth"). Hier werden Daten verwaltet und sicher an Slaves verteilt.
*   **Slave (Receiver):** Empfängt verschlüsselte Updates. Lokale Änderungen am Tresor sind nicht vorgesehen und werden beim nächsten Sync überschrieben.
*   **Standalone:** Isolierter lokaler Tresor ohne Netzwerkfunktionen. Alle Synchronisations-Optionen werden automatisch ausgeblendet.

---

## 3. Konfigurations-Leitfaden (Formular-Referenz)

### 3.1 Sicherheitskonfiguration
*   **System Role:** Auswahl der Rolle (Master/Slave/Standalone).
*   **Directory Path:** Absoluter Pfad zum Verzeichnis des `master.key` (z. B. `/var/lib/symcon_keys/` oder `/secrets`).
*   **Check Directory Permissions:** Validiert, ob der Symcon-Dienst Lese- und Schreibrechte im Zielverzeichnis hat. Dies ist für die automatische Schlüsselerstellung zwingend erforderlich.

### 3.2 Synchronisation (Nur Master)
*   **Sync Token (Shared Secret):** Der "Hausschlüssel" für die Kommunikation zwischen Master und Slave.
    1.  **Generate Random Token:** Erzeugt ein sicheres, zufälliges 32-Byte Token.
    2.  **Show/Copy Token:** Zeigt das Token im Klartext an, um es in der Slave-Instanz zu hinterlegen.
    3.  **Save Token (Encrypted):** Speichert das Token verschlüsselt in der Datei `system.vault`. **Wichtig:** Ohne diesen Schritt ist keine Synchronisation möglich.
*   **Slave WebHooks (Tabelle):**
    *   **Server (Label):** Anzeigename für Ihre Übersicht (z. B. "Ferienhaus").
    *   **URL:** Ziel-WebHook des Slaves (Format: `https://[IP-oder-DNS]/hook/secrets_[ID]`).
    *   **TLS Mode:** *Strict* (CA-validiert) oder *Pinned* (validiert via SHA-256 Fingerprint, ideal für selbstsignierte Zertifikate im lokalen Netzwerk).
    *   **Key Provisioning:** Legt fest, ob der `master.key` bei jedem Sync mitgesendet wird (*Sync Payload*).
*   **Basic-Auth Passwords:** Im ausklappbaren Bereich können Passwörter für die Slave-WebHooks verschlüsselt hinterlegt werden (integrierter Passwort-Manager für Slaves).

### 3.3 Actions & Wartung
*   **Manually Sync to Slaves:** Stößt sofort eine Übertragung an alle Slaves in der Liste an.
*   **Rotate Encryption Key:** Erzeugt einen neuen Master-Key und verschlüsselt den gesamten Tresor sowie alle System-Geheimnisse mit dem neuen Schlüssel um.

---

## 4. Tresor-Explorer (Bedienung)

### 4.1 Navigation & Hybride Strukturen
Das Modul erkennt automatisch die Struktur Ihrer Daten:
*   **Ordner (📁):** Knoten, die Unterelemente (Arrays) enthalten.
*   **Datensätze (🔑):** Knoten mit reinen Datenfeldern (User, PW, etc.).
*   **Hybrid-Modus:** Ein Ordner kann eigene Felder besitzen (z. B. Standort-Informationen) **und** gleichzeitig Unterordner enthalten. Diese Felder erscheinen oben unter dem Bereich „🔑 FELDER DIESES ORDNER“.
*   **⚙️ / 🗑️:** Symbole zum Öffnen des Detail-Editors (Popup) oder zum Löschen eines Elements.

### 4.2 Erstellung & Import
*   **NEU AN DIESER POSITION:** Name für das Element eingeben und Typ wählen. Schrägstriche (/) sind im Namen verboten.
*   **JSON IMPORT:** Erlaubt das Einlesen beliebiger JSON-Arrays. Die Struktur wird automatisch analysiert und im Explorer korrekt "hydriert".

---

## 5. PHP API (Skript-Nutzung)
```php
$id = 59597; // Instanz-ID des SecretsManager

// 1. Ein Secret via Pfad auslesen
$pass = SEC_GetSecret($id, "Standorte/Produktion/SPS_Passwort");

// 2. Alle verfügbaren Schlüssel der aktuellen Ebene auflisten
$keys = json_decode(SEC_GetKeys($id), true);
```

***
***

# 🔐 SymconSecrets - Documentation (V 2.5)

## 1. The Core Problem & Solution
By default, IP-Symcon stores all configurations and variables in plaintext within the `settings.json` file. This creates significant security risks for backups, unauthorized file access, or when working in distributed systems.

**SymconSecrets** solves this via a "Zero-Knowledge" principle and provides significant operational advantages:
*   **Encryption (AES-128-GCM):** All data is stored in encrypted form only (Authenticated Encryption). Plaintext never touches the disk.
*   **Hardware Key Isolation:** The `master.key` is stored on the host OS, physically isolated from Symcon (e.g., on a USB stick or a protected system directory).
*   **Stateless UI:** Navigation and editing happen exclusively in volatile memory (RAM). No trace of your browsing history remains in the configuration.
*   **Centralized Management:** Updates (e.g., password changes) are made at a single point of truth (Master) and are **immediately available system-wide** across all linked Slaves through automatic synchronization. This eliminates manual maintenance and prevents inconsistencies in distributed environments.
*   **Zero-Convention Import:** Automatic folder detection without technical metadata or special syntax. The module analyzes the shape of your JSON independently.

---

## 2. System Roles (Operation Modes)
*   **Master (Sender):** The central instance ("Single Source of Truth"). Manages data and pushes it securely to Slaves.
*   **Slave (Receiver):** Receives encrypted updates. Local edits to the vault are not intended and will be overwritten during the next sync.
*   **Standalone:** Isolated local vault without network features. All synchronization options are automatically hidden.

---

## 3. Configuration Guide (Form Reference)

### 3.1 Security Configuration
*   **System Role:** Choose your role (Master/Slave/Standalone).
*   **Directory Path:** Absolute path to the `master.key` directory (e.g., `/var/lib/symcon_keys/` or `/secrets`).
*   **Check Directory Permissions:** Validates that the Symcon service has R/W access to the target directory. This is mandatory for automatic key generation.

### 3.2 Synchronization (Master Only)
*   **Sync Token (Shared Secret):** The "house key" for communication between Master and Slave.
    1.  **Generate Random Token:** Creates a secure, random 32-byte token.
    2.  **Show/Copy Token:** Displays the token in plaintext for entry into the Slave instance.
    3.  **Save Token (Encrypted):** Stores the token encrypted in the `system.vault` file. **Important:** Synchronization is not possible without this step.
*   **Slave WebHooks (Table):**
    *   **Server (Label):** Display name for your overview (e.g., "Holiday Home").
    *   **URL:** The Slave's WebHook URL (Format: `https://[IP-or-DNS]/hook/secrets_[ID]`).
    *   **TLS Mode:** *Strict* (CA-validated) or *Pinned* (validated via SHA-256 fingerprint, ideal for self-signed certificates in a local network).
    *   **Key Provisioning:** Determines if the `master.key` is included in every sync (*Sync Payload*).
*   **Basic-Auth Passwords:** Passwords for the Slave WebHooks can be stored encrypted in the expansion panel (integrated password manager for Slaves).

### 3.3 Actions & Maintenance
*   **Manually Sync to Slaves:** Triggers an immediate push to all slaves in the list.
*   **Rotate Encryption Key:** Generates a new master key and re-encrypts the entire vault and all system secrets with the new key.

---

## 4. Vault Explorer Usage

### 4.1 Navigation & Hybrid Structures
The module automatically detects the structure of your data:
*   **Folders (📁):** Nodes containing sub-elements (arrays).
*   **Records (🔑):** Nodes containing only data fields (User, PW, etc.).
*   **Hybrid Mode:** A folder can hold its own fields (e.g., location information) **and** simultaneously contain sub-folders. These fields appear at the top under the "🔑 FOLDER FIELDS" section.
*   **⚙️ / 🗑️:** Icons to open the detail editor (popup) or delete an item.

### 4.2 Creation & Import
*   **NEW AT THIS POSITION:** Enter a name for the element and select the type. Slashes (/) are forbidden in names.
*   **JSON IMPORT:** Allows importing any standard JSON array. The structure is automatically analyzed and correctly "hydrated" in the Explorer.

---

## 5. PHP API (Script Usage)
```php
$id = 59597; // Instance ID of the SecretsManager

// 1. Retrieve a secret via path
$pass = SEC_GetSecret($id, "Locations/Production/PLC_Password");

// 2. List all available keys at the current level
$keys = json_decode(SEC_GetKeys($id), true);
```
