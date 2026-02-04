# 🔐 SymconSecrets - Dokumentation (V 2.5)

## 1. Das Problem & Die Lösung
Standardmäßig speichert IP-Symcon alle Konfigurationen und Variablen im Klartext in der `settings.json`. Dies führt zu Sicherheitsrisiken bei Backups und unbefugtem Dateizugriff. 

**SymconSecrets** löst dies durch ein „Zero-Knowledge“-Prinzip:
*   **Verschlüsselung (AES-128-GCM):** Alle Daten liegen nur verschlüsselt vor.
*   **Hardware-Schlüssel-Isolation:** Der `master.key` liegt außerhalb von Symcon auf dem Betriebssystem.
*   **Stateless UI:** Navigation und Bearbeitung finden nur im flüchtigen RAM statt.
*   **Zero-Convention Import:** Automatische Erkennung von Ordnern ohne technische Metadaten.

---

## 2. Systemrollen (Operation Modes)
*   **Master (Sender):** Die zentrale Instanz ("Single Source of Truth"). Hier werden Daten verwaltet und an Slaves verteilt.
*   **Slave (Receiver):** Empfängt verschlüsselte Updates. Lokale Änderungen werden beim nächsten Sync überschrieben.
*   **Standalone:** Isolierter lokaler Tresor ohne Netzwerkfunktionen.

---

## 3. Konfigurations-Leitfaden (Das Formular)

### 3.1 Sicherheitskonfiguration
*   **System Role:** Auswahl der Rolle (Master/Slave/Standalone).
*   **Directory Path:** Absoluter Pfad zum Verzeichnis des `master.key` (z. B. `/var/lib/symcon_keys/`).
*   **Check Directory Permissions:** Validiert, ob der Symcon-Dienst Lese- und Schreibrechte hat. Dies ist für die automatische Schlüsselerstellung zwingend.

### 3.2 Synchronisation (Nur Master)
*   **Sync Token (Shared Secret):** Der "Hausschlüssel" für die Kommunikation.
    1.  **Generate Random Token:** Erzeugt ein sicheres 32-Byte Token.
    2.  **Show/Copy Token:** Zeigt das Token zum Kopieren für die Slave-Instanz an.
    3.  **Save Token (Encrypted):** Speichert das Token verschlüsselt in der `system.vault` Datei. **Wichtig:** Ohne Speicherung ist kein Sync möglich.
*   **Slave WebHooks (Tabelle):**
    *   **Server (Label):** Anzeigename (z. B. "Standort A").
    *   **URL:** Ziel-WebHook des Slaves (`https://[IP]/hook/secrets_[ID]`).
    *   **TLS Mode:** *Strict* (CA-validiert) oder *Pinned* (validiert via SHA-256 Fingerprint, ideal für selbstsignierte Zertifikate).
    *   **Key Provisioning:** Legt fest, ob der `master.key` aktiv mitgesendet wird.
*   **Basic-Auth Passwords:** Im ausklappbaren Bereich werden Passwörter für die Slave-WebHooks verschlüsselt hinterlegt.

### 3.3 Actions & Wartung
*   **Manually Sync to Slaves:** Sofortiger Push-Vorgang an alle Slaves.
*   **Rotate Encryption Key:** Erzeugt einen neuen Master-Key und verschlüsselt den gesamten Tresor sowie alle System-Geheimnisse neu.

---

## 4. Tresor-Explorer (Bedienung)

### 4.1 Navigation & Hybride Strukturen
Das Modul erkennt automatisch die Struktur:
*   **Ordner (📁):** Knoten mit Unterelementen.
*   **Datensätze (🔑):** Knoten mit reinen Datenfeldern (User, PW, etc.).
*   **Hybrid-Modus:** Ein Ordner kann eigene Felder besitzen (z. B. Standort-Infos) **und** Unterordner enthalten. Diese Felder erscheinen oben unter „🔑 FELDER DIESES ORDNER“.
*   **⚙️ / 🗑️:** Symbole zum Öffnen des Detail-Editors oder zum Löschen.

### 4.2 Erstellung & Import
*   **NEU AN DIESER POSITION:** Name eingeben und Typ wählen. Schrägstriche (/) sind im Namen verboten.
*   **JSON IMPORT:** Erlaubt das Einlesen beliebiger JSON-Arrays. Die Struktur wird automatisch analysiert und "hydriert".

---

## 5. PHP API
```php
$id = 12345;
// Secret via Pfad auslesen
$pass = SEC_GetSecret($id, "Standorte/Berlin/MQTT_Pass");
// Alle Schlüssel der aktuellen Ebene auflisten
$keys = json_decode(SEC_GetKeys($id), true);
```

---
---

# 🔐 SymconSecrets - Documentation (V 2.5)

## 1. The Core Concept
IP-Symcon stores data in plaintext within `settings.json`. SymconSecrets mitigates this risk by ensuring sensitive data is only stored in encrypted form and handled in volatile memory.

## 2. System Roles
*   **Master:** Source of truth, manages and pushes data to Slaves.
*   **Slave:** Mirror instance, receives updates via WebHook.
*   **Standalone:** Isolated local vault with no network connectivity.

## 3. Configuration Guide (The Form)

### 3.1 Security Configuration
*   **Directory Path:** Absolute OS path for the `master.key` (e.g., `/secrets`).
*   **Check Directory Permissions:** Ensures Symcon has R/W access to initialize the key file.

### 3.2 Synchronization (Master Only)
*   **Sync Token:** Generate, Copy (to Slave), and **Save** (to encrypt it into the system vault).
*   **Slave WebHooks:**
    *   **TLS Mode:** Use *Strict* for CA certificates or *Pinned* for self-signed certificates (requires SHA-256 fingerprint).
    *   **Key Provisioning:** Determines if the `master.key` is included in the sync payload.
*   **Basic-Auth Passwords:** Securely link passwords to slave URLs via the expansion panel.

### 3.3 Actions
*   **Manually Sync:** Immediate push to all slaves.
*   **Rotate Encryption Key:** Re-encrypts the entire vault and system data with a newly generated key.

## 4. Vault Explorer Usage

### 4.1 Hybrid Logic & Navigation
*   **Zero-Convention Detection:** Folders are detected automatically based on JSON hierarchy.
*   **Hybrid Nodes:** Folders can hold their own data fields (displayed at the top) while acting as a container for sub-items.
*   **Navigation:** Use icons to drill down (📁/🔑) and the "BACK" button to navigate up.

### 4.2 Creation & Import
*   **NEW ITEM:** Enter a name (no slashes allowed) and select Folder or Record.
*   **JSON IMPORT:** Paste standard JSON structures to overwrite and automatically hydrate the vault.

## 5. PHP API
```php
$id = 12345;
$pass = SEC_GetSecret($id, "Locations/London/Wifi_Pass");
$keys = json_decode(SEC_GetKeys($id), true);
```
