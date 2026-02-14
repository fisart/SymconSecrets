SymconSecrets – Dokumentation
1. Warum benötigt man dieses Modul in IP-Symcon?

Standardmäßig speichert IP-Symcon alle Variableninhalte, Skripte und Konfigurationen in der Datei settings.json. Dies führt zu folgenden Sicherheitsproblemen:

Klartext-Speicherung: Passwörter für Dienste (Spotify, MQTT, Datenbanken, Kameras) stehen im Klartext in der Einstellungsdatei.

Unsichere Backups: Ein Backup des Systems enthält automatisch alle Passwörter. Wer Zugriff auf das Backup hat, hat Zugriff auf alle Ihre Konten.

Sichtbarkeit: Jeder Benutzer mit Zugriff auf die IP-Symcon Verwaltungskonsole kann die Passwörter in den Skripten oder Variablen lesen.

Verwaltungsaufwand: Bei verteilten Systemen müssen Passwörter auf jedem System manuell gepflegt werden.

2. Wie werden diese Probleme beseitigt?

Das Modul SymconSecrets adressiert diese Risiken durch ein „Zero-Knowledge“-Konzept:

Verschlüsselung: Alle Geheimnisse werden mit AES-128-GCM verschlüsselt. In der Datenbank liegt nur unlesbarer Datensalat („Blob“).

Hardware-Trennung (Schlüssel-Isolation): Der Entschlüsselungs-Key (master.key) liegt als physische Datei auf dem Betriebssystem (z.B. USB-Stick oder geschützter Ordner), getrennt von der Symcon-Datenbank.

NEU: Stateless Editor (Sicherheits-Update): Im Gegensatz zu herkömmlichen Modulen speichert SymconSecrets die Passwörter während der Eingabe nicht in den Instanz-Eigenschaften ab. Die Daten werden direkt vom Browser in den Arbeitsspeicher (RAM) des Servers übertragen. Dadurch landen Passwörter zu keinem Zeitpunkt unverschlüsselt in der settings.json.

3. Wie funktioniert das Modul?

Das Modul arbeitet nach dem Tresor-Prinzip:

Der Tresor (Vault): Eine String-Variable in IP-Symcon, die das verschlüsselte JSON-Paket enthält.

Der Schlüssel (Master Key): Eine Datei (master.key), die lokal auf dem Server liegt.

Der Zugriff (In-Memory):

Die Entschlüsselung findet ausschließlich im Arbeitsspeicher (RAM) statt.

Stateless UI: Wenn Sie den Editor öffnen, wird das JSON-Objekt im Browser angezeigt. Sobald Sie die Konsole schließen, wird der Klartext im RAM gelöscht. Es erfolgt keine Speicherung auf der Festplatte, solange die Daten nicht verschlüsselt wurden.

Synchronisation (Master -> Slave): Der Master sendet das verschlüsselte Paket über einen WebHook an die Slaves (abgesichert via HTTPS, Sync Token und optional Basic Auth).

4. Wie wird es konfiguriert?
Schritt A: Einrichtung des Masters (Sender)

Instanz SecretsManager erstellen und Rolle Master wählen.

Verzeichnispfad: Pfad für den master.key angeben (z.B. /var/lib/symcon_keys/).

Sync Token: Generieren und kopieren.

Geheimnisse eingeben: JSON-Objekt in den Editor einfügen.

Hinweis: Durch die Stateless-Technologie müssen Sie nach der Eingabe auf "Encrypt & Save Local" klicken. Wenn Sie das Formular ohne Speichern schließen, wird die Eingabe aus Sicherheitsgründen verworfen.

Schritt B: Einrichtung eines Slaves (Empfänger)

Instanz auf dem Zielsystem erstellen, Rolle Slave wählen.

Pfad und denselben Sync Token wie beim Master hinterlegen.

WebHook URL notieren.

Schritt C: Verknüpfung

URL des Slaves im Master unter „Slave WebHooks“ eintragen.

„Manually Sync to Slaves“ anklicken.

Hier ist die detaillierte Ergänzung für Ihre Dokumentation, welche die neue **Passkey-Funktionalität** (Biometrie) umfassend beschreibt.

---

# 🔐 Biometrische Authentifizierung (Passkeys)

## 1. Übersicht
Die Passkey-Funktion ermöglicht es Ihnen, den Zugriff auf den Tresor oder eigene WebHook-Skripte durch biometrische Merkmale (Fingerabdruck, Gesichtserkennung oder Windows Hello) zu schützen. Dies ersetzt die manuelle Eingabe von Passwörtern durch einen sicheren kryptografischen Handshake (WebAuthn/FIDO2).

### Sicherheitsmerkmale:
*   **Hardware-gebunden:** Der private Schlüssel verlässt niemals Ihr Gerät (Smartphone oder PC).
*   **Zero-Knowledge:** Im Tresor wird lediglich der öffentliche Schlüssel im versteckten Ordner `__AUTH__` gespeichert.
*   **Zustandslos:** Die Authentifizierung erfolgt im RAM-Buffer und ist an Ihre IP-Adresse und Ihren Browser gebunden.

---

## 2. Einrichtung (Registrierung)

Bevor Sie ein Gerät nutzen können, muss es einmalig verknüpft werden. Dieser Vorgang ist durch ein spezielles Passwort geschützt, das Sie selbst im Tresor festlegen.

### Schritt 1: Registrierungs-Passwort festlegen
1. Öffnen Sie den **Tresor-Explorer** in IP-Symcon.
2. Erstellen Sie auf der obersten Ebene (**root**) einen neuen Record mit dem Namen: `RegistrationPassword`.
3. Öffnen Sie diesen Record (⚙️) und fügen Sie ein Feld hinzu:
   *   Name: `PW`
   *   Wert: Ein starkes Passwort Ihrer Wahl (z. B. `mein-sicherer-schluessel`).
4. Klicken Sie auf **💾 Speichern**.

### Schritt 2: Gerät verknüpfen
Rufen Sie die Registrierungs-URL auf dem Gerät auf, das Sie hinzufügen möchten (Smartphone oder PC). **Wichtig: Dies funktioniert nur über eine verschlüsselte HTTPS-Verbindung!**

**URL-Format:**
`https://[Ihre-Symcon-URL]/hook/secrets_[ID]?register=1&pass=[Ihr-PW]`

**Beispiel:**
`https://08a32d3d...ipmagic.de/hook/secrets_59597?register=1&pass=mein-sicherer-schluessel`

Folgen Sie den Anweisungen im Browser und berühren Sie den Sensor Ihres Geräts. Nach der Meldung „✅ Gerät erfolgreich registriert!“ ist das Gerät hinterlegt.

---

## 3. Nutzung im Alltag

### 3.1 Login-Portal
Sie können das Portal nutzen, um eine Sitzung für Ihren Browser zu starten.
**URL-Format:**
`https://[Ihre-Symcon-URL]/hook/secrets_[ID]?portal=1`

Nach erfolgreichem Scan ist Ihr Browser für 60 Minuten (Standard) autorisiert.

### 3.2 Integration in eigene Skripte
Sie können die biometrische Prüfung in jedes beliebige WebHook-Skript einbauen. Wenn ein Benutzer nicht eingeloggt ist, wird er automatisch zum Biometrie-Portal umgeleitet und kehrt nach dem Scan zu Ihrem Skript zurück.

**Beispiel-Skript:**
```php
<?php
$instanceID = 59597; // ID Ihrer SecretsManager Instanz

// Prüfen, ob der Browser biometrisch autorisiert ist
if (!SEC_IsPortalAuthenticated($instanceID)) {
    // Falls nicht, Weiterleitung zum Login-Portal mit Rücksprung-URL
    $currentUrl = $_SERVER['REQUEST_URI'];
    $loginUrl = "/hook/secrets_" . $instanceID . "?portal=1&return=" . urlencode($currentUrl);
    
    header("Location: " . $loginUrl);
    exit;
}

// Ab hier ist der Zugriff sicher
echo "Willkommen! Ihr Zugriff wurde biometrisch verifiziert.";
```

# 🛠️ Fortgeschrittene Administration & Biometrie-Verbund

## 1. Das Admin-Dashboard
Das Admin-Dashboard ist eine zentrale Steuerseite, die über den WebHook aufgerufen werden kann. Es dient dazu, Registrierungs-Links für alle im System befindlichen Master- und Slave-Instanzen automatisch zu generieren.

### 1.1 Zugriffsschutz (Zweistufig)
Der Zugriff auf das Dashboard ist besonders geschützt:
*   **Erst-Login:** Erfolgt über ein spezielles Admin-Passwort in der URL: 
    `?admin=1&pass=[AdminPortal-Passwort]`
*   **Folge-Logins:** Sobald ein Gerät einmal per Passwort autorisiert wurde, erkennt das Modul die biometrische Sitzung. Zukünftige Aufrufe benötigen nur noch den Fingerabdruck/Passkey über `?admin=1`.

---

## 2. Sicherheits-Architektur (Zwei-Passwort-Konzept)
Um maximale Sicherheit zu gewährleisten, nutzt das System zwei getrennte Passwörter im Tresor:

1.  **AdminPortal (Record `AdminPortal` -> Feld `PW`):**
    *   **Zweck:** Schützt das Dashboard.
    *   **Sicherheit:** Sollte niemals geteilt werden. Ermöglicht den Zugriff auf alle System-Links.
2.  **RegistrationPassword (Record `RegistrationPassword` -> Feld `PW`):**
    *   **Zweck:** Schützt den eigentlichen Registrierungs-Vorgang eines neuen Geräts.
    *   **Sicherheit:** Dieses Passwort ist Teil der Registrierungs-Links (`?register=1&pass=...`).

---

## 3. Passkeys in verteilten Systemen (Master/Slave)
Passkeys sind aus Sicherheitsgründen kryptografisch an eine exakte **Domain (URL)** gebunden.

### 3.1 Das Multi-Domain-Prinzip
Wenn Sie einen Master und mehrere Slaves (mit unterschiedlichen URLs) betreiben, muss ein Gerät für **jede URL einmal registriert** werden. Ein Key für `master.ipmagic.de` wird vom Browser niemals für `slave.ipmagic.de` herausgegeben.

### 3.2 Intelligente Synchronisation (Merging)
Damit der Master beim Synchronisieren nicht die mühsam registrierten Passkeys auf den Slaves löscht, verfügt das Modul über eine **Merging-Logik**:
*   Der Slave empfängt die Passwörter vom Master.
*   Der Slave erkennt seine lokal registrierten Geräte (`__AUTH__`-Ordner).
*   Das Modul führt beide Datensätze zusammen.
*   **Ergebnis:** Lokale biometrische Schlüssel bleiben auf dem jeweiligen System dauerhaft erhalten, auch wenn der Master ein Update sendet.

---

## 4. Nutzung im Betrieb

### Einbindung in Skripte
Verwenden Sie die Funktion `SEC_IsPortalAuthenticated($id)`, um WebHook-Skripte zu schützen. Das Modul prüft automatisch die IP-Adresse und den Browser-Typ, um Sitzungshijacking zu verhindern.

### Synchronisation der Passkeys
Falls Sie einen Cloud-Passwortmanager (Google, Apple, Microsoft) nutzen, werden erstellte Passkeys automatisch zwischen Ihren Geräten synchronisiert. Eine erneute Registrierung für ein Tablet oder ein zweites Handy ist in diesem Fall oft nicht notwendig.

---

English Summary (Updated)

SymconSecrets is a secure credential manager for IP-Symcon that encrypts secrets using AES-128-GCM.

Key Features

Zero-Knowledge Storage: Encrypted blobs in the database; plaintext never hits the disk.

Hardware Separation: Master Key is stored on the OS file system, not in the Symcon settings.

Stateless Editor (New): Plaintext secrets are transmitted directly from the browser to the server's RAM. They are never stored as module properties, ensuring that settings.json remains free of sensitive cleartext even during the configuration phase.

Auto-Sync: Automated, secure distribution from Master to multiple Slaves.

Security Note on Stateless UI

Because secrets are not stored in module properties, unsaved changes in the JSON editor will be lost if the management console is closed before clicking "Encrypt & Save". This is a deliberate security feature to prevent accidental cleartext leaks to the file system.

PHP Usage (API)
code
PHP
download
content_copy
expand_less
$instanceID = 12345;

// Get a single password
$password = SEC_GetSecret($instanceID, 'Spotify');

// Get a complex configuration array
$config = json_decode(SEC_GetSecret($instanceID, 'MySQL_Config'), true);

// List all available keys
$keys = json_decode(SEC_GetKeys($instanceID), true);
---
---

# 🔐 Biometric Authentication (Passkeys)

## 1. Overview
The Passkey feature allows you to protect access to your vault or custom WebHook scripts using biometrics (fingerprint, face recognition, or Windows Hello). This replaces manual password entry with a secure cryptographic handshake (WebAuthn/FIDO2).

### Security Features:
*   **Hardware-Bound:** The private key never leaves your device (smartphone or PC).
*   **Zero-Knowledge:** Only the public key is stored in your vault within the hidden `__AUTH__` folder.
*   **Stateless:** Authentication is managed in a RAM buffer and is tied to your IP address and browser.

---

## 2. Setup (Registration)

Before you can use a device, it must be linked once. This process is protected by a special password that you define yourself within the vault.

### Step 1: Define the Registration Password
1. Open the **Vault Explorer** in IP-Symcon.
2. At the top level (**root**), create a new record named: `RegistrationPassword`.
3. Open this record (⚙️) and add a field:
   *   Name: `PW`
   *   Value: A strong password of your choice (e.g., `my-secure-key`).
4. Click **💾 Save**.

### Step 2: Link your Device
Open the registration URL on the device you want to add (smartphone or PC). **Important: This only works over an encrypted HTTPS connection!**

**URL Format:**
`https://[Your-Symcon-URL]/hook/secrets_[ID]?register=1&pass=[Your-PW]`

**Example:**
`https://08a32d3d...ipmagic.de/hook/secrets_59597?register=1&pass=my-secure-key`

Follow the instructions in the browser and touch your device's sensor. Once the message "✅ Device successfully registered!" appears, your device is linked.

---

## 3. Daily Usage

### 3.1 Login Portal
You can use the portal to start a session for your browser.
**URL Format:**
`https://[Your-Symcon-URL]/hook/secrets_[ID]?portal=1`

After a successful scan, your browser is authorized for 60 minutes (default).

### 3.2 Integration into Custom Scripts
You can integrate biometric verification into any WebHook script. If a user is not logged in, they will be automatically redirected to the Biometric Portal and returned to your script after the scan.

**Example Script:**
```php
<?php
$instanceID = 59597; // ID of your SecretsManager instance

// Check if the browser is biometrically authorized
if (!SEC_IsPortalAuthenticated($instanceID)) {
    // If not, redirect to the Login Portal with a return URL
    $currentUrl = $_SERVER['REQUEST_URI'];
    $loginUrl = "/hook/secrets_" . $instanceID . "?portal=1&return=" . urlencode($currentUrl);
    
    header("Location: " . $loginUrl);
    exit;
}

// Access is secure beyond this point
echo "Welcome! Your access has been biometrically verified.";
```
---

# 🛠️ Advanced Administration & Biometric Federation (English)

## 1. The Admin Dashboard
The Admin Dashboard is a centralized management page accessible via WebHook. It automatically generates registration links for all configured Master and Slave instances within your federation.

### 1.1 Access Control (Two-Tier)
Access to the dashboard is strictly regulated:
*   **First-time Access:** Authorized via a dedicated Admin password in the URL:
    `?admin=1&pass=[AdminPortal-Password]`
*   **Subsequent Access:** Once a device has been authorized via password, the module establishes a biometric link. Future visits only require a fingerprint/Passkey scan via `?admin=1`.

---

## 2. Security Architecture (Two-Password Concept)
For maximum security, the system utilizes two distinct passwords stored within the vault:

1.  **AdminPortal (Record `AdminPortal` -> Field `PW`):**
    *   **Purpose:** Protects the Admin Dashboard.
    *   **Security:** Should never be shared. Grants access to all system-wide registration links.
2.  **RegistrationPassword (Record `RegistrationPassword` -> Field `PW`):**
    *   **Purpose:** Protects the actual device enrollment process.
    *   **Security:** This password is embedded in the enrollment links (`?register=1&pass=...`).

---

## 3. Passkeys in Distributed Environments (Master/Slave)
For anti-phishing security, Passkeys are cryptographically bound to a specific **Domain (URL)**.

### 3.1 Multi-Domain Principle
When operating a Master and multiple Slaves (using different URLs), a device must be **registered once for every URL**. A browser will never provide a key registered for `master.ipmagic.de` to the site `slave.ipmagic.de`.

### 3.2 Intelligent Synchronization (Merging)
To prevent the Master from overwriting locally registered Passkeys on Slaves during a sync, the module implements **Merging Logic**:
*   The Slave receives password updates from the Master.
*   The Slave identifies its locally registered devices (stored in the `__AUTH__` folder).
*   The module merges both datasets.
*   **Result:** Local biometric keys are preserved on each specific system, even after a full sync from the Master.

---

## 4. Operational Usage

### Script Integration
Use the `SEC_IsPortalAuthenticated($id)` function to protect your custom WebHook scripts. The module automatically validates the IP address and Browser Agent to prevent session hijacking.

### Passkey Synchronization
If you use a cloud-based password manager (Google, Apple, Microsoft), your Passkeys are automatically synchronized across your devices. In such cases, re-registering for a tablet or a second smartphone is usually not required.

---
