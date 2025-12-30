## SymconSecrets – Dokumentation (aktueller Funktionsstand)

### 1. Warum benötigt man dieses Modul in IP-Symcon?

Standardmäßig speichert IP-Symcon Variableninhalte und Instanz-Konfigurationen in der Datei `settings.json` (und damit auch in Backups). Daraus ergeben sich typische Risiken:

* **Klartext-Speicherung:** Passwörter/Token können im Klartext in Konfigurationen oder Variablen auftauchen.
* **Unsichere Backups:** Backups enthalten Konfigurationen – wer Zugriff hat, kann ggf. Secrets auslesen.
* **Sichtbarkeit:** Admins/Benutzer mit Konsolen-Zugriff können Inhalte sehen.
* **Verteilte Systeme:** Mehrere Symcon-Instanzen erfordern sonst manuelle Pflege.

---

### 2. Wie werden diese Probleme beseitigt?

SymconSecrets folgt einem **„Zero-Knowledge“-Prinzip**:

* **Verschlüsselung (AES-128-GCM):** Secrets liegen in IP-Symcon nur als verschlüsselter Blob vor (Vault).
* **Schlüssel-Isolation:** Der Entschlüsselungs-Key liegt **nicht** in Symcon, sondern als Datei `master.key` im OS-Dateisystem (z.B. geschützter Ordner).
* **Stateless Editor:** Der Editor arbeitet ohne Property-Zwischenspeicherung. Inhalte werden nur im RAM angezeigt/bearbeitet und nur nach „Encrypt & Save“ dauerhaft (verschlüsselt) gespeichert.
* **Zusätzliche System-Secrets ausgelagert:** Secrets, die früher typischerweise in Properties lagen (z.B. Sync-Token, WebHook-Passwort, Slave-Basic-Auth-Passwörter), werden **verschlüsselt in einer separaten Datei** `system.vault` gespeichert (ebenfalls AES-GCM).

> Ergebnis: **keine Passwörter/Token in der `settings.json`**, sofern du die vorgesehenen “Save … (encrypted)” Buttons nutzt.

---

### 3. Wie funktioniert das Modul?

#### 3.1 Der Tresor (Vault)

* **`Vault`** ist eine (versteckte) Symcon-Variable, die ein verschlüsseltes JSON-Paket enthält:

  * Cipher: `aes-128-gcm`
  * IV + Tag + Ciphertext
* Der Klartext-Vault ist ein JSON-Objekt (frei strukturierbar), das du im Editor bearbeiten kannst.

#### 3.2 Der Schlüssel (master.key)

* Der AES-Key wird als Datei `master.key` im angegebenen Verzeichnis gespeichert.
* Master/Standalone erzeugen den Key automatisch, falls noch keiner existiert (Verzeichnis muss schreibbar sein).
* Slaves benötigen den Key abhängig von der gewählten Key-Provisioning-Strategie (siehe Sync).

#### 3.3 System-Secrets (system.vault)

* **`system.vault`** ist eine Datei im selben Key-Verzeichnis wie `master.key`.
* Darin liegen verschlüsselt (AES-GCM) z.B.:

  * **Sync Token**
  * **WebHook Basic-Auth Password (Slave)**
  * **Per-Slave Basic-Auth Passwords (Master-Mapping nach URL)**

#### 3.4 Stateless UI / In-Memory

* Beim „Unlock & Load“ wird der Vault entschlüsselt und in der UI angezeigt.
* Wird die Konsole geschlossen oder „Cancel/Wipe“ genutzt, wird Klartext verworfen (RAM/Buffer).
* Dauerhaft gespeichert wird erst beim Klick auf **„Encrypt & Save“**.

#### 3.5 Synchronisation (Master → Slaves)

* Master sendet an jeden Slave per WebHook ein Paket mit:

  * `auth` (Sync Token)
  * `vault` (verschlüsselter Vault)
  * optional `key` (nur wenn Key-Transport aktiviert und erlaubt)
* Schutz:

  * Sync-Token (Shared Secret)
  * optional **Basic Auth** pro Slave
  * TLS-Optionen pro Slave:

    * **HTTP (no TLS)**
    * **HTTPS Strict**
    * **HTTPS Pinned** (Fingerprint)

**Wichtige Policy (aktueller Stand):**

* **KeyTransport = manual → SKIP** (Slave bleibt funktional mit altem Stand)
* **KeyTransport = sync + TLS=http → SKIP** (Key wird niemals über unsicheren Transport gesendet)
* **KeyTransport = sync + TLS=strict/pinned → Sync erlaubt (Key wird gesendet)**

---

### 4. Konfiguration

#### Schritt A: Master (Sender)

1. Instanz erstellen → **System Role: Master**
2. **KeyFolderPath** setzen (z.B. `/var/lib/symcon_keys/`)
3. **Sync Token**

   * „Generate Random Token“ (nur Master sichtbar)
   * Token in `AuthTokenInput` einfügen/prüfen
   * „Save Token (encrypted)“ → Speicherung verschlüsselt in `system.vault`
4. Vault pflegen

   * „Unlock & Load Data“
   * JSON bearbeiten
   * „Encrypt & Save“ (speichert verschlüsselt in `Vault`)
5. Slaves konfigurieren

   * In „Slave WebHooks“ pro Slave:

     * Server-Label
     * URL
     * TLS Mode
     * Key Provisioning (manual/sync)
     * Fingerprint (nur pinned)
     * User (optional)
   * Für Slave-Basic-Auth-Passwörter:

     * ExpansionPanel „Store per-Slave Basic-Auth Passwords“
     * Slave auswählen
     * Passwort eingeben
     * „Save Slave Password (encrypted)“

#### Schritt B: Slave (Receiver)

1. Instanz erstellen → **System Role: Slave**
2. **KeyFolderPath** setzen (für `master.key` und `system.vault`)
3. **Sync Token** (vom Master kopieren)

   * in `AuthTokenInput` eintragen
   * „Save Token (encrypted)“
4. Optional: WebHook Basic Auth für eingehende Sync-Requests

   * `HookUser` setzen
   * `HookPassInput` eingeben
   * „Save WebHook Password (encrypted)“
5. WebHook URL steht im Feld „WebHook URL … /hook/secrets_XXXXX“

#### Schritt C: Sync auslösen

* Master: „Manually Sync to Slaves“
* Ergebnis pro Slave im Message-Log (OK/FAIL/SKIP).

---

### 5. Key Rotation (nur Master/Standalone)

* Master/Standalone bietet einen Button **„Rotate Encryption Key“** (Master/Standalone sichtbar).
* Ablauf:

  * Vault und system.vault werden mit altem Key im RAM entschlüsselt
  * neuer `master.key` wird atomar gesetzt
  * Vault und system.vault werden mit neuem Key neu verschlüsselt
  * optional Sync (je nach Implementierung)
* **Bei manual-Slaves erfolgt kein Update (SKIP)**, damit sie stabil bleiben.

---

Beispiel Passwort Array

$vault = [
  "Spotify" => [
    "User" => "artur@example.com",
    "PW" => "S3cure!Spotify#2025",
    "URL" => "https://accounts.spotify.com",
    "Location" => "Hermitage",
    "IP" => "0.0.0.0"
  ],
  "MySQL_Prod" => [
    "User" => "db_admin",
    "PW" => "T9$kL!2zQp#7",
    "URL" => "mysql://10.10.20.15:3306",
    "Location" => "Berlin",
    "IP" => "10.10.20.15"
  ],
  "Camera_NVR" => [
    "User" => "nvr",
    "PW" => "Nvr-8h*P!44",
    "URL" => "http://192.168.1.50",
    "Location" => "Hermitage",
    "IP" => "192.168.1.50"
  ]
];

und hier der entsprechende JSON String

{
  "Spotify": {
    "User": "artur@example.com",
    "PW": "S3cure!Spotify#2025",
    "URL": "https://accounts.spotify.com",
    "Location": "Hermitage",
    "IP": "0.0.0.0"
  },
  "MySQL_Prod": {
    "User": "db_admin",
    "PW": "T9$kL!2zQp#7",
    "URL": "mysql://10.10.20.15:3306",
    "Location": "Berlin",
    "IP": "10.10.20.15"
  },
  "Camera_NVR": {
    "User": "nvr",
    "PW": "Nvr-8h*P!44",
    "URL": "http://192.168.1.50",
    "Location": "Hermitage",
    "IP": "192.168.1.50"
  }
}

## PHP Usage (API)

```php
$instanceID = 12345;

// Get a single secret
$password = SEC_GetSecret($instanceID, 'Spotify');

// Get a complex configuration array
$config = json_decode(SEC_GetSecret($instanceID, 'MySQL_Config'), true);

// List all available keys
$keys = json_decode(SEC_GetKeys($instanceID), true);
```



**Hinweis:** Unsaved Änderungen im JSON-Editor gehen verloren, wenn du die Konsole schließt oder „Cancel/Wipe“ nutzt. Das ist gewollt (Stateless-Sicherheitsprinzip).

## SymconSecrets – Documentation (current functional state)

### 1. Why do you need this module in IP-Symcon?

By default, IP-Symcon stores variable contents and instance configuration values in the file `settings.json` (and therefore also in backups). This leads to typical risks:

* **Plaintext storage:** Passwords/tokens can end up in configuration or variables in clear text.
* **Unsafe backups:** Backups contain configurations—anyone with access may be able to extract secrets.
* **Visibility:** Admins/users with Management Console access can view contents.
* **Distributed systems:** Multiple Symcon instances otherwise require manual secret maintenance.

---

### 2. How are these issues solved?

SymconSecrets follows a **“zero-knowledge” concept**:

* **Encryption (AES-128-GCM):** Secrets are stored in IP-Symcon only as an encrypted blob (Vault).
* **Key isolation:** The decryption key is **not** stored in Symcon. It is stored as `master.key` on the OS file system (e.g., in a protected directory).
* **Stateless editor:** The editor works without saving intermediate values in instance properties. Data is only shown/edited in RAM and is only persisted after **“Encrypt & Save”** (encrypted).
* **Additional system secrets moved out:** Secrets that would typically be stored in properties (e.g., sync token, webhook password, per-slave basic-auth passwords) are stored **encrypted in a separate file** `system.vault` (also AES-GCM).

> Result: **No passwords/tokens in `settings.json`**, as long as you use the intended “Save … (encrypted)” buttons.

---

### 3. How does the module work?

#### 3.1 The vault (Vault)

* **`Vault`** is a (hidden) Symcon variable that contains an encrypted JSON package:

  * Cipher: `aes-128-gcm`
  * IV + Tag + Ciphertext
* The plaintext vault is a freely structured JSON object that you edit in the JSON editor.

#### 3.2 The key (master.key)

* The AES key is stored as the file `master.key` inside the configured directory.
* Master/Standalone generate the key automatically if it does not exist yet (the directory must be writable).
* Slaves require the key depending on the chosen key provisioning strategy (see Sync).

#### 3.3 System secrets (system.vault)

* **`system.vault`** is a file located in the same key directory as `master.key`.
* It stores encrypted (AES-GCM) system-level secrets such as:

  * **Sync token**
  * **Webhook basic-auth password (on the slave)**
  * **Per-slave basic-auth passwords (master mapping by URL)**

#### 3.4 Stateless UI / In-memory handling

* When you click **“Unlock & Load Data”**, the vault is decrypted and shown in the UI.
* If you close the console or click **“Cancel / Wipe”**, plaintext is discarded (RAM/buffer).
* Data is persisted only when you click **“Encrypt & Save”**.

#### 3.5 Synchronization (Master → Slaves)

* The master sends a package via WebHook to each slave containing:

  * `auth` (sync token)
  * `vault` (encrypted vault)
  * optionally `key` (only if key transport is enabled and allowed)
* Protection mechanisms:

  * Sync token (shared secret)
  * optional **Basic Auth** per slave
  * per-slave TLS options:

    * **HTTP (no TLS)**
    * **HTTPS Strict**
    * **HTTPS Pinned** (fingerprint)

**Important policy (current behavior):**

* **KeyTransport = manual → SKIP** (slave stays functional with its old state)
* **KeyTransport = sync + TLS=http → SKIP** (key is never sent over an insecure transport)
* **KeyTransport = sync + TLS=strict/pinned → Sync allowed (key is sent)**

---

### 4. Configuration

#### Step A: Master (Sender)

1. Create instance → **System Role: Master**
2. Set **KeyFolderPath** (e.g., `/var/lib/symcon_keys/`)
3. **Sync token**

   * “Generate Random Token” (only visible on Master)
   * verify/insert token into `AuthTokenInput`
   * “Save Token (encrypted)” → stored encrypted in `system.vault`
4. Maintain the vault

   * “Unlock & Load Data”
   * edit JSON
   * “Encrypt & Save” (stores encrypted into `Vault`)
5. Configure slaves

   * In “Slave WebHooks” per slave:

     * Server label
     * URL
     * TLS Mode
     * Key Provisioning (manual/sync)
     * Fingerprint (pinned only)
     * User (optional)
   * For slave Basic Auth passwords:

     * Expansion panel “Store per-Slave Basic-Auth Passwords”
     * select slave
     * enter password
     * “Save Slave Password (encrypted)”

#### Step B: Slave (Receiver)

1. Create instance → **System Role: Slave**
2. Set **KeyFolderPath** (for `master.key` and `system.vault`)
3. **Sync token** (copied from the master)

   * enter into `AuthTokenInput`
   * click “Save Token (encrypted)”
4. Optional: WebHook Basic Auth for incoming sync requests

   * set `HookUser`
   * enter `HookPassInput`
   * “Save WebHook Password (encrypted)”
5. The WebHook URL is shown in “WebHook URL … /hook/secrets_XXXXX”

#### Step C: Trigger synchronization

* On the master: click **“Manually Sync to Slaves”**
* Result per slave is written to the Symcon message log (OK/FAIL/SKIP).

---

### 5. Key rotation (Master/Standalone only)

* Master/Standalone provides the button **“Rotate Encryption Key”** (visible on Master/Standalone).
* Flow:

  * Vault and system.vault are decrypted with the old key in RAM
  * a new `master.key` is set atomically
  * Vault and system.vault are re-encrypted with the new key
  * optional synchronization (depending on your implementation)
* **Manual slaves are not updated (SKIP)** to keep them stable and functional.

---
Example Password Array

$vault = [
  "Spotify" => [
    "User" => "artur@example.com",
    "PW" => "S3cure!Spotify#2025",
    "URL" => "https://accounts.spotify.com",
    "Location" => "Hermitage",
    "IP" => "0.0.0.0"
  ],
  "MySQL_Prod" => [
    "User" => "db_admin",
    "PW" => "T9$kL!2zQp#7",
    "URL" => "mysql://10.10.20.15:3306",
    "Location" => "Berlin",
    "IP" => "10.10.20.15"
  ],
  "Camera_NVR" => [
    "User" => "nvr",
    "PW" => "Nvr-8h*P!44",
    "URL" => "http://192.168.1.50",
    "Location" => "Hermitage",
    "IP" => "192.168.1.50"
  ]
];

Here is the associated JSON String

{
  "Spotify": {
    "User": "artur@example.com",
    "PW": "S3cure!Spotify#2025",
    "URL": "https://accounts.spotify.com",
    "Location": "Hermitage",
    "IP": "0.0.0.0"
  },
  "MySQL_Prod": {
    "User": "db_admin",
    "PW": "T9$kL!2zQp#7",
    "URL": "mysql://10.10.20.15:3306",
    "Location": "Berlin",
    "IP": "10.10.20.15"
  },
  "Camera_NVR": {
    "User": "nvr",
    "PW": "Nvr-8h*P!44",
    "URL": "http://192.168.1.50",
    "Location": "Hermitage",
    "IP": "192.168.1.50"
  }
}


## PHP Usage (API)

```php
$instanceID = 12345;

// Get a single secret
$password = SEC_GetSecret($instanceID, 'Spotify');

// Get a complex configuration array
$config = json_decode(SEC_GetSecret($instanceID, 'MySQL_Config'), true);

// List all available keys
$keys = json_decode(SEC_GetKeys($instanceID), true);
```

**Note:** Unsaved changes in the JSON editor are lost if you close the console or click “Cancel / Wipe”. This is intentional (stateless security design).
