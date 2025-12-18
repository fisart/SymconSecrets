SymconSecrets – Dokumentation

1. Warum benötigt man dieses Modul in IP-Symcon?

Standardmäßig speichert IP-Symcon alle Variableninhalte, Skripte und Konfigurationen in der Datei settings.json. Dies führt zu folgenden Sicherheitsproblemen:

Klartext-Speicherung: Passwörter für Dienste (Spotify, MQTT, Datenbanken, Kameras) stehen im Klartext in der Einstellungsdatei.

Unsichere Backups: Ein Backup des Systems enthält automatisch alle Passwörter. Wer Zugriff auf das Backup hat, hat Zugriff auf alle Ihre Konten.

Sichtbarkeit: Jeder Benutzer mit Zugriff auf die IP-Symcon Verwaltungskonsole kann die Passwörter in den Skripten oder Variablen lesen.

Verwaltungsaufwand: Bei verteilten Systemen (z.B. Hauptwohnsitz, Ferienhaus, Gartenhaus) müssen Passwörter auf jedem System manuell gepflegt und synchronisiert werden.

2. Wie werden diese Probleme beseitigt?

Das Modul SymconSecrets adressiert diese Risiken durch ein "Zero-Knowledge"-Konzept innerhalb der Symcon-Datenbank:

Verschlüsselung: Alle Geheimnisse werden mit AES-128-GCM verschlüsselt. In der Datenbank (und somit im Backup) liegt nur unlesbarer Datensalat ("Blob").

Hardware-Trennung (Schlüssel-Isolation): Der Entschlüsselungs-Key (master.key) wird nicht in der IP-Symcon Datenbank gespeichert. Er liegt als physische Datei auf dem Betriebssystem (z.B. auf einem USB-Stick oder in einem geschützten Ordner auf dem NAS/Docker-Host).

Konsequenz: Wenn jemand Ihr Backup stiehlt, kann er die Daten ohne den physischen Key nicht entschlüsseln.

Automatisierte Verteilung: Ein Master-Slave-System erlaubt es, Passwörter zentral an einer Stelle zu pflegen. Änderungen werden automatisch und verschlüsselt an alle verknüpften IP-Symcon Installationen (Slaves) gepusht.

3. Wie funktioniert das Modul?

Das Modul arbeitet nach dem Tresor-Prinzip:

Der Tresor (Vault): Eine String-Variable in IP-Symcon, die das verschlüsselte JSON-Paket enthält.

Der Schlüssel (Master Key): Eine Datei (master.key), die lokal auf dem Server liegt.

Der Zugriff (In-Memory):

Wenn ein Skript ein Passwort anfordert, lädt das Modul den Key von der Festplatte und den Tresor aus der Datenbank.

Die Entschlüsselung findet nur im Arbeitsspeicher (RAM) statt.

Das Passwort wird niemals entschlüsselt auf die Festplatte zurückgeschrieben.

Synchronisation (Master -> Slave):
Der Master sendet das verschlüsselte Paket über einen WebHook an die Slaves.

Dies geschieht über HTTPS (SSL).

Die Übertragung ist durch ein Shared Secret (Sync Token) und optional durch Basic Auth (Benutzer/Passwort) abgesichert.

Der Slave speichert das Paket, ohne es lesen zu müssen. Erst bei Bedarf entschlüsselt er es mit seinem eigenen lokalen Key.

4. Wie wird es konfiguriert?
Schritt A: Einrichtung des Masters (Sender)

Erstellen Sie eine Instanz von SecretsManager.

Wählen Sie die Rolle Master (Sender).

Verzeichnispfad: Geben Sie einen Pfad an, in dem der Key gespeichert werden soll (z.B. /var/lib/symcon_keys/ oder /secrets/ bei Docker). Der Ordner muss existieren und schreibbar sein.

Sync Token: Klicken Sie auf "Generate Random Token". Kopieren Sie diesen Token für später!

Geheimnisse eingeben: Fügen Sie Ihre Passwörter als JSON-Objekt in das Eingabefeld ein:

code
JSON
download
content_copy
expand_less
{ "Spotify": "MeinPasswort123", "MQTT": { "User": "admin", "Pass": "sicher" } }

Klicken Sie auf "Encrypt & Save Local".

Schritt B: Einrichtung eines Slaves (Empfänger)

Erstellen Sie auf dem zweiten System eine Instanz von SecretsManager.

Wählen Sie die Rolle Slave (Receiver).

Verzeichnispfad: Geben Sie den lokalen Pfad für den Key an (muss identisch zum Master-Key sein, der Key wird beim ersten Sync übertragen).

Sync Token: Fügen Sie hier exakt den Token ein, den Sie beim Master generiert haben.

Notieren Sie sich die angezeigte WebHook URL (z.B. /hook/secrets_54321).

Schritt C: Verknüpfung

Gehen Sie zurück zum Master.

Fügen Sie unter "Slave WebHooks" die URL des Slaves hinzu:
http://<IP-DES-SLAVES>:3777/hook/secrets_54321

Klicken Sie beim Master auf "Manually Sync to Slaves".

Ergebnis: Der Key und die Daten werden an den Slave übertragen.

5. Wie wird es eingesetzt (PHP)?

In Ihren Skripten (z.B. für Alexa, Sonos, MQTT-Client) schreiben Sie keine Passwörter mehr. Sie fragen das Modul.

Beispiel 1: Einfaches Passwort abrufen

code
PHP
download
content_copy
expand_less
$instanceID = 12345; // ID Ihrer SecretsManager Instanz
$password = SEC_GetSecret($instanceID, 'Spotify');

if ($password) {
    echo "Login erfolgreich mit: " . $password;
}

Beispiel 2: Komplexes Array abrufen

code
PHP
download
content_copy
expand_less
// Holt ein ganzes Konfigurationsobjekt (z.B. für Datenbank)
$json = SEC_GetSecret($instanceID, 'MySQL_Config');
$config = json_decode($json, true);

$db_user = $config['user'];
$db_pass = $config['pass'];

Beispiel 3: Nutzung in Modul-Konfigurationsformularen
Wenn Sie eigene Module entwickeln, können Sie eine Dropdown-Liste aller verfügbaren Schlüssel anzeigen lassen:

code
PHP
download
content_copy
expand_less
// Liefert JSON-Liste der Keys: ["Spotify", "MySQL_Config", ...]
$keys = SEC_GetKeys($instanceID);



# SymconSecrets
A secure credential manager for IP-Symcon that encrypts secrets using AES-128-GCM with external key storage and automated Master-Slave replication.

SymconSecrets is a security module designed to protect sensitive data (API keys, passwords, user credentials) within IP-Symcon. Unlike standard variables, secrets are stored as encrypted blobs using AES-128-GCM, with the decryption key isolated on the OS file system (or USB stick). It features a Master-Slave architecture, allowing you to manage secrets centrally and automatically push updates to multiple IP-Symcon installations without exposing credentials in cleartext backups or the management console.
Key Features List (Optional add-on)
Zero-Knowledge Storage: Passwords are never stored in settings.json in cleartext.
Hardware Separation: Master encryption keys are stored outside the IP-Symcon environment.
Automated Sync: Push updates from a Master server to multiple Slave instances via secure WebHooks.
In-Memory Caching: High-performance decryption for scripts with RAM buffering.
Flexible Input: Supports arbitrary JSON structures for complex credentials.

# SymconSecrets

A secure credential manager for IP-Symcon that encrypts secrets using AES-128-GCM. It features a Master-Slave architecture to distribute secrets automatically to multiple IP-Symcon installations without exposing them in cleartext.

## Features
*   **Zero-Knowledge Storage:** Passwords are stored as encrypted blobs (AES-128-GCM).
*   **Hardware Separation:** The Master Key is stored on the OS file system (e.g., USB stick), not in the database.
*   **Auto-Sync:** Master instance pushes updates to Slave instances via WebHooks.
*   **In-Memory Caching:** High performance decryption for scripts.

## Requirements
*   IP-Symcon 6.0 or higher
*   PHP 7.4 or higher with OpenSSL extension

## Setup

### 1. Master Configuration
1.  Create an instance of **SecretsManager**.
2.  Set Role to **Master**.
3.  Enter a local path for the Key File (e.g., `/var/lib/symcon_keys/` on Linux or Docker mount).
4.  Generate a **Sync Token**.
5.  Paste your secrets as a JSON object into the input field and click **Encrypt**.

### 2. Slave Configuration
1.  Create an instance on the remote system.
2.  Set Role to **Slave**.
3.  Enter a local path for the Key File (must be writable).
4.  Paste the **same Sync Token** as the Master.
5.  Copy the **WebHook URL** displayed in the configuration.

### 3. Connection
1.  Go back to the Master.
2.  Add the Slave's WebHook URL to the "Slave WebHooks" list.
3.  Click **Manually Sync to Slaves**.

## PHP Usage

To retrieve a password in your scripts:

```php
$instanceID = 12345; // Your SecretsManager Instance ID
Returns a String : $password = SEC_GetSecret($instanceID, $key);

Returns a Array : $password = json_decode(SEC_GetSecret($instanceID, $key), true);

Return all keys : $keys = SEC_GetKeys($instanceID); // Returns JSON string


