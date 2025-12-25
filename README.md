Die Dokumentation ist inhaltlich sehr fundiert. Um die wichtige Änderung der Stateless UI (Vermeidung von Klartext in der settings.json während der Eingabe) korrekt abzubilden, habe ich die entsprechenden Abschnitte ergänzt.

Hier ist die aktualisierte Dokumentation mit den hervorgehobenen Änderungen:

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

Anmerkung: Ich habe die Array-Struktur am Ende deiner Doku als Beispiel für die Organisation von Multi-System-Umgebungen beibehalten, da dies ein sehr guter Anwendungsfall für das Modul ist.