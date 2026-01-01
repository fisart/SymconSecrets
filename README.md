Hier ist die aktualisierte Dokumentation in Deutsch und Englisch, angepasst an den neuen Funktionsstand inklusive des grafischen Tresor-Explorers und der optimierten Benutzeroberfläche.

SymconSecrets – Dokumentation (aktueller Funktionsstand)
1. Warum benötigt man dieses Modul in IP-Symcon?

Standardmäßig speichert IP-Symcon Variableninhalte und Instanz-Konfigurationen im Klartext in der Datei settings.json. Daraus ergeben sich Sicherheitsrisiken bei Backups, unbefugtem Dateizugriff oder der Arbeit in verteilten Systemen.

2. Wie werden diese Probleme beseitigt?

SymconSecrets folgt einem „Zero-Knowledge“-Prinzip:

Verschlüsselung (AES-128-GCM): Alle Geheimnisse liegen in Symcon nur verschlüsselt vor (Vault).

Schlüssel-Isolation: Der master.key liegt außerhalb von Symcon im OS-Dateisystem.

Grafischer Tresor-Explorer: Ein interaktiver Editor im Actions-Bereich ermöglicht die Verwaltung komplexer Strukturen (Ordner & Datensätze), ohne Klartext-Properties zu nutzen (Disk-Clean).

Automatischer Cloud-Sync: Master-Systeme verteilen verschlüsselte Tresore sicher an Slaves.

3. Funktionsweise
3.1 Der Tresor (Vault) und Explorer

Der Tresor wird als verschlüsselter JSON-Blob gespeichert. Der neue Tresor-Explorer erlaubt eine intuitive Navigation:

Ordner (📁): Gruppieren von Zusammenhängen (z.B. Standorte, Gerätetypen).

Datensätze (🔑): Enthalten die eigentlichen Felder (User, PW, IP, URL, etc.).

Navigation: Per Klick auf Zeilen „hineinzoomen“ und per „ZURÜCK“-Button navigieren.

3.2 Stateless UI / RAM-Buffer

Die Navigation (aktueller Pfad) und die Auswahl im Editor werden ausschließlich in flüchtigen RAM-Buffern gehalten. Sobald die Konsole geschlossen wird, hinterlässt die Navigation keine Spuren in der settings.json.

3.3 Synchronisation & Modi

Master (Sender): Verwaltet den Tresor und pusht ihn an Slaves.

Slave (Receiver): Empfängt Updates über einen geschützten WebHook.

Standalone: Lokaler Tresor ohne Netzwerk-Funktionen. Hinweis: Im Standalone-Modus werden alle Synchronisations-Optionen (Token, Slaves) automatisch ausgeblendet.

4. Konfiguration
Schritt A: Basis-Setup (Alle Modi)

Instanz erstellen und System Role wählen.

KeyFolderPath setzen (z.B. /var/lib/symcon_keys/).

Auf „Übernehmen“ klicken, um den master.key zu initialisieren.

Schritt B: Tresor befüllen (Explorer)

Den Bereich 📂 TRESOR-EXPLORER in den Actions nutzen.

Über „➕ NEU“ Ordner oder Datensätze anlegen.

Zum Bearbeiten auf ein Gerät (🔑) klicken → der Editor öffnet sich unten.

Werte eintragen und „💾 Details speichern“ klicken.

JSON-Import: Große Strukturen können über das Feld „JSON IMPORT“ direkt als String eingelesen werden. Dies setzt den Explorer automatisch auf „root“ zurück.

Schritt C: Synchronisation (Nur Master)

Sync Token generieren und verschlüsselt speichern.

Slaves in der Liste anlegen (URL, TLS-Modus, User).

Slave-Passwörter im Bereich „Store per-Slave Basic-Auth Passwords“ hinterlegen.

5. PHP API (Nutzung in Skripten)
code
PHP
download
content_copy
expand_less
$id = 12345; // Instanz-ID

// 1. Einfaches Secret auslesen (flache Struktur)
$pw = SEC_GetSecret($id, "Spotify");

// 2. Tief verschachteltes Secret auslesen (Pfad-Logik)
$ip = SEC_GetSecret($id, "RASPI/Heartbeat/IP");

// 3. Alle verfügbaren Namen auflisten
$keys = json_decode(SEC_GetKeys($id), true);
SymconSecrets – Documentation (Current State)
1. Why do you need this module?

By default, IP-Symcon stores configurations in plaintext within settings.json. SymconSecrets mitigates risks associated with unsafe backups and unauthorized access by ensuring sensitive data never touches the disk unencrypted.

2. Solutions Provided

AES-128-GCM Encryption: Secrets are stored as an encrypted "Vault".

Key Isolation: The master.key is stored on the OS file system, isolated from Symcon backups.

Graphical Vault Explorer: A stateless, interactive editor in the Actions area for managing complex hierarchies (Disk-Clean).

Encrypted System Secrets: Tokens and passwords for internal module logic are stored in a separate system.vault.

3. How it Works
3.1 Vault Explorer

The vault is a nested JSON structure managed via the Explorer:

Folders (📁): For logical grouping (e.g., Locations, Categories).

Records (🔑): Containers for actual data fields (User, PW, IP, etc.).

Navigation: Click rows to drill down; use the "BACK" button to move up.

3.2 Stateless UI

Navigation states (Current Path) are stored in volatile RAM buffers. No trace of your browsing history within the vault is left in the settings.json.

3.3 Roles

Master: Full management and distribution to slaves.

Slave: Receives updates via encrypted WebHook.

Standalone: Isolated local vault. Note: All sync-related settings (Tokens, Slave lists) are automatically hidden in Standalone mode.

4. Configuration
Step A: Initial Setup

Create instance and select System Role.

Set KeyFolderPath and click "Apply" to generate the master.key.

Step B: Managing Secrets

Use the 📂 TRESOR-EXPLORER in the Actions section.

Create items using the "➕ NEW" area.

Click a record (🔑) to open the editor panel at the bottom.

Enter values and click "💾 Save Details".

JSON Import: Use the "JSON IMPORT" field to paste large structures. This automatically resets the Explorer to root.

Step C: Sync (Master only)

Generate and save a Sync Token.

Add Slaves to the list.

Store Slave credentials in the dedicated encrypted expansion panel.

5. PHP API
code
PHP
download
content_copy
expand_less
$id = 12345;

// 1. Access a simple secret
$pw = SEC_GetSecret($id, "Spotify");

// 2. Access a nested secret using path logic
$ip = SEC_GetSecret($id, "RASPI/Heartbeat/IP");

// 3. List all identifiers
$keys = json_decode(SEC_GetKeys($id), true);

Note: The old "Unlock & Load" workflow has been replaced by the interactive Explorer for enhanced security and usability. All edits in the Detail-Panel must be saved explicitly via the "Save Details" button.