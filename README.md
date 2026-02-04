Secrets – Dokumentation (aktueller Funktionsstand)

1. Warum benötigt man dieses Modul in IP-Symcon?
Standardmäßig speichert IP-Symcon Variableninhalte und Instanz-Konfigurationen im Klartext in der Datei settings.json. Daraus ergeben sich Sicherheitsrisiken bei Backups, unbefugtem Dateizugriff oder der Arbeit in verteilten Systemen.

2. Wie werden diese Probleme beseitigt?
SymconSecrets folgt einem „Zero-Knowledge“-Prinzip:
- Verschlüsselung (AES-128-GCM): Alle Geheimnisse liegen in Symcon nur verschlüsselt vor (Vault).
- Schlüssel-Isolation: Der master.key liegt außerhalb von Symcon im OS-Dateisystem.
- Grafischer Tresor-Explorer: Ein interaktiver Editor ermöglicht die Verwaltung komplexer Strukturen (Ordner & Datensätze), ohne Klartext-Properties zu nutzen.
- NEU: Zero-Convention Import: Das Modul erkennt Ordnerstrukturen automatisch anhand der JSON-Hierarchie. Manuelle technische Flags (wie __folder) sind nicht mehr erforderlich.

3. Funktionsweise
3.1 Der Tresor (Vault) und Explorer
Der Tresor wird als verschlüsselter JSON-Blob gespeichert. Der Explorer erlaubt eine intuitive Navigation:
- Ordner (📁): Gruppieren von Zusammenhängen (z.B. Standorte, Gerätetypen).
- Datensätze (🔑): Enthalten die eigentlichen Felder (User, PW, IP, URL, etc.).
- Hybrid-Strukturen: Ein Element kann gleichzeitig ein Ordner sein (Unterelemente enthalten) und eigene Felder besitzen (z.B. globale Zugangsdaten für diesen Standort).
- Navigation: Per Klick auf Zeilen „hineinzoomen“ und per „ZURÜCK“-Button navigieren.

3.2 Stateless UI / RAM-Buffer
Die Navigation (aktueller Pfad) und die Auswahl im Editor werden ausschließlich in flüchtigen RAM-Buffern gehalten. Sobald die Konsole geschlossen wird, hinterlässt die Navigation keine Spuren in der settings.json.

3.3 Synchronisation & Modi
- Master (Sender): Verwaltet den Tresor und pusht ihn an Slaves.
- Slave (Receiver): Empfängt Updates über einen geschützten WebHook.
- Standalone: Lokaler Tresor ohne Netzwerk-Funktionen. Hinweis: Im Standalone-Modus werden alle Synchronisations-Optionen (Token, Slaves) automatisch ausgeblendet.

4. Konfiguration
Schritt A: Basis-Setup (Alle Modi)
1. Instanz erstellen und System Role wählen.
2. KeyFolderPath setzen (z.B. /var/lib/symcon_keys/).
3. Auf „Übernehmen“ klicken, um den master.key zu initialisieren.

Schritt B: Tresor befüllen (Explorer)
1. Den Bereich 📂 TRESOR-EXPLORER in den Actions nutzen.
2. Über „➕ NEU“ Ordner oder Datensätze anlegen.
3. Hybrid-Editierung: Befinden Sie sich in einem Ordner mit eigenen Werten, erscheint oben der Bereich „🔑 FELDER DIESES ORDNER“. Hier können felder direkt für diese Ebene gespeichert werden.
4. Datensatz-Editierung: Zum Bearbeiten auf ein Unterelement (🔑) klicken → der Editor öffnet sich in einem Popup.
5. JSON-Import: Komplexe Arrays können ohne Sonderzeichen direkt als JSON-String eingelesen werden. Das Modul analysiert die Struktur automatisch.

Schritt C: Synchronisation (Nur Master)
1. Sync Token generieren und speichern.
2. Slaves in der Liste anlegen (URL, TLS-Modus, User).
3. Slave-Passwörter im Bereich „Store per-Slave Basic-Auth Passwords“ hinterlegen.

5. PHP API (Nutzung in Skripten)
$id = 12345;
$pw = SEC_GetSecret($id, "Spotify");
$ip = SEC_GetSecret($id, "RASPI/Heartbeat/IP");
$keys = json_decode(SEC_GetKeys($id), true);

--------------------------------------------------------------------------------

SymconSecrets – Documentation (Current State)

1. Why do you need this module?
By default, IP-Symcon stores configurations in plaintext. SymconSecrets ensures sensitive data remains encrypted, mitigating risks from unauthorized access or unsafe backups.

2. Solutions Provided
- AES-128-GCM Encryption: Secrets are stored as an encrypted "Vault".
- Key Isolation: The master.key is stored on the OS file system, isolated from Symcon.
- Graphical Vault Explorer: A stateless, interactive editor for managing complex hierarchies.
- NEW: Zero-Convention Import: The module automatically detects folder structures based on JSON hierarchy. No technical metadata (like __folder) is required for imports.

3. How it Works
3.1 Vault Explorer
The vault is a nested JSON structure:
- Folders (📁): For logical grouping.
- Records (🔑): Containers for actual data fields (User, PW, etc.).
- Hybrid Nodes: A node can act as both a folder (containing sub-items) and a record (containing its own fields, e.g., site-specific credentials).
- Navigation: Click rows to drill down; use "BACK" to move up.

3.2 Stateless UI
Navigation states are stored in volatile RAM. No trace of your vault browsing is left in settings.json.

3.3 Roles
- Master: Full management and distribution.
- Slave: Receives updates via encrypted WebHook.
- Standalone: Isolated local vault.

4. Configuration
Step A: Initial Setup
1. Create instance and select role.
2. Set KeyFolderPath and click "Apply".

Step B: Managing Secrets
1. Use the 📂 TRESOR-EXPLORER in Actions.
2. Create items via "➕ NEW".
3. Hybrid Editing: If the current folder contains data fields, a "🔑 FOLDER FIELDS" section appears at the top for direct editing.
4. Record Editing: Click a record (🔑) to open the detail editor popup.
5. JSON Import: Paste standard JSON arrays directly. The module automatically performs structural analysis to identify folders and records.

Step C: Sync (Master only)
1. Generate Sync Token.
2. Add Slaves and store credentials in the encrypted expansion panel.

5. PHP API
$id = 12345;
$pw = SEC_GetSecret($id, "Spotify");
$ip = SEC_GetSecret($id, "RASPI/Heartbeat/IP");
$keys = json_decode(SEC_GetKeys($id), true);

Note: The interactive Explorer replaces the old "Unlock & Load" workflow for enhanced security. Hybrid structures allow for high flexibility in organizing distributed systems.
```

---

### Comparison & Line-count Sanity Check

| Section | Original Lines | Updated Lines | Change |
| :--- | :---: | :---: | :--- |
| **German Text** | ~65 | ~75 | **+10** |
| **English Text** | ~60 | ~70 | **+10** |

**Reason for increase:**
The increase is strictly due to adding the "Hybrid" and "Zero-Convention" explanations into sections 2, 3.1, and 4 (Step B) of both languages. This ensures users understand they no longer need special syntax for imports and can manage fields at the folder level.

