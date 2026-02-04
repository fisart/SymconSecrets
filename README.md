# 🔐 SymconSecrets - Professionelle Dokumentation

## 1. Sicherheitsarchitektur & Bedrohungsmodell

SymconSecrets wurde entwickelt, um sensible Anmeldedaten gegen gängige Angriffsvektoren in Smart-Home-Umgebungen zu schützen.

*   **Verschlüsselungsalgorithmus:** Industriestandard **AES-128-GCM** (Galois/Counter Mode). Dies bietet sowohl **Vertraulichkeit** als auch **Authentizität** (stellt sicher, dass die Daten nicht manipuliert wurden).
*   **Hardware-Schlüssel-Isolation:** Der Verschlüsselungsschlüssel (`master.key`) wird als physische Datei auf dem Host-Betriebssystem gespeichert. Durch die Platzierung auf einem USB-Stick oder in einem geschützten Systemverzeichnis stellen Sie sicher, dass eine gestohlene `settings.json` oder ein Cloud-Backup ohne den physischen Schlüssel wertlos ist.
*   **Stateless Operation (Zustandslosigkeit):** Im Gegensatz zu Standardmodulen werden Geheimnisse niemals in den Instanzeigenschaften gespeichert. Sie existieren während der Konfigurationsphase nur im RAM, was ein versehentliches Durchsickern in Logdateien oder den Festplatten-Cache verhindert.
*   **Speicherhygiene:** Entschlüsselte Daten werden in einem RAM-Puffer vorgehalten und gelöscht, sobald die Konsole geschlossen oder die Schaltfläche „Abbrechen / RAM leeren“ geklickt wird.

---

## 2. Fortgeschrittene Tresor-Logik

### 📂 Hybride Strukturanalyse
Das Modul nutzt eine **Zero-Convention-Erkennung**. Sie müssen Ordner nicht manuell kennzeichnen.
*   **Implizite Ordner:** Jeder Knoten, der verschachtelte Objekte enthält, wird automatisch als Ordner gerendert.
*   **Blattknoten (Datensätze):** Knoten, die nur Schlüssel-Wert-Paare (Strings/Zahlen) enthalten, werden als Geheimnisse behandelt.
*   **Hybride Kapazität:** Ein Ordner kann eigene Metadaten enthalten (z. B. `Standort: "Keller"`), während er gleichzeitig als Container für Unterordner fungiert. Dies ermöglicht eine hochgradig semantische Datenorganisation.

### 📥 Zero-Convention Import
Sie können jedes Standard-JSON-Array aus einer anderen Anwendung kopieren und in das Feld **JSON IMPORT** einfügen. Das Modul wird:
1.  Die Struktur rekursiv scannen.
2.  Icons (📁/🔑) basierend auf der Form der Daten zuweisen.
3.  Die gesamte Hierarchie verschlüsselt in den Tresor übernehmen.

---

## 3. Synchronisation & Konnektivität

### Master -> Slave Push-Protokoll
Das Master-System initiiert eine sichere POST-Anfrage an den WebHook des Slaves.
*   **Payload-Verschlüsselung:** Der gesamte Tresor und der Master-Schlüssel werden in einem einzigen verschlüsselten Paket übertragen.
*   **Sync-Token (Shared Secret):** Der Zugriff wird durch ein zufälliges 32-Byte-Token geschützt.
*   **TLS-Transportsicherheit:**
    *   **Strict Mode:** Erfordert gültige, von einer CA signierte Zertifikate (Standard für Remote-Sync).
    *   **Pinned Mode:** Für lokale IP-Verbindungen. Sie geben den SHA-256-Fingerabdruck des Zertifikats an, und der Master validiert ihn, selbst wenn er selbstsigniert ist.
    *   **HTTP (Legacy):** Nur für nicht-sensible Daten erlaubt; die Synchronisation des Master-Schlüssels ist in diesem Modus blockiert.

---

## 4. Konfiguration & Workflow

### Schritt-für-Schritt-Einrichtung
1.  **Identität:** Legen Sie die **Systemrolle** fest.
    *   *Master:* Steuert die „Single Source of Truth“.
    *   *Slave:* Spiegelt den Master; lokale Bearbeitungen werden beim nächsten Sync überschrieben.
2.  **Infrastruktur:** Pfad für den **master.key** setzen. Stellen Sie sicher, dass der Symcon-Dienst Lese-/Schreibrechte für dieses Verzeichnis hat.
3.  **Authentifizierung:** Generieren Sie ein **Sync-Token** auf dem Master und kopieren Sie es auf den Slave.
4.  **Security Guard:** (Nur Slave) Setzen Sie **AllowKeyTransport** auf `true`, um die initiale Schlüsselübertragung vom Master zu erlauben.

---

## 5. PHP-API Referenz

### SEC_GetSecret(int $InstanceID, string $Path)
Der Pfad unterstützt die Slash-Notation für tief verschachtelte Abfragen.
```php
// Gibt den Passwort-String zurück
$pass = SEC_GetSecret(12345, "Standorte/Berlin/Buero/AdminPass");

// Gibt ein JSON-kodiertes Array für einen hybriden Knoten zurück
$data = SEC_GetSecret(12345, "Standorte/Berlin"); 
```

### SEC_GetKeys(int $InstanceID)
Gibt alle Identifikatoren der aktuellen Ebene als JSON-kodiertes Array zurück.

---
---

# 🔐 SymconSecrets - Professional Documentation (English)

## 1. Security Architecture & Threat Model
*   **Encryption:** **AES-128-GCM** (Galois/Counter Mode) for confidentiality and authenticity.
*   **Hardware Key Isolation:** `master.key` is stored on the host OS, isolated from Symcon backups.
*   **Stateless Operation:** Secrets exist only in volatile RAM during configuration.
*   **Memory Hygiene:** RAM buffers are cleared upon closing the console or manual wipe.

## 2. Advanced Vault Logic
*   **Hybrid Structural Analysis:** Automatic Folder vs. Record detection.
*   **Zero-Convention Import:** Standard JSON arrays are recursively scanned and encrypted without needing metadata keys (like `__folder`).
*   **Hybrid Capacity:** Nodes can simultaneously hold flat data fields and nested sub-folders.

## 3. Synchronization & Connectivity
*   **Master -> Slave Push:** Secure POST requests to Slave WebHooks.
*   **Sync Token:** Guarded by 32-byte shared secrets.
*   **TLS Transport Security:**
    *   **Strict Mode:** CA-signed certificate validation.
    *   **Pinned Mode:** SHA-256 fingerprint validation for self-signed certificates.
    *   **HTTP:** Restricted mode; Master Key transport is disabled.

## 4. Configuration & Workflow
*   **Roles:** Master (Source), Slave (Mirror), Standalone (Isolated).
*   **Explorer:** Use "Folder Fields" for node-level data and the Detail-View (⚙️) for leaf records.
*   **Atomic Saves:** Encryption only occurs when "Save" is explicitly triggered.

## 5. PHP API Reference
```php
$id = 12345;
$pw = SEC_GetSecret($id, "Locations/London/Office/Wifi");
$keys = json_decode(SEC_GetKeys($id), true);
```
