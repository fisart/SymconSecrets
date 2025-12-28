<?php

declare(strict_types=1);

class SecretsManager extends IPSModuleStrict {

    // The name of the key file stored on the OS
    private const KEY_FILENAME = 'master.key';

    public function Create(): void {
        parent::Create();

        // 0 = Slave (Receiver), 1 = Master (Sender), 2 = Standalone (Local Vault Only)
        $this->RegisterPropertyInteger("OperationMode", 0);
        
        // Configuration Properties
        $this->RegisterPropertyString("KeyFolderPath", ""); 
        $this->RegisterPropertyString("AuthToken", "");
        
        // Basic Auth Properties (Optional Protection for WebHook)
        $this->RegisterPropertyString("HookUser", "");
        $this->RegisterPropertyString("HookPass", "");
        
        // List of Slaves (Master Only)
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        // Internal Storage for the Encrypted Blob
        $this->RegisterVariableString("Vault", "Encrypted Vault");
    }

    /**
     * DYNAMIC FORM GENERATION
     * This is called by IP-Symcon BEFORE the settings window opens.
     * It modifies the static form.json to hide irrelevant fields based on Master/Slave role.
     */
public function GetConfigurationForm(): string {
        // 1. Statische Vorlage laden
        $json = json_decode(file_get_contents(__DIR__ . "/form.json"), true);
        
        // 2. Aktuelle Rolle einlesen
        $mode = $this->ReadPropertyInteger("OperationMode");
        
        // Helfer-Variablen für die Logik
        $isSlave      = ($mode === 0);
        $isMaster     = ($mode === 1);
        $isStandalone = ($mode === 2);
        
        // Wer darf den Editor sehen? (Master und Standalone)
        $isEditorRole = ($isMaster || $isStandalone);
        
        // Wer braucht Synchronisations-Einstellungen? (Master und Slave)
        $isSyncRole   = ($isMaster || $isSlave);

        // Liste aller Editor-Elemente für das Deep-Dive Grid
        $editorElements = [
            'LabelPath', 'BtnBack', 'EditorList', 'PanelAddEntry', 
            'BtnEncrypt', 'BtnClear', 'LabelSecurityWarning'
        ];

        // 3. Elemente filtern
        foreach ($json['elements'] as &$element) {
            $name = $element['name'] ?? '';

            // --- WEBHOOK INFO (Nur Slave) ---
            if ($name === 'HookInfo') {
                $element['caption'] = "WebHook URL für diesen Slave: /hook/secrets_" . $this->InstanceID;
                $element['visible'] = $isSlave; 
            }

            // --- WEBHOOK PROTECTION / BASIC AUTH (Nur Slave) ---
            if (in_array($name, ['LabelHookAuth', 'HookUser', 'HookPass'])) {
                $element['visible'] = $isSlave;
            }

            // --- SYNC TOKEN / SHARED SECRET (Master & Slave, aber NICHT Standalone) ---
            if (in_array($name, ['BtnGenToken', 'AuthToken', 'BtnShowToken'])) {
                $element['visible'] = $isSyncRole;
            }

            // --- MASTER SPEZIFISCH (Nur Master) ---
            if (in_array($name, ['SlaveURLs', 'LabelSeparator', 'LabelMasterHead'])) {
                $element['visible'] = $isMaster;
            }

            // --- EDITOR WORKFLOW (Master & Standalone) ---
            // Wir blenden im Standard-Zustand des Formulars alle Editor-Elemente aus.
            // Diese werden erst dynamisch durch "LoadVault" (Unlock) sichtbar gemacht.
            if (in_array($name, $editorElements)) {
                $element['visible'] = false;
            }

            // Der Unlock-Button ist die Pforte zum Editor
            if ($name === 'BtnLoad') {
                $element['visible'] = $isEditorRole; 
            }
        }

        // 4. Actions (Der Sync-Button ganz unten)
        if (isset($json['actions'])) {
            foreach ($json['actions'] as &$action) {
                if (($action['name'] ?? '') === 'BtnSync') {
                    $action['visible'] = $isMaster; // Nur Master darf manuell synctriggern
                }
            }
        }

        return json_encode($json);
    }

    public function ApplyChanges(): void {
        parent::ApplyChanges();
        
        // 1. Variable im Baum verstecken
        $vaultID = @$this->GetIDForIdent("Vault");
        if ($vaultID) {
            IPS_SetHidden($vaultID, true);
        }

        // 2. Aktuelle Rolle prüfen
        $mode = $this->ReadPropertyInteger("OperationMode");

        // --- SCHRITT 3: Rollenabhängige WebHook Registrierung ---
        // Nur der Slave (0) muss Daten empfangen können.
        // Master (1) und Standalone (2) registrieren keinen Hook.
        if ($mode === 0) {
            @$this->RegisterHook("secrets_" . $this->InstanceID);
        }
        // Hinweis: Falls die Instanz von Slave auf Standalone umgestellt wird,
        // bleibt der Hook technisch in IP-Symcon vorhanden, wird aber durch 
        // die Logik in ProcessHookData (Schritt 6) blockiert.

        // 3. RAM Cache leeren bei Konfigurationsänderung
        $this->SetBuffer("DecryptedCache", ""); 

        // 4. Validierung des Verzeichnisses
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $errorMessage = "";
        
        if ($folder === "") {
            $this->SetStatus(104); // IS_INACTIVE
        } elseif (!is_dir($folder)) {
            $errorMessage = "Directory does not exist: " . $folder;
            $this->SetStatus(202); // IS_EBASE (Error)
        } 
        // Master (1) und Standalone (2) müssen zwingend schreiben können (Key-Generierung)
        elseif ($mode !== 0 && !is_writable($folder)) {
            $errorMessage = "Directory is not writable: " . $folder;
            $this->SetStatus(202);
        } 
        else {
            $this->SetStatus(102); // IS_ACTIVE
        }

        $this->UpdateFormLayout($errorMessage);
    }

    /**
     * Public wrapper for UI updates (called by form.json)
     */
    public function UpdateUI(): void {
        $this->UpdateFormLayout("");
    }

    /**
     * Internal helper to update static UI elements like Error Headers
     */
    private function UpdateFormLayout(string $errorMessage): void {
        if ($errorMessage !== "") {
            $this->UpdateFormField("HeaderError", "visible", true);
            $this->UpdateFormField("HeaderError", "caption", "!!! CONFIGURATION ERROR: " . $errorMessage . " !!!");
            $this->UpdateFormField("StatusLabel", "caption", "Error: " . $errorMessage);
        } else {
            $this->UpdateFormField("HeaderError", "visible", false);
            $this->UpdateFormField("StatusLabel", "caption", "Instance OK");
        }
    }

    // =========================================================================
    // CONFIGURATION ACTIONS (Called by Buttons)
    // =========================================================================

    public function CheckDirectory(): void {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $mode = $this->ReadPropertyInteger("OperationMode");

        if ($folder === "") {
            echo "No directory entered yet.";
            return;
        }

        if (!is_dir($folder)) {
            echo "❌ ERROR: Directory not found!\n\nPath: $folder";
            return;
        }

        if ($mode === 1 && !is_writable($folder)) {
            echo "❌ ERROR: Directory is NOT writable!\n\nPath: $folder";
            return;
        }

        $f = $this->_getFullPath();
        echo "✅ SUCCESS!\n\nDir: $folder\nFile: " . (file_exists($f) ? "Found" : "Will create on save");
    }

    public function GenerateToken(): void {
        $token = bin2hex(random_bytes(32));
        $this->UpdateFormField("AuthToken", "value", $token);
        echo "Token Generated & Inserted.";
    }

    public function ShowToken(): void {
        $token = $this->ReadPropertyString("AuthToken");
        echo ($token === "") ? "No token set." : "YOUR SYNC TOKEN:\n\n" . $token . "\n\n(Select text and Ctrl+C to copy)";
    }

    // =========================================================================
    // PUBLIC API (For Scripts)
    // =========================================================================

    public function GetKeys(): string {
        if ($this->GetStatus() !== 102) return json_encode([]);
        
        $cache = $this->_getCache();
        if ($cache === null) {
            $cache = $this->_decryptVault();
            if ($cache === false) return json_encode([]);
            $this->_setCache($cache);
        }
        return json_encode(array_keys($cache));
    }

    public function GetSecret(string $ident): string {
        if ($this->GetStatus() !== 102) return "";

        $cache = $this->_getCache();
        if ($cache === null) {
            $cache = $this->_decryptVault();
            if ($cache === false) {
                if($this->GetValue("Vault") !== "") {
                    $this->LogMessage("Decryption failed. Check Key File.", KL_ERROR);
                }
                return "";
            }
            $this->_setCache($cache);
        }

        if (isset($cache[$ident])) {
            $val = $cache[$ident];
            // If it's an array, return JSON string. If string, return string.
            return (is_array($val) || is_object($val)) ? (json_encode($val) ?: "") : (string)$val;
        }

        trigger_error("SecretsManager: Secret '$ident' not found.", E_USER_NOTICE);
        return "";
    }

    // =========================================================================
    // SYNCHRONIZATION (Master -> Slave)
    // =========================================================================

    /**
     * SYNCHRONIZATION (Master -> Slave)
     * Pushes the encrypted vault and the master key to all configured remote systems.
     */
    public function SyncSlaves(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");

        // --- SCHRITT 5: Funktions-Schutz ---
        // Nur ein Master (1) darf Daten an Slaves senden.
        if ($mode !== 1) {
            if ($mode === 2) {
                echo "Sync cancelled: Standalone systems are isolated.";
            } else {
                echo "Sync cancelled: Only Master instances can initiate synchronization.";
            }
            return;
        }

        // Slaves aus der Konfiguration laden
        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        if (!is_array($slaves) || count($slaves) === 0) {
            echo "No slaves configured in the list.";
            return;
        }

        // Vorbereitung der Daten
        $keyHex = $this->_readKey();
        $vault = $this->GetValue("Vault");
        $token = $this->ReadPropertyString("AuthToken");

        if ($token === "") {
            echo "Error: Sync Token is missing. Please generate a token first.";
            return;
        }

        // Das Paket für die Slaves schnüren
        $payload = json_encode([
            'auth' => $token,
            'key'  => $keyHex,
            'vault'=> $vault
        ]);

        $successCount = 0;
        $totalSlaves = count($slaves);

        // Alle konfigurierten Slaves nacheinander abarbeiten
        foreach ($slaves as $slave) {
            if (!isset($slave['Url']) || $slave['Url'] == "") {
                continue;
            }

            $headers = "Content-type: application/json\r\n";
            
            // Basic Auth Header hinzufügen, falls Benutzername gesetzt ist
            if (isset($slave['User']) && isset($slave['Pass']) && $slave['User'] !== "") {
                $auth = base64_encode($slave['User'] . ":" . $slave['Pass']);
                $headers .= "Authorization: Basic " . $auth . "\r\n";
            }

            // Stream Context Konfiguration (inkl. SSL-Fix für lokale IPs)
            $options = [
                'http' => [
                    'method' => 'POST',
                    'header' => $headers,
                    'content'=> $payload,
                    'timeout'=> 5,
                    'ignore_errors' => true 
                ],
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true
                ]
            ];

            $ctx = stream_context_create($options);
            
            // Paket senden
            $res = @file_get_contents($slave['Url'], false, $ctx);
            
            // HTTP Antwort analysieren
            $statusLine = $http_response_header[0] ?? "Unknown Status"; 

            if ($res !== false && strpos($statusLine, "200") !== false && trim($res) === "OK") {
                $this->LogMessage("✅ Sync Success: " . $slave['Url'], KL_MESSAGE);
                $successCount++;
            } else {
                $this->LogMessage("❌ Sync Failed: " . $slave['Url'] . " -> " . $statusLine . " (Response: " . trim((string)$res) . ")", KL_ERROR);
            }
        }
        
        // Abschließende Meldung für die Konsole
        if ($successCount === $totalSlaves) {
            echo "✅ Synchronization completed successfully for all $successCount slaves.";
        } else {
            echo "Sync finished. Success: $successCount / Total: $totalSlaves. Check the IP-Symcon log for detailed errors.";
        }
    }

    /**
     * WEBHOOK DATA PROCESSING
     * This is called by IP-Symcon when data is posted to /hook/secrets_ID
     */
    protected function ProcessHookData(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");

        // --- SCHRITT 6: Sicherheits-Guard ---
        // Nur Instanzen im Slave-Modus (0) dürfen Daten empfangen.
        // Master (1) und Standalone (2) lehnen jeglichen Empfang strikt ab.
        if ($mode !== 0) {
            header("HTTP/1.1 403 Forbidden");
            echo "Access Denied: This instance is not configured as a Slave.";
            $this->LogMessage("Unauthorized WebHook access attempt: Instance is not a Slave.", KL_WARNING);
            return;
        }

        // Sicherstellen, dass es ein POST-Request ist
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header("HTTP/1.1 405 Method Not Allowed");
            echo "Only POST requests are allowed.";
            return;
        }

        // 1. Optionaler Basic Auth Check (WebHook-Schutz)
        $hookUser = $this->ReadPropertyString("HookUser");
        $hookPass = $this->ReadPropertyString("HookPass");

        if ($hookUser !== "" && $hookPass !== "") {
            if (!isset($_SERVER['PHP_AUTH_USER']) || 
                $_SERVER['PHP_AUTH_USER'] !== $hookUser || 
                $_SERVER['PHP_AUTH_PW'] !== $hookPass) 
            {
                header('WWW-Authenticate: Basic realm="SecretsManager"');
                header('HTTP/1.0 401 Unauthorized');
                echo 'Authentication Required';
                return;
            }
        }

        // Daten einlesen
        $input = file_get_contents("php://input");
        $data = json_decode($input, true);

        // 2. Token Check (Shared Secret)
        // Vergleicht den empfangenen Token mit dem lokal gespeicherten Sync Token
        if (!isset($data['auth']) || $data['auth'] !== $this->ReadPropertyString("AuthToken")) {
            header("HTTP/1.1 403 Forbidden");
            echo "Invalid Sync Token";
            $this->LogMessage("WebHook Error: Received an invalid or missing Sync Token.", KL_ERROR);
            return;
        }

        // 3. Daten verarbeiten und speichern
        // Der Slave speichert Key und Vault, ohne sie im Klartext lesen zu müssen.
        if (isset($data['key'])) {
            $this->_writeKey($data['key']);
        }

        if (isset($data['vault'])) {
            $this->SetValue("Vault", $data['vault']);
            // RAM Cache leeren, damit beim nächsten Zugriff mit dem neuen Key entschlüsselt wird
            $this->SetBuffer("DecryptedCache", ""); 
        }

        // Rückmeldung an den Master
        echo "OK";
    }
    // =========================================================================
    // INTERNAL CRYPTO HELPERS
    // =========================================================================

    private function _getFullPath(): string {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if ($folder === "") return "";
        return rtrim($folder, '/\\') . DIRECTORY_SEPARATOR . self::KEY_FILENAME;
    }

    private function _encryptAndSave(array $dataArray): bool {
        $keyHex = $this->_loadOrGenerateKey();
        if (!$keyHex) return false;

        $newKeyBin = hex2bin($keyHex);
        $plain = json_encode($dataArray);
        
        $cipher = "aes-128-gcm";
        $iv = random_bytes(openssl_cipher_iv_length($cipher));
        $tag = ""; 
        
        $cipherText = openssl_encrypt($plain, $cipher, $newKeyBin, 0, $iv, $tag);

        if ($cipherText === false) return false;

        $vaultData = json_encode([
            'cipher' => $cipher,
            'iv' => bin2hex($iv),
            'tag'=> bin2hex($tag),
            'data'=> $cipherText
        ]);

        $this->SetValue("Vault", $vaultData);
        $this->_setCache($dataArray);
        
        return true;
    }

    private function _decryptVault() {
        $vaultJson = $this->GetValue("Vault");
        if (!$vaultJson) return false;

        $meta = json_decode($vaultJson, true);
        $keyHex = $this->_readKey();
        
        if (!$keyHex || !$meta) return false;

        $decrypted = openssl_decrypt(
            $meta['data'], 
            $meta['cipher'] ?? "aes-128-gcm", 
            hex2bin($keyHex), 
            0, 
            hex2bin($meta['iv']), 
            hex2bin($meta['tag'])
        );

        return json_decode($decrypted, true);
    }

    private function _loadOrGenerateKey() {
        $path = $this->_getFullPath();
        if ($path === "") return false;

        // Wenn die Datei schon existiert, laden wir sie einfach
        if (file_exists($path)) {
            return trim(file_get_contents($path));
        }

        // --- KORREKTUR HIER ---
        // Ein Schlüssel darf generiert werden, wenn wir Master (1) ODER Standalone (2) sind.
        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode === 1 || $mode === 2) {
            $newKey = bin2hex(random_bytes(16)); 
            if (file_put_contents($path, $newKey) === false) {
                return false; // Verzeichnis eventuell nicht schreibbar
            }
            return $newKey;
        }
        
        return false;
    }

    private function _readKey() {
        return $this->_loadOrGenerateKey();
    }

    private function _writeKey(string $hexKey): void {
        $path = $this->_getFullPath();
        if ($path !== "") {
            file_put_contents($path, $hexKey);
        }
    }

    private function _getCache() {
        $data = $this->GetBuffer("DecryptedCache");
        if ($data === "") return null;
        return json_decode($data, true);
    }

    private function _setCache(array $array): void {
        $this->SetBuffer("DecryptedCache", json_encode($array));
    }


    private function RenderEditor(): void {
    $fullData = json_decode($this->GetBuffer("DecryptedCache"), true);
    $path = json_decode($this->GetBuffer("CurrentPath"), true);

    // Wir "wühlen" uns durch das Array bis zum aktuellen Pfad
    $currentLevel = $fullData;
    foreach ($path as $step) {
        if (isset($currentLevel[$step])) {
            $currentLevel = $currentLevel[$step];
        }
    }

    // Liste für das UI aufbereiten
    $listValues = [];
    foreach ($currentLevel as $key => $value) {
        $isObject = is_array($value);
        $listValues[] = [
            'Key'    => $key,
            'Value'  => $isObject ? "" : $value,
            'Type'   => $isObject ? "Folder" : "Password",
            'Action' => $isObject ? "📂 Open" : "✏️ Edit"
        ];
    }

    // UI aktualisieren
    $pathString = "Root" . (count($path) > 0 ? " > " . implode(" > ", $path) : "");
    $this->UpdateFormField("LabelPath", "caption", "Current Path: " . $pathString);
    $this->UpdateFormField("LabelPath", "visible", true);
    $this->UpdateFormField("BtnBack", "visible", count($path) > 0);
    $this->UpdateFormField("EditorList", "values", json_encode($listValues));
    $this->UpdateFormField("EditorList", "visible", true);
    $this->UpdateFormField("PanelAddEntry", "visible", true);
    $this->UpdateFormField("BtnEncrypt", "visible", true);
    $this->UpdateFormField("BtnClear", "visible", true);
    $this->UpdateFormField("BtnLoad", "visible", false);
    $this->UpdateFormField("LabelSecurityWarning", "visible", true);
}
public function HandleListAction(string $EditorList): void {
    $list = json_decode($EditorList, true);
    $path = json_decode($this->GetBuffer("CurrentPath"), true);
    
    // Wir müssen herausfinden, welche Zeile gerade "aktiv" ist.
    // In IP-Symcon wird bei onEdit die ganze Liste gesendet.
    // Wir speichern zuerst alle Änderungen aus der Liste in unseren Cache:
    $this->SyncListToBuffer($list);

    // Wir schauen, ob ein Ordner angeklickt wurde (Simuliert durch das Klicken in der Liste)
    // Hinweis: Für ein echtes "Deep Dive" nutzen wir hier eine einfache Logik:
    // Wenn der Typ "Folder" ist, navigieren wir eine Ebene tiefer.
    foreach ($list as $row) {
        if ($row['Type'] === 'Folder' && $row['Key'] !== "") {
             // In einem echten Modul müsste man hier prüfen, welche Zeile angeklickt wurde.
             // Da Symcon onEdit für die Zelle feuert, nehmen wir an, dass der User "Open" wollte:
             $path[] = $row['Key'];
             $this->SetBuffer("CurrentPath", json_encode($path));
             $this->RenderEditor();
             return;
        }
    }
}

public function NavigateUp(): void {
    $path = json_decode($this->GetBuffer("CurrentPath"), true);
    if (count($path) > 0) {
        array_pop($path); // Letztes Element entfernen
        $this->SetBuffer("CurrentPath", json_encode($path));
        $this->RenderEditor();
    }
}

public function AddEntry(string $name, string $type): void {
    if ($name === "") return;

    $fullData = json_decode($this->GetBuffer("DecryptedCache"), true);
    
    // Nutze den Helper mit dem & Zeichen!
    $temp = &$this->getCurrentLevelReference($fullData);

    // Neuen Eintrag erzeugen
    if ($type === "object") {
        $temp[$name] = []; 
    } else {
        $temp[$name] = "new_password"; 
    }

    $this->SetBuffer("DecryptedCache", json_encode($fullData));
    $this->RenderEditor();
}

private function SyncListToBuffer(array $listFromUI): void {
    $fullData = json_decode($this->GetBuffer("DecryptedCache"), true);

    // Nutze den Helper!
    $temp = &$this->getCurrentLevelReference($fullData);

    // Wir überschreiben die Werte im Master-Array
    foreach ($listFromUI as $row) {
        if ($row['Type'] === 'Password') {
            $temp[$row['Key']] = $row['Value'];
        }
    }

    $this->SetBuffer("DecryptedCache", json_encode($fullData));
}

public function LoadVault(): void {
    // 1. Daten entschlüsseln
    $cache = $this->_decryptVault();
    
    if ($cache === false) {
        // Falls der Tresor leer ist (Neuanlage), starten wir mit einem leeren Array
        $vaultValue = $this->GetValue("Vault");
        if ($vaultValue === "" || $vaultValue === "Encrypted Vault") {
            $cache = [];
        } else {
            echo "❌ Fehler: Tresor konnte nicht entschlüsselt werden. Key-Datei prüfen!";
            return;
        }
    }

    // 2. Den kompletten Tresor-Inhalt unverschlüsselt im RAM-Buffer ablegen
    $this->SetBuffer("DecryptedCache", json_encode($cache));
    
    // 3. Den aktuellen Pfad auf die Wurzel (Root) setzen
    $this->SetBuffer("CurrentPath", json_encode([]));

    // 4. Das UI-Grid mit der ersten Ebene befüllen
    $this->RenderEditor();
}

public function EncryptAndSave(string $EditorList): void {
    $mode = $this->ReadPropertyInteger("OperationMode");
    if ($mode === 0) return; // Slaves dürfen nicht speichern

    // 1. Zuerst die Änderungen aus der aktuell sichtbaren Liste in den RAM-Buffer mergen
    $listData = json_decode($EditorList, true);
    $this->SyncListToBuffer($listData);

    // 2. Den gesamten Tresor-Inhalt (alle Ebenen) aus dem RAM-Buffer holen
    $fullData = json_decode($this->GetBuffer("DecryptedCache"), true);

    // 3. Das gesamte Paket verschlüsseln und in die IPS-Variable schreiben
    if ($this->_encryptAndSave($fullData)) {
        
        // 4. Erfolg melden und den Editor aus Sicherheitsgründen sperren/leeren
        $this->ClearVault(); 
        echo "✅ Tresor erfolgreich verschlüsselt und gespeichert.";
        
        // 5. Falls Master-Modus: Sync an Slaves anstoßen
        if ($mode === 1) {
            $this->SyncSlaves();
        }
    } else {
        echo "❌ Fehler: Verschlüsselung fehlgeschlagen.";
    }
}

public function ClearVault(): void {
    // RAM-Buffer restlos leeren
    $this->SetBuffer("DecryptedCache", "");
    $this->SetBuffer("CurrentPath", "");

    // Alle Editor-Elemente in der UI verstecken
    $this->UpdateFormField("LabelPath", "visible", false);
    $this->UpdateFormField("BtnBack", "visible", false);
    $this->UpdateFormField("EditorList", "visible", false);
    $this->UpdateFormField("PanelAddEntry", "visible", false);
    $this->UpdateFormField("BtnEncrypt", "visible", false);
    $this->UpdateFormField("BtnClear", "visible", false);
    $this->UpdateFormField("LabelSecurityWarning", "visible", false);
    
    // Den "Unlock" Button wieder anzeigen
    $this->UpdateFormField("BtnLoad", "visible", true);
}

// Interner Helper: Findet die aktuelle Ebene im Gesamt-Array
private function &getCurrentLevelReference(&$fullData) {
    $path = json_decode($this->GetBuffer("CurrentPath"), true);
    $level = &$fullData; // Start bei Root
    foreach ($path as $step) {
        if (isset($level[$step]) && is_array($level[$step])) {
            $level = &$level[$step]; // Wir gehen eine Ebene tiefer
        }
    }
    return $level;
}
}

?>