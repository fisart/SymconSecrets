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
            if (in_array($name, $editorElements)) {
                $element['visible'] = false;
            }

            if ($name === 'BtnLoad') {
                $element['visible'] = $isEditorRole; 
            }
        }

        // 4. Actions (Der Sync-Button ganz unten)
        if (isset($json['actions'])) {
            foreach ($json['actions'] as &$action) {
                if (($action['name'] ?? '') === 'BtnSync') {
                    $action['visible'] = $isMaster; 
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

        // Nur der Slave (0) muss Daten empfangen können.
        if ($mode === 0) {
            @$this->RegisterHook("secrets_" . $this->InstanceID);
        }

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
        elseif ($mode !== 0 && !is_writable($folder)) {
            $errorMessage = "Directory is not writable: " . $folder;
            $this->SetStatus(202);
        } 
        else {
            $this->SetStatus(102); // IS_ACTIVE
        }

        $this->UpdateFormLayout($errorMessage);
    }

    public function UpdateUI(): void {
        $this->UpdateFormLayout("");
    }

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
    // CONFIGURATION ACTIONS
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

        if ($mode !== 0 && !is_writable($folder)) {
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
            return (is_array($val) || is_object($val)) ? (json_encode($val) ?: "") : (string)$val;
        }

        trigger_error("SecretsManager: Secret '$ident' not found.", E_USER_NOTICE);
        return "";
    }

    // =========================================================================
    // SYNCHRONIZATION
    // =========================================================================

    public function SyncSlaves(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");

        if ($mode !== 1) {
            if ($mode === 2) {
                echo "Sync cancelled: Standalone systems are isolated.";
            } else {
                echo "Sync cancelled: Only Master instances can initiate synchronization.";
            }
            return;
        }

        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        if (!is_array($slaves) || count($slaves) === 0) {
            echo "No slaves configured in the list.";
            return;
        }

        $keyHex = $this->_readKey();
        $vault = $this->GetValue("Vault");
        $token = $this->ReadPropertyString("AuthToken");

        if ($token === "") {
            echo "Error: Sync Token is missing. Please generate a token first.";
            return;
        }

        $payload = json_encode([
            'auth' => $token,
            'key'  => $keyHex,
            'vault'=> $vault
        ]);

        $successCount = 0;
        $totalSlaves = count($slaves);

        foreach ($slaves as $slave) {
            if (!isset($slave['Url']) || $slave['Url'] == "") continue;

            $headers = "Content-type: application/json\r\n";
            if (isset($slave['User']) && isset($slave['Pass']) && $slave['User'] !== "") {
                $auth = base64_encode($slave['User'] . ":" . $slave['Pass']);
                $headers .= "Authorization: Basic " . $auth . "\r\n";
            }

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
            $res = @file_get_contents($slave['Url'], false, $ctx);
            $statusLine = $http_response_header[0] ?? "Unknown Status"; 

            if ($res !== false && strpos($statusLine, "200") !== false && trim($res) === "OK") {
                $this->LogMessage("✅ Sync Success: " . $slave['Url'], KL_MESSAGE);
                $successCount++;
            } else {
                $this->LogMessage("❌ Sync Failed: " . $slave['Url'] . " -> " . $statusLine . " (Response: " . trim((string)$res) . ")", KL_ERROR);
            }
        }
        
        if ($successCount === $totalSlaves) {
            echo "✅ Synchronization completed successfully for all $successCount slaves.";
        } else {
            echo "Sync finished. Success: $successCount / Total: $totalSlaves.";
        }
    }

    protected function ProcessHookData(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");

        if ($mode !== 0) {
            header("HTTP/1.1 403 Forbidden");
            echo "Access Denied: This instance is not configured as a Slave.";
            $this->LogMessage("Unauthorized WebHook access attempt.", KL_WARNING);
            return;
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header("HTTP/1.1 405 Method Not Allowed");
            return;
        }

        $hookUser = $this->ReadPropertyString("HookUser");
        $hookPass = $this->ReadPropertyString("HookPass");

        if ($hookUser !== "" && $hookPass !== "") {
            if (!isset($_SERVER['PHP_AUTH_USER']) || 
                $_SERVER['PHP_AUTH_USER'] !== $hookUser || 
                $_SERVER['PHP_AUTH_PW'] !== $hookPass) 
            {
                header('WWW-Authenticate: Basic realm="SecretsManager"');
                header('HTTP/1.0 401 Unauthorized');
                return;
            }
        }

        $input = file_get_contents("php://input");
        $data = json_decode($input, true);

        if (!isset($data['auth']) || $data['auth'] !== $this->ReadPropertyString("AuthToken")) {
            header("HTTP/1.1 403 Forbidden");
            return;
        }

        if (isset($data['key'])) $this->_writeKey($data['key']);
        if (isset($data['vault'])) {
            $this->SetValue("Vault", $data['vault']);
            $this->SetBuffer("DecryptedCache", ""); 
        }

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
        if (!$vaultJson || $vaultJson === "Encrypted Vault") return false;

        $meta = json_decode($vaultJson, true);
        $keyHex = $this->_readKey();
        
        if (!$keyHex || !$meta || !isset($meta['data'])) return false;

        $decrypted = openssl_decrypt(
            $meta['data'], 
            $meta['cipher'] ?? "aes-128-gcm", 
            hex2bin($keyHex), 
            0, 
            hex2bin($meta['iv']), 
            hex2bin($meta['tag'])
        );

        if ($decrypted === false) return false;

        return json_decode($decrypted, true);
    }

    private function _loadOrGenerateKey() {
        $path = $this->_getFullPath();
        if ($path === "") return false;

        if (file_exists($path)) {
            return trim(file_get_contents($path));
        }

        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode === 1 || $mode === 2) {
            $newKey = bin2hex(random_bytes(16)); 
            if (file_put_contents($path, $newKey) === false) return false;
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

    // =========================================================================
    // EDITOR NAVIGATION & RENDER
    // =========================================================================

    private function RenderEditor(): void {
        $decrypted = $this->GetBuffer("DecryptedCache");
        $fullData = ($decrypted == "") ? [] : json_decode($decrypted, true);
        if (!is_array($fullData)) $fullData = [];

        $pathBuffer = $this->GetBuffer("CurrentPath");
        $path = ($pathBuffer === "") ? [] : json_decode($pathBuffer, true);
        if (!is_array($path)) $path = [];

        $currentLevel = $fullData;
        foreach ($path as $step) {
            if (isset($currentLevel[$step]) && is_array($currentLevel[$step])) {
                $currentLevel = $currentLevel[$step];
            }
        }

        $listValues = [];
        if (is_array($currentLevel)) {
            foreach ($currentLevel as $key => $value) {
                $isObject = is_array($value);
                $listValues[] = [
                    'Key'    => $key,
                    'Value'  => $isObject ? "" : (string)$value,
                    'Type'   => $isObject ? "Folder" : "Password",
                    'Action' => $isObject ? "📂 Open" : "✏️ Edit"
                ];
            }
        }

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

    /**
     * Handle actions (like clicking the "Open" button) inside the Editor List.
     */
    public function HandleListAction(string $EditorList): void {
        // 1. Daten sicher dekodieren (erfüllt die PHPLibrary Anforderung)
        $list = json_decode($EditorList, true);

        // Sicherheits-Check, falls IP-Symcon die Daten doch anders übergibt
        if (!is_array($list)) {
            $list = (array)$EditorList;
        }

        if (count($list) === 0) return;

        // 2. Änderungen (Passwörter) im RAM-Buffer sichern
        $this->SyncListToBuffer($list);

        // 3. Navigation (Deep-Dive)
        // Wir suchen nach der Zeile, die den Typ "Folder" hat
        foreach ($list as $row) {
            if (isset($row['Type']) && $row['Type'] === 'Folder' && !empty($row['Key'])) {
                
                // Wir prüfen, ob der Pfad existiert und erweitern ihn
                $pathBuffer = $this->GetBuffer("CurrentPath");
                $path = ($pathBuffer === "") ? [] : json_decode($pathBuffer, true);
                if (!is_array($path)) $path = [];
                
                $path[] = $row['Key'];
                
                $this->SetBuffer("CurrentPath", json_encode($path));
                
                // UI neu zeichnen für die tiefere Ebene
                $this->RenderEditor();
                return;
            }
        }
    }

    public function NavigateUp(): void {
        $pathBuffer = $this->GetBuffer("CurrentPath");
        $path = ($pathBuffer === "") ? [] : json_decode($pathBuffer, true);
        if (is_array($path) && count($path) > 0) {
            array_pop($path); 
            $this->SetBuffer("CurrentPath", json_encode($path));
            $this->RenderEditor();
        }
    }

    public function AddEntry(string $name, string $type): void {
        if (trim($name) === "") {
            echo "Error: Name cannot be empty.";
            return;
        }

        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        
        // Holen uns die Referenz auf die aktuelle Ebene (egal wie tief wir sind)
        $temp = &$this->getCurrentLevelReference($fullData);

        // Prüfen ob der Key bereits existiert
        if (isset($temp[$name])) {
            echo "Error: An entry with this name already exists here.";
            return;
        }

        // Neuen Eintrag erzeugen
        if ($type === "object") {
            $temp[$name] = []; // Erzeugt einen neuen Unterordner (Array)
        } else {
            $temp[$name] = "new_password"; // Erzeugt einen String
        }

        $this->SetBuffer("DecryptedCache", json_encode($fullData));
        
        // Wichtig: Nach dem Hinzufügen muss der Editor neu gezeichnet werden
        $this->RenderEditor();
        echo "Entry '$name' added.";
    }

    private function SyncListToBuffer(array $listFromUI): void {
        $decrypted = $this->GetBuffer("DecryptedCache");
        $fullData = ($decrypted == "") ? [] : json_decode($decrypted, true);
        if (!is_array($fullData)) $fullData = [];

        $temp = &$this->getCurrentLevelReference($fullData);

        foreach ($listFromUI as $row) {
            if ($row['Type'] === 'Password') {
                $temp[$row['Key']] = $row['Value'];
            }
        }

        $this->SetBuffer("DecryptedCache", json_encode($fullData));
    }

    public function LoadVault(): void {
        $cache = $this->_decryptVault();
        if ($cache === false) {
            $vaultValue = $this->GetValue("Vault");
            if ($vaultValue === "" || $vaultValue === "Encrypted Vault") {
                $cache = [];
            } else {
                echo "❌ Fehler: Tresor konnte nicht entschlüsselt werden. Key-Datei prüfen!";
                return;
            }
        }
        $this->SetBuffer("DecryptedCache", json_encode($cache));
        $this->SetBuffer("CurrentPath", json_encode([]));
        $this->RenderEditor();
    }

    public function EncryptAndSave(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode === 0) return; 

        $decrypted = $this->GetBuffer("DecryptedCache");
        $fullData = ($decrypted == "") ? [] : json_decode($decrypted, true);

        if ($this->_encryptAndSave($fullData)) {
            $this->ClearVault(); 
            echo "✅ Tresor erfolgreich verschlüsselt und gespeichert.";
            if ($mode === 1) $this->SyncSlaves();
        } else {
            echo "❌ Fehler: Verschlüsselung fehlgeschlagen.";
        }
    }

    public function ClearVault(): void {
        $this->SetBuffer("DecryptedCache", "");
        $this->SetBuffer("CurrentPath", "");

        $editorElements = [
            'LabelPath', 'BtnBack', 'EditorList', 'PanelAddEntry', 
            'BtnEncrypt', 'BtnClear', 'LabelSecurityWarning'
        ];
        foreach ($editorElements as $elem) {
            $this->UpdateFormField($elem, "visible", false);
        }
        $this->UpdateFormField("BtnLoad", "visible", true);
    }

    private function &getCurrentLevelReference(&$fullData) {
        $pathBuffer = $this->GetBuffer("CurrentPath");
        $path = ($pathBuffer === "") ? [] : json_decode($pathBuffer, true);
        if (!is_array($path)) $path = [];

        $level = &$fullData; 
        foreach ($path as $step) {
            if (isset($level[$step]) && is_array($level[$step])) {
                $level = &$level[$step]; 
            }
        }
        return $level;
    }
}