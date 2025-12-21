<?php

declare(strict_types=1);

class SecretsManager extends IPSModuleStrict {

    // The name of the key file stored on the OS
    private const KEY_FILENAME = 'master.key';

    public function Create(): void {
        parent::Create();

        // 0 = Slave (Receiver), 1 = Master (Sender)
        $this->RegisterPropertyInteger("OperationMode", 0);
        
        // Configuration Properties
        $this->RegisterPropertyString("KeyFolderPath", ""); 
        $this->RegisterPropertyString("AuthToken", "");
        
        // Basic Auth Properties (Optional Protection for WebHook)
        $this->RegisterPropertyString("HookUser", "");
        $this->RegisterPropertyString("HookPass", "");

        // Editor Input Buffer (Temporary storage for JSON editing)
        $this->RegisterPropertyString("InputJson", "");
        
        // List of Slaves (Master Only)
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        // Internal Storage for the Encrypted Blob
        $this->RegisterVariableString("Vault", "");
    }

    /**
     * DYNAMIC FORM GENERATION
     * This is called by IP-Symcon BEFORE the settings window opens.
     * It modifies the static form.json to hide irrelevant fields based on Master/Slave role.
     */
    public function GetConfigurationForm(): string {
        // 1. Load the static JSON template
        $json = json_decode(file_get_contents(__DIR__ . "/form.json"), true);
        
        // 2. Read current settings
        $mode = $this->ReadPropertyInteger("OperationMode");
        $inputContent = $this->ReadPropertyString("InputJson");
        
        $isMaster = ($mode === 1);
        $isSlave = ($mode === 0);
        $isUnlocked = ($inputContent !== ""); 

        // 3. Process Main Elements (Hide/Show fields)
        foreach ($json['elements'] as &$element) {
            $name = $element['name'] ?? '';

            // --- SLAVE SPECIFIC UI ---
            if ($name === 'HookInfo') {
                $element['caption'] = "This Instance WebHook: /hook/secrets_" . $this->InstanceID;
                $element['visible'] = $isSlave; 
            }
            // Hide Slave Auth fields if we are Master
            if (in_array($name, ['LabelHookAuth', 'HookUser', 'HookPass'])) {
                if (!$isSlave) $element['visible'] = false;
            }

            // --- MASTER SPECIFIC UI ---
            // Hide General Master Setup fields if we are Slave
            if (in_array($name, ['BtnGenToken', 'SlaveURLs', 'LabelSeparator', 'LabelMasterHead'])) {
                if (!$isMaster) $element['visible'] = false;
            }

            // --- EDITOR WORKFLOW (Master Only) ---
            if ($isMaster) {
                // LOCKED STATE: Show Unlock button, Hide Editor
                if ($name === 'BtnLoad') {
                    $element['visible'] = !$isUnlocked;
                }
                
                // UNLOCKED STATE: Show Editor, Save, Cancel, Warning
                if (in_array($name, ['InputJson', 'BtnEncrypt', 'BtnClear', 'LabelSecurityWarning'])) {
                    $element['visible'] = $isUnlocked;
                }
            } else {
                // If Slave, hide ALL editor controls
                if (in_array($name, ['BtnLoad', 'InputJson', 'BtnEncrypt', 'BtnClear', 'LabelSecurityWarning'])) {
                    $element['visible'] = false;
                }
            }
        }

        // 4. Process Actions (Bottom Bar Buttons)
        if (isset($json['actions'])) {
            foreach ($json['actions'] as &$action) {
                if (($action['name'] ?? '') === 'BtnSync') {
                    $action['visible'] = $isMaster; // Only Master can sync
                }
            }
        }

        return json_encode($json);
    }

    public function ApplyChanges(): void {
        parent::ApplyChanges();
        
        // FIX for Module Store: Hide variable here, where we know it exists
        $vaultID = @$this->GetIDForIdent("Vault");
        if ($vaultID) {
            IPS_SetHidden($vaultID, true);
        }

        // Register WebHook (Suppress warning if already exists)
        @$this->RegisterHook("secrets_" . $this->InstanceID);

        // Clear RAM Cache on config change
        //$this->SetBuffer("DecryptedCache", ""); 

        // Validate Directory Logic
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $mode = $this->ReadPropertyInteger("OperationMode");
        
        $errorMessage = "";
        
        // Check 1: Is path empty?
        if ($folder === "") {
            $this->SetStatus(104); // IS_INACTIVE
        } 
        // Check 2: Does directory exist?
        elseif (!is_dir($folder)) {
            $errorMessage = "Directory does not exist: " . $folder;
            $this->SetStatus(202); // IS_EBASE (Error)
        } 
        // Check 3: Is it writable (Master only)?
        elseif ($mode === 1 && !is_writable($folder)) {
            $errorMessage = "Directory is not writable: " . $folder;
            $this->SetStatus(202); // IS_EBASE (Error)
        } 
        // All Good
        else {
            $this->SetStatus(102); // IS_ACTIVE
        }

        // Update UI Layout (Error Header)
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
    // EDITOR ACTIONS (Load / Save / Wipe)
    // =========================================================================

    public function LoadVault(): void {
        $cache = $this->_decryptVault();
        
        if ($cache === false) {
            if ($this->GetValue("Vault") === "") {
                $json = "{}"; // Start empty
            } else {
                echo "❌ Error: Could not decrypt vault. Check Key File.";
                return;
            }
        } else {
            // Pretty print for editing
            $json = json_encode($cache, JSON_PRETTY_PRINT);
        }

        // Save to input field to trigger "Unlocked" state in GetConfigurationForm
        IPS_SetProperty($this->InstanceID, "InputJson", $json);
        IPS_ApplyChanges($this->InstanceID);
    }

    public function EncryptAndSave(): void {
        if ($this->ReadPropertyInteger("OperationMode") !== 1) { echo "Master only."; return; }
        
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if (!is_dir($folder) || !is_writable($folder)) { echo "Dir Error."; return; }

        $jsonInput = $this->ReadPropertyString("InputJson");
        if (trim($jsonInput) === "") { echo "Input empty."; return; }
        
        // Validate JSON Syntax
        $decoded = json_decode($jsonInput, true);
        if ($decoded === null) { 
            echo "❌ JSON Syntax Error!\nPlease check commas and brackets."; 
            return; 
        }

        // Encrypt and Store
        if ($this->_encryptAndSave($decoded)) {
            // WIPE Input to Lock UI
            IPS_SetProperty($this->InstanceID, "InputJson", "");
            IPS_ApplyChanges($this->InstanceID);
            
            echo "✅ Saved & Encrypted. Form Locked.";
            
            // Trigger Sync
            $this->SyncSlaves();
        } else {
            echo "❌ Error: Encryption failed.";
        }
    }

    public function ClearVault(): void {
        // Wipe input field to cancel editing
        IPS_SetProperty($this->InstanceID, "InputJson", "");
        IPS_ApplyChanges($this->InstanceID);
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

    public function SyncSlaves(): void {
        if ($this->ReadPropertyInteger("OperationMode") !== 1) return;

        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        if (!is_array($slaves)) return;

        $keyHex = $this->_readKey();
        $vault = $this->GetValue("Vault");
        $token = $this->ReadPropertyString("AuthToken");

        $payload = json_encode([
            'auth' => $token,
            'key'  => $keyHex,
            'vault'=> $vault
        ]);

        $successCount = 0;
        
        foreach ($slaves as $slave) {
            if (!isset($slave['Url']) || $slave['Url'] == "") continue;

            $headers = "Content-type: application/json\r\n";
            
            // Basic Auth Header
            if (isset($slave['User']) && isset($slave['Pass']) && $slave['User'] !== "") {
                $auth = base64_encode($slave['User'] . ":" . $slave['Pass']);
                $headers .= "Authorization: Basic " . $auth . "\r\n";
            }

            // SSL FIX: Allow self-signed certs for local LAN sync
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
            
            // Send
            $res = @file_get_contents($slave['Url'], false, $ctx);
            
            // Analyze Response
            $statusLine = $http_response_header[0] ?? "Unknown"; 

            if ($res !== false && strpos($statusLine, "200") !== false && trim($res) === "OK") {
                $this->LogMessage("✅ Synced: " . $slave['Url'], KL_MESSAGE);
                $successCount++;
            } else {
                $this->LogMessage("❌ Failed: " . $slave['Url'] . " -> " . $statusLine . " (Msg: " . trim($res) . ")", KL_ERROR);
            }
        }
        
        if ($successCount > 0) {
            echo "Sync completed. Success: $successCount / Total: " . count($slaves);
        } else {
            echo "Sync FAILED. Check messages log for details.";
        }
    }

    protected function ProcessHookData(): void {
        // 1. Basic Auth Check
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

        $input = file_get_contents("php://input");
        $data = json_decode($input, true);

        // 2. Token Check
        if (($data['auth'] ?? '') !== $this->ReadPropertyString("AuthToken")) {
            header("HTTP/1.1 403 Forbidden");
            echo "Invalid Token";
            return;
        }

        // 3. Save Data
        if (isset($data['key'])) {
            $this->_writeKey($data['key']);
        }

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

    public function EncryptAndSave(string $jsonInput): void {
        // 1. Ensure we are in Master mode
        if ($this->ReadPropertyInteger("OperationMode") !== 1) { 
            echo "Master only."; 
            return; 
        }
        
        // 2. Validate the directory before attempting to save the key
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if (!is_dir($folder) || !is_writable($folder)) { 
            echo "❌ Error: Directory is not writable or does not exist."; 
            return; 
        }

        // 3. Check if the input passed from the UI is empty
        if (trim($jsonInput) === "") { 
            echo "❌ Error: Input is empty."; 
            return; 
        }
        
        // 4. Validate JSON Syntax of the input
        $decoded = json_decode($jsonInput, true);
        if ($decoded === null) { 
            echo "❌ JSON Syntax Error!\nPlease check commas and brackets."; 
            return; 
        }

        // 5. Encrypt and Store (this calls your internal crypto helper)
        if ($this->_encryptAndSave($decoded)) {
            
            // 6. Clear the temporary Property and Save settings
            // This "locks" the form again by making InputJson empty
            IPS_SetProperty($this->InstanceID, "InputJson", "");
            IPS_ApplyChanges($this->InstanceID);
            
            echo "✅ Saved & Encrypted. Form Locked.";
            
            // 7. Trigger distribution to Slaves
            $this->SyncSlaves();
        } else {
            echo "❌ Error: Encryption failed.";
        }
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

        if (file_exists($path)) {
            return trim(file_get_contents($path));
        }

        if ($this->ReadPropertyInteger("OperationMode") === 1) {
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
}
?>