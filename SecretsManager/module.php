<?php

declare(strict_types=1);

class SecretsManager extends IPSModuleStrict {

    private const KEY_FILENAME = 'master.key';

    public function Create(): void {
        parent::Create();
        // 0 = Slave, 1 = Master
        $this->RegisterPropertyInteger("OperationMode", 0);
        
        // Configuration Properties
        $this->RegisterPropertyString("KeyFolderPath", ""); 
        $this->RegisterPropertyString("AuthToken", "");
        
        // Basic Auth Properties
        $this->RegisterPropertyString("HookUser", "");
        $this->RegisterPropertyString("HookPass", "");

        $this->RegisterPropertyString("InputJson", "");
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        // Internal Storage
        $this->RegisterVariableString("Vault", "Encrypted Vault");
        // Hide internal storage from WebFront
        IPS_SetHidden($this->GetIDForIdent("Vault"), true);
    }

    /**
     * DYNAMIC FORM GENERATION
     * Controls visibility of:
     * 1. Master vs Slave fields
     * 2. Editor Locked vs Unlocked state
     */
    public function GetConfigurationForm(): string {
        $json = json_decode(file_get_contents(__DIR__ . "/form.json"), true);
        
        $mode = $this->ReadPropertyInteger("OperationMode");
        // We check the input field to see if we are in "Edit Mode"
        $inputContent = $this->ReadPropertyString("InputJson");
        
        $isMaster = ($mode === 1);
        $isSlave = ($mode === 0);
        $isUnlocked = ($inputContent !== ""); 

        // 1. Process Main Elements
        foreach ($json['elements'] as &$element) {
            $name = $element['name'] ?? '';

            // --- SLAVE SPECIFIC ---
            if ($name === 'HookInfo') {
                $element['caption'] = "This Instance WebHook: /hook/secrets_" . $this->InstanceID;
                $element['visible'] = $isSlave; 
            }
            // Hide Slave Auth fields on Master
            if (in_array($name, ['LabelHookAuth', 'HookUser', 'HookPass'])) {
                if (!$isSlave) $element['visible'] = false;
            }

            // --- MASTER SPECIFIC ---
            // Hide General Master Setup fields on Slave
            if (in_array($name, ['BtnGenToken', 'SlaveURLs', 'LabelSeparator', 'LabelMasterHead'])) {
                if (!$isMaster) $element['visible'] = false;
            }

            // --- EDITOR WORKFLOW (Master Only) ---
            if ($isMaster) {
                // The "Unlock" button is visible only when LOCKED (empty input)
                if ($name === 'BtnLoad') {
                    $element['visible'] = !$isUnlocked;
                }
                
                // The Editor, Save, Cancel, and Warning are visible only when UNLOCKED
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

        // 2. Process Actions (Bottom Bar) - FIX: Hide Sync Button on Slave
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
        
        // Register WebHook (Suppress warning if exists)
        @$this->RegisterHook("secrets_" . $this->InstanceID);

        // Clear RAM Cache
        $this->SetBuffer("DecryptedCache", ""); 

        // 1. Validate Directory Logic
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

        // 2. Update UI (Internal call)
        $this->UpdateFormLayout($errorMessage);
    }

    /**
     * Called by form.json "onChange".
     * Must have ZERO arguments to ensure compatibility with IP-Symcon calls.
     */
    public function UpdateUI(): void {
        $this->UpdateFormLayout("");
    }

    /**
     * Internal Logic to hide/show fields dynamically while the form is open.
     */
    private function UpdateFormLayout(string $errorMessage): void {
        $mode = $this->ReadPropertyInteger("OperationMode");
        $isMaster = ($mode === 1);
        $isSlave = ($mode === 0);
        
        // 1. Handle Error Header Visibility
        if ($errorMessage !== "") {
            $this->UpdateFormField("HeaderError", "visible", true);
            $this->UpdateFormField("HeaderError", "caption", "!!! CONFIGURATION ERROR: " . $errorMessage . " !!!");
            $this->UpdateFormField("StatusLabel", "caption", "Error: " . $errorMessage);
        } else {
            $this->UpdateFormField("HeaderError", "visible", false);
            $this->UpdateFormField("StatusLabel", "caption", "Instance OK");
        }

        // 2. Slave Specific UI (Hidden on Master)
        $hookUrl = "/hook/secrets_" . $this->InstanceID;
        $this->UpdateFormField("HookInfo", "caption", "This Instance WebHook: " . $hookUrl);
        $this->UpdateFormField("HookInfo", "visible", $isSlave);
        
        $this->UpdateFormField("LabelHookAuth", "visible", $isSlave);
        $this->UpdateFormField("HookUser", "visible", $isSlave);
        $this->UpdateFormField("HookPass", "visible", $isSlave);

        // 3. Master Specific UI (Hidden on Slave)
        $this->UpdateFormField("BtnGenToken", "visible", $isMaster); 
        
        $this->UpdateFormField("SlaveURLs", "visible", $isMaster);
        $this->UpdateFormField("LabelSeparator", "visible", $isMaster);
        $this->UpdateFormField("LabelMasterHead", "visible", $isMaster);
        $this->UpdateFormField("InputJson", "visible", $isMaster);
        $this->UpdateFormField("BtnEncrypt", "visible", $isMaster);
        
        // 4. Action Buttons (Hidden on Slave)
        $this->UpdateFormField("BtnSync", "visible", $isMaster);
    }

    // --- EDITOR ACTIONS ---

    /**
     * UNLOCK: Decrypts data and fills the input field for editing.
     */
    public function LoadVault(): void {
        $cache = $this->_decryptVault();
        
        if ($cache === false) {
            if ($this->GetValue("Vault") === "") {
                $json = "{}"; // Empty vault
            } else {
                echo "❌ Error: Could not decrypt vault. Check Key File.";
                return;
            }
        } else {
            // Pretty Print for editing
            $json = json_encode($cache, JSON_PRETTY_PRINT);
        }

        // Set input and save to unlock UI
        IPS_SetProperty($this->InstanceID, "InputJson", $json);
        IPS_ApplyChanges($this->InstanceID);
    }

    /**
     * SAVE: Validates, Minifies, Encrypts, Saves, and Relocks.
     */
    public function EncryptAndSave(): void {
        if ($this->ReadPropertyInteger("OperationMode") !== 1) { echo "Master only."; return; }
        
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if (!is_dir($folder) || !is_writable($folder)) { echo "Dir Error."; return; }

        $jsonInput = $this->ReadPropertyString("InputJson");
        if (trim($jsonInput) === "") { echo "Input empty."; return; }
        
        // Validation
        $decoded = json_decode($jsonInput, true);
        if ($decoded === null) { 
            echo "❌ JSON Syntax Error!\nPlease check commas and brackets."; 
            return; 
        }

        // Encrypt & Save
        if ($this->_encryptAndSave($decoded)) {
            // WIPE Input to Lock UI
            IPS_SetProperty($this->InstanceID, "InputJson", "");
            IPS_ApplyChanges($this->InstanceID);
            
            echo "✅ Saved & Encrypted. Form Locked.";
            $this->SyncSlaves();
        } else {
            echo "❌ Error: Encryption failed.";
        }
    }

    /**
     * CANCEL: Wipes the input field without saving.
     */
    public function ClearVault(): void {
        IPS_SetProperty($this->InstanceID, "InputJson", "");
        IPS_ApplyChanges($this->InstanceID);
    }

    // --- STANDARD ACTIONS ---

    /**
     * Called by "Check Directory Permissions" button.
     */
    public function CheckDirectory(): void {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $mode = $this->ReadPropertyInteger("OperationMode");

        if ($folder === "") {
            echo "No directory entered yet.";
            return;
        }

        if (!is_dir($folder)) {
            echo "❌ ERROR: Directory not found!\n\nPath: $folder\n\nPlease ensure the path is absolute and accessible by the Symcon user.";
            return;
        }

        if ($mode === 1 && !is_writable($folder)) {
            echo "❌ ERROR: Directory is NOT writable!\n\nPath: $folder\n\nMaster mode requires write permissions to create 'master.key'.";
            return;
        }

        $fullPath = $this->_getFullPath();
        $fileStatus = file_exists($fullPath) ? "master.key found." : "master.key will be created on save.";
        
        echo "✅ SUCCESS!\n\nDirectory: $folder\nPermissions: OK\nFile: $fileStatus";
    }

    /**
     * Called by "Generate Random Token" button.
     */
    public function GenerateToken(): void {
        $token = bin2hex(random_bytes(32));
        $this->UpdateFormField("AuthToken", "value", $token);
        echo "Token Generated!\n\n$token\n\n(It has been inserted into the field. Copy this to use on Slaves!)";
    }

    /**
     * Called by "Show/Copy Token" button.
     */
    public function ShowToken(): void {
        $token = $this->ReadPropertyString("AuthToken");
        if ($token === "") {
            echo "No token set yet.";
        } else {
            echo "YOUR SYNC TOKEN:\n\n" . $token . "\n\n(Select text and Ctrl+C to copy)";
        }
    }

    // -------------------------------------------------------------------------
    // PUBLIC FUNCTIONS
    // -------------------------------------------------------------------------

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
            if (is_array($val) || is_object($val)) {
                $json = json_encode($val);
                return $json === false ? "" : $json;
            }
            return (string)$val;
        }

        trigger_error("SecretsManager: Secret '$ident' not found.", E_USER_NOTICE);
        return "";
    }

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
            
            // Add Basic Auth Header
            if (isset($slave['User']) && isset($slave['Pass']) && $slave['User'] !== "") {
                $auth = base64_encode($slave['User'] . ":" . $slave['Pass']);
                $headers .= "Authorization: Basic " . $auth . "\r\n";
            }

            // --- THE FIX IS HERE ---
            // We explicitly tell PHP to trust ANY certificate (Self-Signed or IP-based)
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
            
            // Execute Request
            $result = @file_get_contents($slave['Url'], false, $ctx);
            
            // Analyze Result
            if ($result === false) {
                // If it fails here with HTTPS, it usually means the port is wrong 
                // (e.g. trying HTTPS on port 3777 which is usually HTTP)
                $error = error_get_last();
                $errorMsg = $error['message'] ?? 'Unknown Error';
                $this->LogMessage("❌ Sync Network Error: " . $slave['Url'] . " -> " . $errorMsg, KL_ERROR);
            } else {
                $statusLine = $http_response_header[0] ?? "Unknown"; 
                
                if (strpos($statusLine, "200") !== false && trim($result) === "OK") {
                    $this->LogMessage("✅ Sync Success: " . $slave['Url'], KL_MESSAGE);
                    $successCount++;
                } else {
                    $this->LogMessage("❌ Sync Rejected: " . $slave['Url'] . " -> " . $statusLine . " (Msg: " . trim($result) . ")", KL_ERROR);
                }
            }
        }
        
        if ($successCount > 0) {
            echo "Sync completed. Success: $successCount / Total: " . count($slaves);
        } else {
            echo "Sync FAILED. Check messages log for details.";
        }
    }

    protected function ProcessHookData(): void {
        // 1. Basic Auth Check (Defense Layer 1)
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

        // 2. Token Check (Defense Layer 2)
        $input = file_get_contents("php://input");
        $data = json_decode($input, true);

        if (($data['auth'] ?? '') !== $this->ReadPropertyString("AuthToken")) {
            header("HTTP/1.1 403 Forbidden");
            echo "Invalid Token";
            return;
        }

        // 3. Process Data
        if (isset($data['key'])) {
            $this->_writeKey($data['key']);
        }

        if (isset($data['vault'])) {
            $this->SetValue("Vault", $data['vault']);
            $this->SetBuffer("DecryptedCache", ""); 
        }

        echo "OK";
    }

    // --- INTERNAL HELPERS ---

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