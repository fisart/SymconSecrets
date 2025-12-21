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

        // Input Buffer (Used for "Native Save" workflow)
        $this->RegisterPropertyString("InputJson", "");
        
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        // Internal Storage
        $this->RegisterVariableString("Vault", "Encrypted Vault");
        
        // Note: Variable is hidden in ApplyChanges to be Module Store compliant
    }

    /**
     * DYNAMIC FORM GENERATION
     * Controls visibility of Master vs Slave fields.
     * (Simplified: Removed the Editor Locked/Unlocked logic as buttons are gone)
     */
    public function GetConfigurationForm(): string {
        $json = json_decode(file_get_contents(__DIR__ . "/form.json"), true);
        
        $mode = $this->ReadPropertyInteger("OperationMode");
        $isMaster = ($mode === 1);
        $isSlave = ($mode === 0);

        foreach ($json['elements'] as &$element) {
            $name = $element['name'] ?? '';

            // --- SLAVE SPECIFIC UI ---
            if ($name === 'HookInfo') {
                $element['caption'] = "This Instance WebHook: /hook/secrets_" . $this->InstanceID;
                $element['visible'] = $isSlave; 
            }
            if (in_array($name, ['LabelHookAuth', 'HookUser', 'HookPass'])) {
                if (!$isSlave) $element['visible'] = false;
            }

            // --- MASTER SPECIFIC UI ---
            if (in_array($name, ['BtnGenToken', 'SlaveURLs', 'LabelSeparator', 'LabelMasterHead', 'InputJson'])) {
                if (!$isMaster) $element['visible'] = false;
            }
            // Note: BtnLoad, BtnEncrypt, BtnClear are removed from form.json, so no need to hide them here.
        }

        // Actions Bar
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
        
        // Module Store Compliance: Hide variable here
        $vaultID = @$this->GetIDForIdent("Vault");
        if ($vaultID) {
            IPS_SetHidden($vaultID, true);
        }

        @$this->RegisterHook("secrets_" . $this->InstanceID);
        $this->SetBuffer("DecryptedCache", ""); 

        // Validate Directory Logic
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $mode = $this->ReadPropertyInteger("OperationMode");
        
        $errorMessage = "";
        
        if ($folder === "") {
            $this->SetStatus(104); // IS_INACTIVE
        } elseif (!is_dir($folder)) {
            $errorMessage = "Directory does not exist: " . $folder;
            $this->SetStatus(202); 
        } elseif ($mode === 1 && !is_writable($folder)) {
            $errorMessage = "Directory is not writable: " . $folder;
            $this->SetStatus(202); 
        } else {
            $this->SetStatus(102); // IS_ACTIVE
        }

        $this->UpdateFormLayout($errorMessage);

        // --- NATIVE SAVE WORKFLOW ---
        // If we are Master and there is text in InputJson, assume User wants to Encrypt & Save.
        if ($mode === 1 && $this->GetStatus() === 102) {
            $input = $this->ReadPropertyString("InputJson");
            
            if ($input !== "") {
                // 1. Validate
                $decoded = json_decode($input, true);
                if ($decoded === null) {
                    // We cannot abort ApplyChanges easily with a popup, 
                    // so we log an error and do NOT clear the input (giving user a chance to fix it)
                    $this->LogMessage("❌ SecretsManager: JSON Syntax Error. Data NOT saved.", KL_ERROR);
                    echo "❌ ERROR: Invalid JSON Syntax. Changes NOT saved. Check Message Log.";
                } else {
                    // 2. Encrypt & Save
                    if ($this->_encryptAndSave($decoded)) {
                        $this->LogMessage("✅ SecretsManager: Secrets encrypted and saved.", KL_MESSAGE);
                        
                        // 3. Wipe Input (Security)
                        // We must use IPS_SetProperty directly to clear the persistence
                        IPS_SetProperty($this->InstanceID, "InputJson", "");
                        // We do NOT call IPS_ApplyChanges again here to avoid infinite loops.
                        // The property is cleared in DB, next reload will show empty field.
                        
                        // 4. Auto-Sync to Slaves
                        $this->SyncSlaves();
                    }
                }
            }
        }
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
    // BUTTON ACTIONS
    // =========================================================================

    public function CheckDirectory(): void {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $mode = $this->ReadPropertyInteger("OperationMode");

        if ($folder === "") { echo "No directory entered yet."; return; }
        if (!is_dir($folder)) { echo "❌ ERROR: Directory not found!\n\nPath: $folder"; return; }
        if ($mode === 1 && !is_writable($folder)) { echo "❌ ERROR: Directory is NOT writable!\n\nPath: $folder"; return; }

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

    /**
     * UNLOCK Button Action (from form.json "BtnLoad")
     * Reads the vault and puts it into the input field for editing.
     */
    public function LoadVault(): void {
        $cache = $this->_decryptVault();
        
        if ($cache === false) {
            if ($this->GetValue("Vault") === "") {
                $json = "{}";
            } else {
                echo "❌ Error: Could not decrypt vault. Check Key File.";
                return;
            }
        } else {
            // Pretty Print for editing
            $json = json_encode($cache, JSON_PRETTY_PRINT);
        }

        // Push decrypted text to the form field
        $this->UpdateFormField("InputJson", "value", $json);
        echo "Data Loaded. Edit and click 'Save Changes'.";
    }

    // =========================================================================
    // PUBLIC API
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
                if($this->GetValue("Vault") !== "") $this->LogMessage("Decryption failed. Check Key File.", KL_ERROR);
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
        if ($this->ReadPropertyInteger("OperationMode") !== 1) return;
        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        if (!is_array($slaves)) return;

        $keyHex = $this->_readKey();
        $vault = $this->GetValue("Vault");
        $token = $this->ReadPropertyString("AuthToken");
        
        $payload = json_encode(['auth' => $token, 'key' => $keyHex, 'vault'=> $vault]);
        $success = 0;

        foreach ($slaves as $slave) {
            if (!isset($slave['Url']) || $slave['Url'] == "") continue;
            
            $headers = "Content-type: application/json\r\n";
            if (isset($slave['User']) && isset($slave['Pass']) && $slave['User'] !== "") {
                $auth = base64_encode($slave['User'] . ":" . $slave['Pass']);
                $headers .= "Authorization: Basic " . $auth . "\r\n";
            }

            $options = [
                'http' => [
                    'method' => 'POST', 'header' => $headers, 'content'=> $payload, 'timeout'=> 5, 'ignore_errors' => true
                ],
                'ssl' => [
                    'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true
                ]
            ];
            $ctx = stream_context_create($options);
            
            $res = @file_get_contents($slave['Url'], false, $ctx);
            $statusLine = $http_response_header[0] ?? "Unknown";

            if ($res !== false && strpos($statusLine, "200") !== false && trim($res) === "OK") {
                $this->LogMessage("✅ Synced: " . $slave['Url'], KL_MESSAGE);
                $success++;
            } else {
                $this->LogMessage("❌ Failed: " . $slave['Url'] . " -> " . $statusLine . " (Msg: " . trim($res) . ")", KL_ERROR);
            }
        }
        
        // Echo only if manually triggered via button, logic inside SyncSlaves handles log messages.
    }

    protected function ProcessHookData(): void {
        $hookUser = $this->ReadPropertyString("HookUser");
        $hookPass = $this->ReadPropertyString("HookPass");

        if ($hookUser !== "" && $hookPass !== "") {
            if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER'] !== $hookUser || $_SERVER['PHP_AUTH_PW'] !== $hookPass) {
                header('WWW-Authenticate: Basic realm="SecretsManager"');
                header('HTTP/1.0 401 Unauthorized');
                echo 'Auth Required';
                return;
            }
        }

        $input = file_get_contents("php://input");
        $data = json_decode($input, true);

        if (($data['auth'] ?? '') !== $this->ReadPropertyString("AuthToken")) {
            header("HTTP/1.1 403 Forbidden");
            echo "Invalid Token";
            return;
        }

        if (isset($data['key'])) $this->_writeKey($data['key']);
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
        $iv = random_bytes(openssl_cipher_iv_length("aes-128-gcm"));
        $tag = ""; 
        $cipherText = openssl_encrypt(json_encode($dataArray), "aes-128-gcm", $newKeyBin, 0, $iv, $tag);
        if ($cipherText === false) return false;
        $this->SetValue("Vault", json_encode(['cipher'=>"aes-128-gcm",'iv'=>bin2hex($iv),'tag'=>bin2hex($tag),'data'=>$cipherText]));
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

    private function _readKey() { return $this->_loadOrGenerateKey(); }
    private function _writeKey(string $hexKey): void { 
        $p = $this->_getFullPath(); 
        if ($p !== "") file_put_contents($p, $hexKey); 
    }
    private function _getCache() {
        $d = $this->GetBuffer("DecryptedCache");
        if ($d === "") return null;
        return json_decode($d, true);
    }
    private function _setCache(array $a): void { $this->SetBuffer("DecryptedCache", json_encode($a)); }
}
?>