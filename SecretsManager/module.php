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
        
        // New: Basic Auth Properties
        $this->RegisterPropertyString("HookUser", "");
        $this->RegisterPropertyString("HookPass", "");

        $this->RegisterPropertyString("InputJson", "");
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        // Internal Storage
        $this->RegisterVariableString("Vault", "Encrypted Vault");
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

        // 2. Update UI (Show/Hide Error Header based on validation)
        $this->UpdateUI($errorMessage);
    }

    /**
     * Called by "Check Directory Permissions" button.
     * Triggers a Modal Popup via echo.
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

    public function UpdateUI(string $errorMessage = ""): void {
        $mode = $this->ReadPropertyInteger("OperationMode");
        
        // Handle Error Header Visibility
        if ($errorMessage !== "") {
            $this->UpdateFormField("HeaderError", "visible", true);
            $this->UpdateFormField("HeaderError", "caption", "!!! CONFIGURATION ERROR: " . $errorMessage . " !!!");
            $this->UpdateFormField("StatusLabel", "caption", "Error: " . $errorMessage);
        } else {
            $this->UpdateFormField("HeaderError", "visible", false);
            $this->UpdateFormField("StatusLabel", "caption", "Instance OK");
        }

        // General UI
        $hookUrl = "/hook/secrets_" . $this->InstanceID;
        $this->UpdateFormField("HookInfo", "caption", "This Instance WebHook: " . $hookUrl);
        
        // Master/Slave Visibility
        $this->UpdateFormField("InputJson", "visible", ($mode === 1));
        $this->UpdateFormField("BtnEncrypt", "visible", ($mode === 1));
        $this->UpdateFormField("SlaveURLs", "visible", ($mode === 1));
        $this->UpdateFormField("BtnSync", "visible", ($mode === 1));
        // We keep HookUser/HookPass visible for both (Master might want self-protection too)
    }

    // -------------------------------------------------------------------------
    // PUBLIC FUNCTIONS
    // -------------------------------------------------------------------------

    /**
     * Returns a JSON encoded array of all available top-level keys.
     */
    public function GetKeys(): string {
        // Stop if instance is broken
        if ($this->GetStatus() !== 102) return json_encode([]);

        $cache = $this->_getCache();

        if ($cache === null) {
            $cache = $this->_decryptVault();
            if ($cache === false) return json_encode([]);
            $this->_setCache($cache);
        }

        // Return just the keys
        return json_encode(array_keys($cache));
    }

    public function GetSecret(string $ident): string {
        // Stop if instance is broken
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

    public function EncryptAndSave(): void {
        if ($this->ReadPropertyInteger("OperationMode") !== 1) {
            echo "Only Master can encrypt data.";
            return;
        }

        // Stop if directory is bad
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if (!is_dir($folder) || !is_writable($folder)) {
            echo "Error: Directory invalid or not writable. Encryption aborted.";
            return;
        }

        $jsonInput = $this->ReadPropertyString("InputJson");
        if (trim($jsonInput) === "") {
            echo "Input is empty.";
            return;
        }

        $decoded = json_decode($jsonInput, true);
        if ($decoded === null) {
            echo "Error: Invalid JSON Format.";
            return;
        }

        $result = $this->_encryptAndSave($decoded);

        if ($result) {
            IPS_SetProperty($this->InstanceID, "InputJson", "");
            IPS_ApplyChanges($this->InstanceID);
            echo "Success: Data encrypted and saved.";
            $this->SyncSlaves();
        } else {
            echo "Error: Encryption failed.";
        }
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

        $count = 0;
        foreach ($slaves as $slave) {
            if (!isset($slave['Url']) || $slave['Url'] == "") continue;

            $headers = "Content-type: application/json\r\n";
            
            // Add Basic Auth Header if columns are filled
            if (isset($slave['User']) && isset($slave['Pass']) && $slave['User'] !== "") {
                $auth = base64_encode($slave['User'] . ":" . $slave['Pass']);
                $headers .= "Authorization: Basic " . $auth . "\r\n";
            }

            $ctx = stream_context_create(['http' => [
                'method' => 'POST',
                'header' => $headers,
                'content'=> $payload,
                'timeout'=> 5
            ]]);
            
            @file_get_contents($slave['Url'], false, $ctx);
            $count++;
        }
        $this->LogMessage("Synced to $count slaves.", KL_MESSAGE);
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
            echo "Forbidden";
            return;
        }

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