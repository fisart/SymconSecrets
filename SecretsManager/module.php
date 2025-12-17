<?php

declare(strict_types=1);

class SecretsManager extends IPSModuleStrict {

    public function Create(): void {
        parent::Create();

        // 0 = Slave, 1 = Master
        $this->RegisterPropertyInteger("OperationMode", 0);
        
        // Configuration
        $this->RegisterPropertyString("KeyFilePath", "");
        $this->RegisterPropertyString("AuthToken", "");
        
        // This property acts as a temporary input buffer for the JSON
        $this->RegisterPropertyString("InputJson", "");
        
        // Slave Configuration
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        // Internal Storage for the Encrypted Vault
        // In Strict mode, variables are ReadOnly by default (Perfect for us)
        $this->RegisterVariableString("Vault", "Encrypted Vault");
        
        // Register WebHook for receiving updates
        $this->RegisterHook("secrets");
    }

    public function ApplyChanges(): void {
        parent::ApplyChanges();
        
        // Clear Cache when config changes
        $this->SetBuffer("DecryptedCache", ""); 

        // Update UI Visibility
        $this->UpdateUI();
        
        // Validate Key File (Just a check, no logic changes)
        $path = $this->ReadPropertyString("KeyFilePath");
        if ($path !== "" && !file_exists($path) && $this->ReadPropertyInteger("OperationMode") === 1) {
             // If Master and key missing, we log a warning but don't auto-create until user saves
             $this->LogMessage("Master Key missing at: $path", KL_WARNING);
        }
    }

    // Helper to control form visibility
    public function UpdateUI(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");
        // Hide Input fields if Slave (0)
        $this->UpdateFormField("InputJson", "visible", ($mode === 1));
        $this->UpdateFormAction("Encrypt & Save Local", "visible", ($mode === 1));
        $this->UpdateFormField("SlaveURLs", "visible", ($mode === 1));
        $this->UpdateFormAction("Manually Sync to Slaves", "visible", ($mode === 1));
    }

    // -------------------------------------------------------------------------
    // PUBLIC FUNCTIONS
    // -------------------------------------------------------------------------

    /**
     * Gets a decrypted secret by its identifier.
     * Usage: SEC_GetSecret(12345, 'Spotify');
     */
    public function GetSecret(string $ident): string {
        $cache = $this->_getCache();

        if ($cache === null) {
            $cache = $this->_decryptVault();
            if ($cache === false) {
                // Return empty string on failure to avoid fatal PHP errors in strict mode, 
                // but log error.
                $this->LogMessage("Decryption failed. Check Key File.", KL_ERROR);
                return "";
            }
            $this->_setCache($cache);
        }

        // Handle complex objects vs simple strings
        if (isset($cache[$ident])) {
            $val = $cache[$ident];
            if (is_array($val) || is_object($val)) {
                return json_encode($val);
            }
            return (string)$val;
        }

        trigger_error("SecretsManager: Secret '$ident' not found.", E_USER_NOTICE);
        return "";
    }

    /**
     * Called by the button "Encrypt & Save Local"
     */
    public function EncryptAndSave(): void {
        if ($this->ReadPropertyInteger("OperationMode") !== 1) {
            echo "Only Master can encrypt data.";
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

        // Perform Encryption
        $result = $this->_encryptAndSave($decoded);

        if ($result) {
            // Security: Clear the input field
            IPS_SetProperty($this->InstanceID, "InputJson", "");
            IPS_ApplyChanges($this->InstanceID);
            echo "Success: Data encrypted and saved.";
            
            // Auto-Sync
            $this->SyncSlaves();
        } else {
            echo "Error: Encryption failed (Check Key File permissions).";
        }
    }

    /**
     * Called by button "Manually Sync to Slaves"
     */
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

        $ctx = stream_context_create(['http' => [
            'method'  => 'POST',
            'header'  => "Content-type: application/json\r\n",
            'content' => $payload,
            'timeout' => 5
        ]]);

        $count = 0;
        foreach ($slaves as $slave) {
            if (isset($slave['Url'])) {
                @file_get_contents($slave['Url'], false, $ctx);
                $count++;
            }
        }
        $this->LogMessage("Synced to $count slaves.", KL_MESSAGE);
    }

    // -------------------------------------------------------------------------
    // WEBHOOK (Receiver)
    // -------------------------------------------------------------------------
    protected function ProcessHookData(): void {
        $input = file_get_contents("php://input");
        $data = json_decode($input, true);

        if (($data['auth'] ?? '') !== $this->ReadPropertyString("AuthToken")) {
            header("HTTP/1.1 403 Forbidden");
            echo "Forbidden";
            return;
        }

        // 1. Write Key
        if (isset($data['key'])) {
            $this->_writeKey($data['key']);
        }

        // 2. Write Vault (Using Strict SetValue)
        if (isset($data['vault'])) {
            $this->SetValue("Vault", $data['vault']);
            // Invalidate Cache
            $this->SetBuffer("DecryptedCache", ""); 
        }

        echo "OK";
    }

    // -------------------------------------------------------------------------
    // INTERNAL HELPERS
    // -------------------------------------------------------------------------

    private function _encryptAndSave(array $dataArray): bool {
        // Generate new key or load existing? 
        // Strategy: Use existing key if possible, only generate if missing.
        // Or: Rotate key on every save? Let's keep it simple: Load or Generate.
        $keyHex = $this->_loadOrGenerateKey();
        if (!$keyHex) return false;

        $newKeyBin = hex2bin($keyHex);
        $plain = json_encode($dataArray);
        
        $cipher = "aes-128-gcm";
        $iv = random_bytes(openssl_cipher_iv_length($cipher));
        
        $cipherText = openssl_encrypt($plain, $cipher, $newKeyBin, 0, $iv, $tag);

        if ($cipherText === false) return false;

        $vaultData = json_encode([
            'cipher' => $cipher,
            'iv' => bin2hex($iv),
            'tag'=> bin2hex($tag),
            'data'=> $cipherText
        ]);

        // Strict Mode SetValue
        $this->SetValue("Vault", $vaultData);
        // Update Cache
        $this->_setCache($dataArray);
        
        return true;
    }

    private function _decryptVault() {
        $vaultJson = $this->GetValue("Vault");
        if (!$vaultJson) return [];

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
        $path = $this->ReadPropertyString("KeyFilePath");
        if ($path === "") return false;

        if (file_exists($path)) {
            return trim(file_get_contents($path));
        }

        // Create if Master
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
        $path = $this->ReadPropertyString("KeyFilePath");
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