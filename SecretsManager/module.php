<?php

declare(strict_types=1);

class SecretsManager extends IPSModuleStrict {

    // HARDCODED FILENAME for security consistency
    private const KEY_FILENAME = 'master.key';

    public function Create(): void {
        parent::Create();

        // 0 = Slave, 1 = Master
        $this->RegisterPropertyInteger("OperationMode", 0);
        
        // Configuration: Now stores the Folder, not the full file path
        $this->RegisterPropertyString("KeyFolderPath", ""); 
        
        $this->RegisterPropertyString("AuthToken", "");
        $this->RegisterPropertyString("InputJson", "");
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        $this->RegisterVariableString("Vault", "Encrypted Vault");
    }

    public function ApplyChanges(): void {
        parent::ApplyChanges();
        
        // Register WebHook (Suppress warning if exists)
        @$this->RegisterHook("secrets_" . $this->InstanceID);

        // Clear RAM Cache
        $this->SetBuffer("DecryptedCache", ""); 

        // Update UI visibility
        $this->UpdateUI();
        
        // VALIDATION LOGIC
        $folder = $this->ReadPropertyString("KeyFolderPath");
        
        if ($folder !== "") {
            // 1. Check if Directory Exists
            if (!is_dir($folder)) {
                $this->LogMessage("Security Alert: The Key Directory does not exist: $folder", KL_ERROR);
                $this->UpdateFormField("StatusLabel", "caption", "Error: Directory not found!");
            } 
            // 2. Check Permissions (If Master, must be writable)
            elseif ($this->ReadPropertyInteger("OperationMode") === 1 && !is_writable($folder)) {
                $this->LogMessage("Security Alert: The Key Directory is not writable: $folder", KL_ERROR);
                $this->UpdateFormField("StatusLabel", "caption", "Error: Directory not writable!");
            }
            // 3. Check if Key File exists inside
            else {
                $fullPath = $this->_getFullPath();
                if (file_exists($fullPath)) {
                    $this->UpdateFormField("StatusLabel", "caption", "OK: Key found at " . self::KEY_FILENAME);
                } else {
                    $this->UpdateFormField("StatusLabel", "caption", "Setup: Key will be created on save.");
                }
            }
        }
    }

    public function GenerateToken(): void {
        $token = bin2hex(random_bytes(32));
        $this->UpdateFormField("AuthToken", "value", $token);
        echo "Token Generated!\n\n$token\n\n(It has been inserted into the field. Copy this to use on Slaves!)";
    }

    public function UpdateUI(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");
        
        $hookUrl = "/hook/secrets_" . $this->InstanceID;
        $this->UpdateFormField("HookInfo", "caption", "This Instance WebHook: " . $hookUrl);
        $this->UpdateFormField("HookInfo", "visible", true);

        $this->UpdateFormField("InputJson", "visible", ($mode === 1));
        $this->UpdateFormField("BtnEncrypt", "visible", ($mode === 1));
        $this->UpdateFormField("SlaveURLs", "visible", ($mode === 1));
        $this->UpdateFormField("BtnSync", "visible", ($mode === 1));
    }

    public function GetSecret(string $ident): string {
        $cache = $this->_getCache();

        if ($cache === null) {
            $cache = $this->_decryptVault();
            if ($cache === false) {
                // Only log if vault has data
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

    protected function ProcessHookData(): void {
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

    // Construct the full path safely
    private function _getFullPath(): string {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if ($folder === "") return "";
        
        // Remove trailing slashes and append standard filename
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