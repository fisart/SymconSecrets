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
        
        // Input Buffer
        $this->RegisterPropertyString("InputJson", "");
        
        // Slave Configuration
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        // Internal Storage (ReadOnly by default in Strict)
        $this->RegisterVariableString("Vault", "Encrypted Vault");
        
        // REMOVED RegisterHook from here to prevent duplicate registration warning
    }

    public function ApplyChanges(): void {
        parent::ApplyChanges();
        
        // Register WebHook (Only do this here)
        // This links /hook/secrets_12345 to this instance
        $this->RegisterHook("secrets_" . $this->InstanceID);

        // Clear Cache
        $this->SetBuffer("DecryptedCache", ""); 

        // UI
        $this->UpdateUI();
        
        // Validate Key File
        $path = $this->ReadPropertyString("KeyFilePath");
        if ($path !== "" && !file_exists($path) && $this->ReadPropertyInteger("OperationMode") === 1) {
             $this->LogMessage("Master Key missing at: $path", KL_WARNING);
        }
    }

    public function UpdateUI(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");
        
        // Show the WebHook URL to the user
        $hookUrl = "/hook/secrets_" . $this->InstanceID;
        $this->UpdateFormField("HookInfo", "caption", "This Instance WebHook: " . $hookUrl);
        // Show Hook info on Slave, Hide on Master (optional preference)
        // Showing it on Master is also fine so you can see what ID it has.
        $this->UpdateFormField("HookInfo", "visible", true);

        // Hide Input fields if Slave (0)
        $this->UpdateFormField("InputJson", "visible", ($mode === 1));
        
        // Hide Buttons
        $this->UpdateFormField("BtnEncrypt", "visible", ($mode === 1));
        $this->UpdateFormField("SlaveURLs", "visible", ($mode === 1));
        $this->UpdateFormField("BtnSync", "visible", ($mode === 1));
    }

    public function GetSecret(string $ident): string {
        $cache = $this->_getCache();

        if ($cache === null) {
            $cache = $this->_decryptVault();
            if ($cache === false) {
                $this->LogMessage("Decryption failed. Check Key File.", KL_ERROR);
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
        $path = $this->ReadPropertyString("KeyFilePath");
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