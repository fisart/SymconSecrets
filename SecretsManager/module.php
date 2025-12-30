<?php

declare(strict_types=1);

/**
 * SecretsManager Class
 * 
 * A secure credential manager for IP-Symcon that encrypts secrets using AES-128-GCM.
 * It features a Master-Slave architecture and a local Standalone mode.
 * 
 * @author Artur Fischer
 * @version 1.1
 */
class SecretsManager extends IPSModuleStrict {

    // The name of the key file stored on the OS
    private const KEY_FILENAME = 'master.key';

    /**
     * Create is called when the instance is created in the IP-Symcon console.
     */
    public function Create(): void {
        // Never delete this line!
        parent::Create();

        // 0 = Slave (Receiver), 1 = Master (Sender), 2 = Standalone (Local Vault Only)
        $this->RegisterPropertyInteger("OperationMode", 0);
        
        // Key Storage Configuration
        $this->RegisterPropertyString("KeyFolderPath", ""); 
        
        // Authentication Token for Synchronization
        $this->RegisterPropertyString("AuthToken", "");
        
        // Basic Auth Properties (Optional Protection for WebHook)
        $this->RegisterPropertyString("HookUser", "");
        $this->RegisterPropertyString("HookPass", "");
        
        // List of Slaves (Master Only)
        $this->RegisterPropertyString("SlaveURLs", "[]"); 

        // Internal Storage for the Encrypted Blob
        $this->RegisterVariableString("Vault", "Encrypted Vault");
    }
public function SyncList($Value): void
{
    // $Value kann je nach Symcon-Version ein IPSList/Array/stdClass/JSON-String sein
    $listData = [];

    if (is_string($Value)) {
        $decoded = json_decode($Value, true);
        $listData = is_array($decoded) ? $decoded : [];
    } elseif (is_iterable($Value)) {
        foreach ($Value as $row) {
            $listData[] = $row;
        }
    } elseif (is_array($Value)) {
        $listData = $Value;
    }

    $this->SyncListToBuffer($listData);
}
    /**
     * DYNAMIC FORM GENERATION
     */
    public function GetConfigurationForm(): string {
        // 1. Load the static JSON template
        $formPath = __DIR__ . "/form.json";
        if (!file_exists($formPath)) {
            return json_encode(['elements' => [['type' => 'Label', 'caption' => 'Critical Error: form.json not found!']]]);
        }
        
        $formText = file_get_contents($formPath);
        $json = json_decode($formText, true);

        if ($json === null) {
            return json_encode(['elements' => [['type' => 'Label', 'caption' => 'Critical Error: form.json is invalid!']]]);
        }
        
        // 2. Read current settings and RAM state
        $mode = $this->ReadPropertyInteger("OperationMode");
        $isUnlocked = ($this->GetBuffer("IsUnlocked") === "true"); 

        $isSlave      = ($mode === 0);
        $isMaster     = ($mode === 1);
        $isStandalone = ($mode === 2);
        
        $isEditorRole = ($isMaster || $isStandalone);
        $isSyncRole   = ($isMaster || $isSlave);

        // 3. Process Main Elements (Hide/Show fields)
        if (isset($json['elements'])) {
            foreach ($json['elements'] as &$element) {
                $name = $element['name'] ?? '';

                if ($name === 'HookInfo') {
                    $element['caption'] = "WebHook URL: /hook/secrets_" . $this->InstanceID;
                    $element['visible'] = $isSlave; 
                }
                
                if (in_array($name, ['LabelHookAuth', 'HookUser', 'HookPass'])) {
                    $element['visible'] = $isSlave;
                }

                if (in_array($name, ['SlaveURLs', 'LabelSeparator', 'LabelMasterHead', 'BtnGenToken'])) {
                    $element['visible'] = $isMaster;
                }

                if (in_array($name, ['AuthToken', 'BtnShowToken'])) {
                    $element['visible'] = $isSyncRole;
                }

                // EDITOR WORKFLOW VISIBILITY
                if (in_array($name, ['BtnDiagnose', 'LabelSecurityWarning', 'PanelAddEntry', 'BtnEncrypt', 'BtnClear', 'EditorList'])) {
                    $element['visible'] = $isUnlocked;
                }
                
                if ($name === 'LabelPath') {
                    $element['visible'] = $isUnlocked;
                    if ($isUnlocked) {
                        $path = json_decode($this->GetBuffer("CurrentPath"), true) ?: [];
                        $element['caption'] = "Current Path: Root" . (count($path) > 0 ? " > " . implode(" > ", $path) : "");
                    }
                }
                
                if ($name === 'BtnBack') {
                    $path = json_decode($this->GetBuffer("CurrentPath"), true) ?: [];
                    $element['visible'] = ($isUnlocked && count($path) > 0);
                }
                
                if ($name === 'EditorList' && $isUnlocked) {
                    $element['values'] = $this->PrepareListValues();
                }

                if ($name === 'BtnLoad') {
                    $element['visible'] = ($isEditorRole && !$isUnlocked);
                }
            }
        }

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
        
        $vaultID = @$this->GetIDForIdent("Vault");
        if ($vaultID) {
            IPS_SetHidden($vaultID, true);
        }

        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode === 0) {
            @$this->RegisterHook("secrets_" . $this->InstanceID);
        }

        $this->SetBuffer("DecryptedCache", ""); 
        
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $errorMessage = "";
        
        if ($folder === "") {
            $this->SetStatus(104); 
        } elseif (!is_dir($folder)) {
            $errorMessage = "Directory does not exist: " . $folder;
            $this->SetStatus(202); 
        } elseif ($mode !== 0 && !is_writable($folder)) {
            $errorMessage = "Directory is not writable: " . $folder;
            $this->SetStatus(202);
        } else {
            $this->SetStatus(102); 
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
            $this->UpdateFormField("StatusLabel", "caption", "Instance OK (Idle)");
        }
    }

    /**
     * Synchronizes the UI list state into the RAM buffer.
     * Handles IPSList objects from Symcon 8.1 correctly.
     */
 public function SyncList(string $Value): void
{
    // In der Form kommt $Value als JSON-String
    $listData = json_decode($Value, true);
    if (!is_array($listData)) {
        $listData = [];
    }

    $this->SyncListToBuffer($listData);
}

    // =========================================================================
    // CONFIGURATION ACTIONS
    // =========================================================================

    public function CheckDirectory(): void {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $mode = $this->ReadPropertyInteger("OperationMode");

        if ($folder === "") { echo "Warning: No path entered."; return; }
        if (!is_dir($folder)) { echo "❌ ERROR: Not found: $folder"; return; }
        if ($mode !== 0 && !is_writable($folder)) { echo "❌ ERROR: Not writable!"; return; }

        $f = $this->_getFullPath();
        echo "✅ SUCCESS!\n\nKey File: " . (file_exists($f) ? "Found." : "Will be created.");
    }

    public function GenerateToken(): void {
        $token = bin2hex(random_bytes(32));
        $this->UpdateFormField("AuthToken", "value", $token);
        echo "Token generated.";
    }

    public function ShowToken(): void {
        $token = $this->ReadPropertyString("AuthToken");
        echo ($token === "") ? "No token set." : "YOUR TOKEN:\n\n" . $token;
    }

    public function Test(): void {
        echo "VERBINDUNG OK!";
    }

    // =========================================================================
    // EDITOR ACTIONS
    // =========================================================================

    public function LoadVault(): void {
        $cache = $this->_decryptVault();
        if ($cache === false) {
            $vaultValue = $this->GetValue("Vault");
            if ($vaultValue === "" || $vaultValue === "Encrypted Vault") {
                $cache = [];
            } else {
                echo "❌ Error: Decryption failed.";
                return;
            }
        }

        $this->SetBuffer("DecryptedCache", json_encode($cache));
        $this->SetBuffer("CurrentPath", json_encode([]));
        $this->SetBuffer("IsUnlocked", "true");
        $this->ReloadForm();
    }

    public function ClearVault(): void {
        $this->SetBuffer("DecryptedCache", "");
        $this->SetBuffer("CurrentPath", "");
        $this->SetBuffer("IsUnlocked", "false");
        $this->ReloadForm();
    }

    /**
     * Handles navigation (Open Folder) using the Key name.
     */
    public function HandleListAction(string $Key): void {
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        $temp = &$this->getCurrentLevelReference($fullData);

        if (isset($temp[$Key]) && is_array($temp[$Key])) {
            $path = json_decode($this->GetBuffer("CurrentPath"), true) ?: [];
            $path[] = $Key;
            $this->SetBuffer("CurrentPath", json_encode($path));
            $this->ReloadForm();
        }
    }

    /**
     * Navigates one level back up.
     */
    public function NavigateUp(): void {
        $path = json_decode($this->GetBuffer("CurrentPath"), true) ?: [];
        if (count($path) > 0) {
            array_pop($path);
            $this->SetBuffer("CurrentPath", json_encode($path));
            $this->ReloadForm();
        }
    }

    /**
     * Updates a field based on the Key name.
     */
    public function UpdateValue(string $Key, string $Field, string $Value): void {
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        $temp = &$this->getCurrentLevelReference($fullData);

        if (isset($temp[$Key])) {
            if (!is_array($temp[$Key])) {
                $temp[$Key] = ['PW' => (string)$temp[$Key], 'User' => '', 'URL' => '', 'Location' => '', 'IP' => ''];
            }
            $temp[$Key][$Field] = $Value;
            $this->SetBuffer("DecryptedCache", json_encode($fullData));
        }
    }

    /**
     * Adds a new folder or a new secret to the current path.
     */
    public function AddEntry(string $NewKeyName, string $NewKeyType): void {
        if (trim($NewKeyName) === "") return;

        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        $temp = &$this->getCurrentLevelReference($fullData);

        if ($NewKeyType === "object") {
            $temp[$NewKeyName] = []; 
        } else {
            $temp[$NewKeyName] = ['User' => '', 'PW' => '', 'URL' => '', 'Location' => '', 'IP' => ''];
        }

        $this->SetBuffer("DecryptedCache", json_encode($fullData));
        $this->ReloadForm();
    }

    /**
     * Encrypts the current RAM state and saves it permanently.
     */
    public function EncryptAndSave(): void {
        if ($this->ReadPropertyInteger("OperationMode") === 0) return;
        
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];

        if ($this->_encryptAndSave($fullData)) {
            $this->ClearVault();
            echo "✅ SUCCESS: Vault encrypted and saved.";
            if ($this->ReadPropertyInteger("OperationMode") === 1) $this->SyncSlaves();
        }
    }

    private function PrepareListValues(): array {
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        $temp = $this->getCurrentLevelReference($fullData);
        
        $values = [];
        if (is_array($temp)) {
            ksort($temp);
            foreach ($temp as $key => $val) {
                $isObj = is_array($val);
                $isFolder = false;
                if ($isObj) {
                    foreach ($val as $v) { if (is_array($v)) { $isFolder = true; break; } }
                    if (isset($val['PW']) || isset($val['User'])) $isFolder = false;
                }

                $values[] = [
                    'Key'      => (string)$key,
                    'User'     => ($isObj && !$isFolder) ? ($val['User'] ?? '') : '',
                    'PW'       => ($isObj && !$isFolder) ? ($val['PW'] ?? '') : (!$isObj ? (string)$val : ''),
                    'URL'      => ($isObj && !$isFolder) ? ($val['URL'] ?? '') : '',
                    'Location' => ($isObj && !$isFolder) ? ($val['Location'] ?? '') : '',
                    'IP'       => ($isObj && !$isFolder) ? ($val['IP'] ?? '') : '',
                    'Type'     => $isFolder ? "Folder" : "Secret",
                    'Action'   => $isFolder ? "📂 Open" : "---"
                ];
            }
        }
        return $values;
    }

    private function &getCurrentLevelReference(&$fullData) {
        $path = json_decode($this->GetBuffer("CurrentPath"), true);
        $level = &$fullData;
        if (is_array($path)) {
            foreach ($path as $step) {
                if (isset($level[$step]) && is_array($level[$step])) $level = &$level[$step];
            }
        }
        return $level;
    }

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    public function GetSecret(string $ident): string {
        $cache = json_decode($this->GetBuffer("DecryptedCache"), true) ?: $this->_decryptVault();
        if ($cache === false || !isset($cache[$ident])) return "";
        return is_array($cache[$ident]) ? json_encode($cache[$ident]) : (string)$cache[$ident];
    }

    public function GetKeys(): string {
        $cache = json_decode($this->GetBuffer("DecryptedCache"), true) ?: $this->_decryptVault();
        return ($cache === false) ? json_encode([]) : json_encode(array_keys($cache));
    }

    public function SyncSlaves(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode !== 1) return;

        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        $payload = json_encode(['auth' => $this->ReadPropertyString("AuthToken"), 'key' => $this->_readKey(), 'vault' => $this->GetValue("Vault")]);

        foreach ($slaves as $slave) {
            if (empty($slave['Url'])) continue;
            $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-type: application/json\r\n", 'content' => $payload, 'timeout' => 5], 'ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]]);
            @file_get_contents($slave['Url'], false, $ctx);
        }
    }

    protected function ProcessHookData(): void {
        if ($this->ReadPropertyInteger("OperationMode") !== 0) { header("HTTP/1.1 403 Forbidden"); return; }
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header("HTTP/1.1 405 Method Not Allowed"); return; }
        $data = json_decode(file_get_contents("php://input"), true);
        if (($data['auth'] ?? '') !== $this->ReadPropertyString("AuthToken")) { header("HTTP/1.1 403 Forbidden"); return; }
        if (isset($data['key'])) $this->_writeKey($data['key']);
        if (isset($data['vault'])) { $this->SetValue("Vault", $data['vault']); $this->SetBuffer("DecryptedCache", ""); }
        echo "OK";
    }

    private function _getFullPath(): string {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        return ($folder === "") ? "" : rtrim($folder, '/\\') . DIRECTORY_SEPARATOR . self::KEY_FILENAME;
    }

    private function _encryptAndSave(array $dataArray): bool {
        $keyHex = $this->_readKey();
        if (!$keyHex) return false;
        $iv = random_bytes(12); $tag = "";
        $cipherText = openssl_encrypt(json_encode($dataArray), "aes-128-gcm", hex2bin($keyHex), 0, $iv, $tag);
        if ($cipherText === false) return false;
        $this->SetValue("Vault", json_encode(['cipher' => "aes-128-gcm", 'iv' => bin2hex($iv), 'tag' => bin2hex($tag), 'data' => $cipherText]));
        return true;
    }

    private function _decryptVault() {
        $vaultJson = $this->GetValue("Vault");
        if (!$vaultJson || $vaultJson === "Encrypted Vault") return false;
        $meta = json_decode($vaultJson, true); $keyHex = $this->_readKey();
        if (!$keyHex || !$meta || !isset($meta['data'])) return false;
        $decrypted = openssl_decrypt($meta['data'], "aes-128-gcm", hex2bin($keyHex), 0, hex2bin($meta['iv']), hex2bin($meta['tag']));
        return ($decrypted === false) ? false : json_decode($decrypted, true);
    }

    private function _loadOrGenerateKey() {
        $path = $this->_getFullPath();
        if ($path === "") return false;
        if (file_exists($path)) return trim(file_get_contents($path));
        if ($this->ReadPropertyInteger("OperationMode") > 0) {
            $newKey = bin2hex(random_bytes(16));
            if (@file_put_contents($path, $newKey) !== false) return $newKey;
        }
        return false;
    }

    private function _readKey() { return $this->_loadOrGenerateKey(); }

    private function _writeKey(string $hexKey): void {
        $path = $this->_getFullPath();
        if ($path !== "") @file_put_contents($path, $hexKey);
    }
}
?>