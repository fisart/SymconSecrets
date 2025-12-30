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
        // This variable is hidden from the user tree
        $this->RegisterVariableString("Vault", "Encrypted Vault");
    }

    /**
     * DYNAMIC FORM GENERATION
     * 
     * This is called by IP-Symcon BEFORE the settings window opens.
     * It modifies the static form.json to hide irrelevant fields based on 
     * the system role and the current unlock state.
     */
    public function GetConfigurationForm(): string {
        // 1. Load the static JSON template from the local directory
        $formPath = __DIR__ . "/form.json";
        if (!file_exists($formPath)) {
            return json_encode(['elements' => [['type' => 'Label', 'caption' => 'Critical Error: form.json not found!']]]);
        }
        
        $formText = file_get_contents($formPath);
        $json = json_decode($formText, true);

        // Check if JSON is valid
        if ($json === null) {
            return json_encode(['elements' => [['type' => 'Label', 'caption' => 'Critical Error: form.json is invalid!']]]);
        }
        
        // 2. Read current settings and RAM state
        $mode = $this->ReadPropertyInteger("OperationMode");
        $isUnlocked = ($this->GetBuffer("IsUnlocked") === "true"); 

        // Identify the roles
        $isSlave      = ($mode === 0);
        $isMaster     = ($mode === 1);
        $isStandalone = ($mode === 2);
        
        // Logic for complex visibility
        $isEditorRole = ($isMaster || $isStandalone);
        $isSyncRole   = ($isMaster || $isSlave);

        // 3. Process Main Elements (Hide/Show fields)
        if (isset($json['elements'])) {
            foreach ($json['elements'] as &$element) {
                $name = $element['name'] ?? '';

                // --- SLAVE SPECIFIC UI LOGIC ---
                if ($name === 'HookInfo') {
                    $element['caption'] = "WebHook URL: /hook/secrets_" . $this->InstanceID;
                    $element['visible'] = $isSlave; 
                }
                
                if ($name === 'LabelHookAuth') {
                    $element['visible'] = $isSlave;
                }
                
                if ($name === 'HookUser') {
                    $element['visible'] = $isSlave;
                }
                
                if ($name === 'HookPass') {
                    $element['visible'] = $isSlave;
                }

                // --- MASTER SPECIFIC UI LOGIC ---
                if ($name === 'SlaveURLs') {
                    $element['visible'] = $isMaster;
                }
                
                if ($name === 'LabelSeparator') {
                    $element['visible'] = $isMaster;
                }
                
                if ($name === 'LabelMasterHead') {
                    $element['visible'] = $isMaster;
                }

                if ($name === 'BtnGenToken') {
                    $element['visible'] = $isMaster;
                }

                // --- SHARED SYNC LOGIC (Master & Slave) ---
                if ($name === 'AuthToken') {
                    $element['visible'] = $isSyncRole;
                }
                
                if ($name === 'BtnShowToken') {
                    $element['visible'] = $isSyncRole;
                }

                // --- EDITOR WORKFLOW VISIBILITY ---
                // Here we explicitly set every element to keep the code structure verbose
                if ($name === 'BtnDiagnose') {
                    $element['visible'] = $isUnlocked;
                }
                
                if ($name === 'LabelSecurityWarning') {
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
                    if ($isUnlocked) {
                        $path = json_decode($this->GetBuffer("CurrentPath"), true) ?: [];
                        $element['visible'] = (count($path) > 0);
                    } else {
                        $element['visible'] = false;
                    }
                }
                
                if ($name === 'EditorList') {
                    $element['visible'] = $isUnlocked;
                    if ($isUnlocked) {
                        $element['values'] = $this->PrepareListValues();
                    }
                }
                
                if ($name === 'PanelAddEntry') {
                    $element['visible'] = $isUnlocked;
                }
                
                if ($name === 'BtnEncrypt') {
                    $element['visible'] = $isUnlocked;
                }
                
                if ($name === 'BtnClear') {
                    $element['visible'] = $isUnlocked;
                }

                // The Unlock / Load button
                if ($name === 'BtnLoad') {
                    $element['visible'] = ($isEditorRole && !$isUnlocked);
                }
            }
        }

        // 4. Process Actions (Bottom Bar Buttons)
        if (isset($json['actions'])) {
            foreach ($json['actions'] as &$action) {
                if (($action['name'] ?? '') === 'BtnSync') {
                    $action['visible'] = $isMaster; 
                }
            }
        }

        return json_encode($json);
    }

    /**
     * ApplyChanges is called when the user clicks 'Apply' in the configuration.
     */
    public function ApplyChanges(): void {
        // Never delete this line!
        parent::ApplyChanges();
        
        // Hide Vault variable from object tree for security
        $vaultID = @$this->GetIDForIdent("Vault");
        if ($vaultID) {
            IPS_SetHidden($vaultID, true);
        }

        // Register WebHook for Slaves (Receiver mode)
        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode === 0) {
            @$this->RegisterHook("secrets_" . $this->InstanceID);
        }

        // Clear RAM Buffer on config change to force refresh
        $this->SetBuffer("DecryptedCache", ""); 

        // Validate the directory path entered by the user
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $errorMessage = "";
        
        if ($folder === "") {
            // Instance is inactive if no path is provided
            $this->SetStatus(104); 
        } elseif (!is_dir($folder)) {
            // Path must be a valid directory
            $errorMessage = "Directory does not exist: " . $folder;
            $this->SetStatus(202); 
        } elseif ($mode !== 0 && !is_writable($folder)) {
            // Master and Standalone need write permissions for the key file
            $errorMessage = "Directory is not writable: " . $folder;
            $this->SetStatus(202);
        } else {
            // Everything is fine
            $this->SetStatus(102); 
        }

        // Update the form UI with potential error messages
        $this->UpdateFormLayout($errorMessage);
    }

    /**
     * Public wrapper for UI updates.
     */
    public function UpdateUI(): void {
        $this->UpdateFormLayout("");
    }

    /**
     * Helper to update the error labels and status indicators in the form.
     */
    private function UpdateFormLayout(string $errorMessage): void {
        if ($errorMessage !== "") {
            $this->UpdateFormField("HeaderError", "visible", true);
            $this->UpdateFormField("HeaderError", "caption", "!!! CONFIGURATION ERROR: " . $errorMessage . " !!!");
            $this->UpdateFormField("StatusLabel", "caption", "Status: Error");
        } else {
            $this->UpdateFormField("HeaderError", "visible", false);
            $this->UpdateFormField("StatusLabel", "caption", "Instance OK (Idle)");
        }
    }

    /**
     * Synchronisiert den aktuellen Snapshot der UI-Liste in den RAM-Buffer.
     * Diese Funktion ist der "Übersetzer" zwischen der Web-Ansicht und dem PHP-Speicher.
     */
    private function SyncListToBuffer($listData): void {
        // Falls keine Daten vorhanden sind, abbrechen
        if (!$listData) return;

        // RAM-Buffer laden
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        
        // Referenz auf die aktuelle Ebene (Ordner) holen
        $temp = &$this->getCurrentLevelReference($fullData);
        
        // Wir iterieren über das IPSList-Objekt aus der UI
        foreach ($listData as $row) {
            // Wir wandeln die Zeile sicherheitshalber in ein PHP-Array um
            $rowData = (array)$row;
            $key = $rowData['Key'] ?? '';

            if ($key !== '' && isset($temp[$key])) {
                // Falls es ein Secret ist (kein Ordner), synchronisieren wir die 5 Felder
                if (isset($rowData['Type']) && $rowData['Type'] === 'Secret') {
                    
                    // Sicherstellen, dass das Ziel im RAM-Buffer ein Array ist
                    if (!is_array($temp[$key])) {
                        $temp[$key] = ['PW' => (string)$temp[$key]];
                    }

                    // Werte aus der UI-Zeile in den RAM-Buffer schreiben
                    $temp[$key]['User']     = $rowData['User']     ?? '';
                    $temp[$key]['PW']       = $rowData['PW']       ?? '';
                    $temp[$key]['URL']      = $rowData['URL']      ?? '';
                    $temp[$key]['Location'] = $rowData['Location'] ?? '';
                    $temp[$key]['IP']       = $rowData['IP']       ?? '';
                }
            }
        }

        // Den aktualisierten Baum zurück in den RAM-Buffer schreiben
        $this->SetBuffer("DecryptedCache", json_encode($fullData));
    }

    // =========================================================================
    // CONFIGURATION ACTIONS (Called by UI Buttons)
    // =========================================================================

    /**
     * Verifies if the directory is accessible and if the master.key exists.
     */
    public function CheckDirectory(): void {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $mode = $this->ReadPropertyInteger("OperationMode");

        if ($folder === "") {
            echo "Warning: No directory path has been entered yet.";
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

        $filePath = $this->_getFullPath();
        $exists = file_exists($filePath);
        
        echo "✅ SUCCESS!\n\nDirectory: $folder\nKey File: " . ($exists ? "Found and ready." : "Will be created on first encryption.");
    }

    /**
     * Generates a 256-bit random hex token for Master-Slave sync.
     */
    public function GenerateToken(): void {
        $token = bin2hex(random_bytes(32));
        $this->UpdateFormField("AuthToken", "value", $token);
        echo "A new random token has been generated and inserted.";
    }

    /**
     * Displays the current sync token in a popup.
     */
    public function ShowToken(): void {
        $token = $this->ReadPropertyString("AuthToken");
        if ($token === "") {
            echo "No synchronization token has been set yet.";
        } else {
            echo "YOUR CURRENT SYNC TOKEN:\n\n" . $token . "\n\n(Select and copy this for your Slave systems)";
        }
    }

    /**
     * Simple test function to verify module connectivity.
     */
    public function Test(): void {
        echo "MODUL-CHECK: Die Verbindung zum SecretsManager ist erfolgreich!";
    }

    // =========================================================================
    // EDITOR ACTIONS (Load / Save / Wipe / Navigate)
    // =========================================================================

    /**
     * Decrypts the vault and initializes the editor view.
     */
    public function LoadVault(): void {
        // 1. Decrypt existing data
        $cache = $this->_decryptVault();
        
        if ($cache === false) {
            $vaultValue = $this->GetValue("Vault");
            if ($vaultValue === "" || $vaultValue === "Encrypted Vault") {
                // Initialize empty vault
                $cache = [];
            } else {
                echo "❌ Error: Could not decrypt vault. Please check your master.key file.";
                return;
            }
        }

        // 2. Store in RAM buffers
        $this->SetBuffer("DecryptedCache", json_encode($cache));
        $this->SetBuffer("CurrentPath", json_encode([]));
        
        // 3. Mark as unlocked
        $this->SetBuffer("IsUnlocked", "true");
        
        // 4. Trigger UI refresh
        $this->ReloadForm();
    }

    /**
     * Clears all decrypted data from RAM and hides the editor.
     */
    public function ClearVault(): void {
        // Clear buffers
        $this->SetBuffer("DecryptedCache", "");
        $this->SetBuffer("CurrentPath", "");
        
        // Reset state
        $this->SetBuffer("IsUnlocked", "false");
        
        // Final UI refresh
        $this->ReloadForm();
    }

    /**
     * Navigates into a sub-folder.
     */
    public function HandleListAction(int $index): void {
        // No need to sync here, already synced via onChange
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        $temp = &$this->getCurrentLevelReference($fullData);
        $keys = array_keys($temp);

        if (isset($keys[$index])) {
            $chosenKey = $keys[$index];
            if (is_array($temp[$chosenKey])) {
                $path = json_decode($this->GetBuffer("CurrentPath"), true) ?: [];
                $path[] = $chosenKey;
                $this->SetBuffer("CurrentPath", json_encode($path));
                $this->ReloadForm();
            }
        }
    }

    /**
     * Navigates one level back up.
     */
    public function NavigateUp(): void {
        // No need to sync here, already synced via onChange
        $path = json_decode($this->GetBuffer("CurrentPath"), true) ?: [];
        if (count($path) > 0) {
            array_pop($path);
            $this->SetBuffer("CurrentPath", json_encode($path));
            $this->ReloadForm();
        }
    }

    /**
     * Updates a specific field of an entry at the current level.
     */
/**
     * Updates a specific field of an entry at the current level.
     * Includes extensive debug logging to verify the data flow and sorting.
     */
    public function UpdateValue(int $index, string $Field, string $Value): void {
        // DIAGNOSE 1: Was kommt von der UI an?
        $this->LogMessage("DEBUG 1: UI sendet - Index: $index, Feld: $Field, Wert: $Value", KL_MESSAGE);

        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        
        // Den Pfad für das Log lesbar machen
        $path = $this->GetBuffer("CurrentPath");
        $this->LogMessage("DEBUG 2: Aktueller Pfad im RAM: " . ($path ?: "Root"), KL_MESSAGE);

        // Referenz auf die aktuelle Ebene holen
        $temp = &$this->getCurrentLevelReference($fullData);
        
        // DIAGNOSE 3: Reihenfolge vor der Sortierung
        $keysBefore = array_keys($temp);
        $this->LogMessage("DEBUG 3: Keys im RAM (vor Sortierung): " . implode(", ", $keysBefore), KL_MESSAGE);

        // Alphabetisch sortieren, damit der Index zur UI passt
        ksort($temp); 
        $keys = array_keys($temp);

        // DIAGNOSE 4: Zuordnung prüfen
        if (isset($keys[$index])) {
            $keyName = $keys[$index];
            $this->LogMessage("DEBUG 4: Index $index wird in PHP dem Key '$keyName' zugeordnet.", KL_MESSAGE);
            
            // DIAGNOSE 5: Struktur-Check
            $isAlreadyArray = is_array($temp[$keyName]);
            $this->LogMessage("DEBUG 5: Ist Eintrag '$keyName' bereits ein Array? " . ($isAlreadyArray ? "JA" : "NEIN (Konvertierung nötig)"), KL_MESSAGE);

            // Sicherstellen, dass es ein Array für die neuen Spalten ist
            if (!$isAlreadyArray) {
                $oldValue = (string)$temp[$keyName];
                $temp[$keyName] = [
                    'PW'       => $oldValue, 
                    'User'     => '', 
                    'URL'      => '', 
                    'Location' => '', 
                    'IP'       => ''
                ];
                $this->LogMessage("DEBUG: Konvertierung abgeschlossen. Alter Wert '$oldValue' wurde in Feld 'PW' verschoben.", KL_MESSAGE);
            }
            
            // Den Wert setzen
            $oldFieldValue = $temp[$keyName][$Field] ?? 'LEER';
            $temp[$keyName][$Field] = $Value;
            
            $this->LogMessage("DEBUG 6: Wert-Änderung in '$keyName': Feld '$Field' von '$oldFieldValue' auf '$Value'", KL_MESSAGE);
            
            // Zurück in den RAM-Buffer schreiben
            $this->SetBuffer("DecryptedCache", json_encode($fullData));

            // DIAGNOSE 7: Kontroll-Check des resultierenden Datensatzes
            $this->LogMessage("DEBUG 7: Datensatz '$keyName' im RAM nun: " . json_encode($temp[$keyName]), KL_MESSAGE);

        } else {
            // FEHLER-DIAGNOSE
            $this->LogMessage("DEBUG ERROR: Index $index existiert nicht! Vorhandene Indizes: 0 bis " . (count($keys)-1), KL_ERROR);
        }
    }
    /**
     * Adds a new folder or a new secret to the current path.
     */
    public function AddEntry(string $NewKeyName, string $NewKeyType, $EditorList): void {
        $this->SyncListToBuffer($EditorList); // Snapshot verarbeiten
        
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
    public function EncryptAndSave($EditorList): void {
        $this->SyncListToBuffer($EditorList); // Snapshot verarbeiten
        
        if ($this->ReadPropertyInteger("OperationMode") === 0) return;
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];

        if ($this->_encryptAndSave($fullData)) {
            $this->ClearVault();
            echo "✅ SUCCESS: Vault encrypted and saved.";
            if ($this->ReadPropertyInteger("OperationMode") === 1) $this->SyncSlaves();
        }
    }


    // =========================================================================
    // PRIVATE HELPERS FOR DATA PREPARATION
    // =========================================================================

    /**
     * Prepares the data list for the UI EditorList element.
     */

    /**
     * Takes the current state of the EditorList from the UI and synchronizes 
     * it into the unencrypted RAM buffer (DecryptedCache).
     */
    private function SyncListToBuffer(array $listData): void {
        // 1. Get the full tree from the RAM buffer
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        
        // 2. Get a reference to the current level we are looking at
        $temp = &$this->getCurrentLevelReference($fullData);
        
        // 3. Iterate through the rows sent by the UI
        foreach ($listData as $row) {
            $key = $row['Key'] ?? '';
            if ($key === '') continue;

            // Only update if the entry exists in our buffer
            if (isset($temp[$key])) {
                // If it's not an array yet (old format), convert it
                if (!is_array($temp[$key])) {
                    $temp[$key] = [
                        'User'     => '',
                        'PW'       => (string)$temp[$key],
                        'URL'      => '',
                        'Location' => '',
                        'IP'       => ''
                    ];
                }

                // Sync the 5 data fields from the UI row to the buffer
                // Folders are skipped here because they don't have these fields
                if ($row['Type'] === 'Secret') {
                    $temp[$key]['User']     = $row['User']     ?? '';
                    $temp[$key]['PW']       = $row['PW']       ?? '';
                    $temp[$key]['URL']      = $row['URL']      ?? '';
                    $temp[$key]['Location'] = $row['Location'] ?? '';
                    $temp[$key]['IP']       = $row['IP']       ?? '';
                }
            }
        }

        // 4. Write the updated full tree back into the RAM buffer
        $this->SetBuffer("DecryptedCache", json_encode($fullData));
    }
    private function PrepareListValues(): array {
        $fullData = json_decode($this->GetBuffer("DecryptedCache"), true) ?: [];
        $temp = $this->getCurrentLevelReference($fullData);
        
        $values = [];
        if (is_array($temp)) {
            // ZWINGEND: Identische Sortierung wie in der UI
            ksort($temp); 

            foreach ($temp as $key => $val) {
                $isObj = is_array($val);
                
                // Ordner-Erkennung: Enthält der Eintrag selbst wieder Arrays?
                $isFolder = false;
                if ($isObj) {
                    foreach ($val as $subVal) {
                        if (is_array($subVal)) {
                            $isFolder = true;
                            break;
                        }
                    }
                    // Falls es die bekannten Secret-Keys hat, ist es kein Ordner
                    if (isset($val['PW']) || isset($val['User'])) {
                        $isFolder = false;
                    }
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

    /**
     * Walks through the multi-dimensional array using references.
     */
    private function &getCurrentLevelReference(&$fullData) {
        $pathString = $this->GetBuffer("CurrentPath");
        $path = json_decode($pathString, true) ?: [];
        
        $level = &$fullData;
        foreach ($path as $step) {
            if (isset($level[$step]) && is_array($level[$step])) {
                $level = &$level[$step];
            }
        }
        return $level;
    }

    // =========================================================================
    // PUBLIC API (For external PHP scripts)
    // =========================================================================

    /**
     * Returns a secret by its identifier.
     */
    public function GetSecret(string $ident): string {
        $decrypted = $this->GetBuffer("DecryptedCache");
        $cache = ($decrypted !== "") ? json_decode($decrypted, true) : $this->_decryptVault();
        
        if ($cache === false) {
            return "";
        }

        // Simple lookup (recursive search would be needed for deep folders)
        if (isset($cache[$ident])) {
            $val = $cache[$ident];
            return (is_array($val) || is_object($val)) ? (json_encode($val) ?: "") : (string)$val;
        }

        return "";
    }

    /**
     * Returns all identifiers in the root level.
     */
    public function GetKeys(): string {
        $decrypted = $this->GetBuffer("DecryptedCache");
        $cache = ($decrypted !== "") ? json_decode($decrypted, true) : $this->_decryptVault();
        
        if ($cache === false) {
            return json_encode([]);
        }

        return json_encode(array_keys($cache));
    }

    // =========================================================================
    // SYNCHRONIZATION (Master -> Slave)
    // =========================================================================

    /**
     * Pushes the vault to all configured slaves.
     */
    public function SyncSlaves(): void {
        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode !== 1) {
            return;
        }

        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        if (!is_array($slaves) || count($slaves) === 0) {
            return;
        }

        $keyHex = $this->_readKey();
        $vault = $this->GetValue("Vault");
        $token = $this->ReadPropertyString("AuthToken");

        $payload = json_encode([
            'auth' => $token,
            'key'  => $keyHex,
            'vault'=> $vault
        ]);

        foreach ($slaves as $slave) {
            if (empty($slave['Url'])) {
                continue;
            }

            $headers = "Content-type: application/json\r\n";
            if (!empty($slave['User'])) {
                $headers .= "Authorization: Basic " . base64_encode($slave['User'] . ":" . $slave['Pass']) . "\r\n";
            }

            $ctx = stream_context_create([
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
            ]);

            $res = @file_get_contents($slave['Url'], false, $ctx);
            
            if ($res !== false) {
                $this->LogMessage("Sync performed for: " . $slave['Url'], KL_MESSAGE);
            }
        }
    }

    /**
     * Processes incoming data via the WebHook.
     */
    protected function ProcessHookData(): void {
        if ($this->ReadPropertyInteger("OperationMode") !== 0) {
            header("HTTP/1.1 403 Forbidden");
            return;
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header("HTTP/1.1 405 Method Not Allowed");
            return;
        }

        // Auth Check
        $hookUser = $this->ReadPropertyString("HookUser");
        if ($hookUser !== "" && (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER'] !== $hookUser)) {
            header('WWW-Authenticate: Basic realm="SecretsManager"');
            header('HTTP/1.0 401 Unauthorized');
            return;
        }

        $input = file_get_contents("php://input");
        $data = json_decode($input, true);

        if (($data['auth'] ?? '') !== $this->ReadPropertyString("AuthToken")) {
            header("HTTP/1.1 403 Forbidden");
            return;
        }

        // Save data
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
    // INTERNAL CRYPTO HELPERS (Explicit Functions)
    // =========================================================================

    /**
     * Builds the full path to the master.key file.
     */
    private function _getFullPath(): string {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if ($folder === "") {
            return "";
        }
        return rtrim($folder, '/\\') . DIRECTORY_SEPARATOR . self::KEY_FILENAME;
    }

    /**
     * Encrypts an array and stores the resulting JSON metadata in the Vault variable.
     */
    private function _encryptAndSave(array $dataArray): bool {
        $keyHex = $this->_readKey();
        if (!$keyHex) {
            return false;
        }

        $newKeyBin = hex2bin($keyHex);
        $plainText = json_encode($dataArray);
        
        $cipher = "aes-128-gcm";
        $iv = random_bytes(openssl_cipher_iv_length($cipher));
        $tag = ""; 
        
        $cipherText = openssl_encrypt($plainText, $cipher, $newKeyBin, 0, $iv, $tag);

        if ($cipherText === false) {
            return false;
        }

        $vaultMeta = [
            'cipher' => $cipher,
            'iv'     => bin2hex($iv),
            'tag'    => bin2hex($tag),
            'data'   => $cipherText
        ];

        $this->SetValue("Vault", json_encode($vaultMeta));
        
        return true;
    }

    /**
     * Decrypts the Vault variable back into a PHP array.
     */
    private function _decryptVault() {
        $vaultJson = $this->GetValue("Vault");
        if (!$vaultJson || $vaultJson === "Encrypted Vault") {
            return false;
        }

        $meta = json_decode($vaultJson, true);
        $keyHex = $this->_readKey();
        
        if (!$keyHex || !$meta || !isset($meta['data'])) {
            return false;
        }

        $decrypted = openssl_decrypt(
            $meta['data'], 
            $meta['cipher'] ?? "aes-128-gcm", 
            hex2bin($keyHex), 
            0, 
            hex2bin($meta['iv']), 
            hex2bin($meta['tag'])
        );

        if ($decrypted === false) {
            return false;
        }

        return json_decode($decrypted, true);
    }

    /**
     * Loads the key or generates a new one if Master/Standalone.
     */
    private function _loadOrGenerateKey() {
        $path = $this->_getFullPath();
        if ($path === "") {
            return false;
        }

        if (file_exists($path)) {
            return trim(file_get_contents($path));
        }

        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode === 1 || $mode === 2) {
            $newKey = bin2hex(random_bytes(16)); 
            if (@file_put_contents($path, $newKey) !== false) {
                return $newKey;
            }
        }
        
        return false;
    }

    /**
     * Reads the master key.
     */
    private function _readKey() {
        return $this->_loadOrGenerateKey();
    }

    /**
     * Writes a key to the file system.
     */
    private function _writeKey(string $hexKey): void {
        $path = $this->_getFullPath();
        if ($path !== "") {
            @file_put_contents($path, $hexKey);
        }
    }

    /**
     * Internal cache getter.
     */
    private function _getCache() {
        $data = $this->GetBuffer("DecryptedCache");
        if ($data === "") {
            return null;
        }
        return json_decode($data, true);
    }

    /**
     * Internal cache setter.
     */
    private function _setCache(array $array): void {
        $this->SetBuffer("DecryptedCache", json_encode($array));
    }
}