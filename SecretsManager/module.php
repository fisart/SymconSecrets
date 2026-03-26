<?php

declare(strict_types=1);
// Version 5.2.2  
class SecretsManager extends IPSModuleStrict
{

    // The name of the key file stored on the OS
    private const KEY_FILENAME = 'master.key';
    private const SYSTEM_FILENAME = 'system.vault';

    public function Create(): void
    {
        parent::Create();

        $this->RegisterPropertyInteger("OperationMode", 0);

        // Key Storage
        $this->RegisterPropertyString("KeyFolderPath", "");

        // IMPORTANT: AuthToken / HookPass werden NICHT mehr als Property gespeichert
        // $this->RegisterPropertyString("AuthToken", "");   // REMOVE
        // $this->RegisterPropertyString("HookPass", "");    // REMOVE

        // Hook user bleibt (nicht geheim)
        $this->RegisterPropertyString("HookUser", "");

        // Slave-side permission to accept a key via sync payload
        $this->RegisterPropertyBoolean("AllowKeyTransport", false);

        // Slave list bleibt, aber OHNE Pass-Spalte
        $this->RegisterPropertyString("SlaveURLs", "[]");

        $this->RegisterVariableString("Vault", "Encrypted Vault");
    }



    /**
     * DYNAMIC FORM GENERATION
     * This is called by IP-Symcon BEFORE the settings window opens.
     * It modifies the static form.json to hide irrelevant fields based on Master/Slave role.
     */


    public function GetConfigurationForm(): string
    {
        $json = json_decode(file_get_contents(__DIR__ . "/form.json"), true);

        $mode = $this->ReadPropertyInteger("OperationMode");

        $isSlave      = ($mode === 0);
        $isMaster     = ($mode === 1);
        $isStandalone = ($mode === 2);

        $isEditorRole = ($isMaster || $isStandalone);
        $isSyncRole   = ($isMaster || $isSlave);

        // Build slave URL options with label (Server — URL)
        $slaveOptions = [];
        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        if (is_array($slaves)) {
            foreach ($slaves as $s) {
                $u = trim((string)($s['Url'] ?? ''));
                if ($u === '') continue;

                $label = trim((string)($s['Server'] ?? ''));
                $cap = ($label !== '') ? ($label . " — " . $u) : $u;

                $slaveOptions[] = ['caption' => $cap, 'value' => $u];
            }
        }
        if (count($slaveOptions) === 0) {
            $slaveOptions[] = ['caption' => '(no slaves configured)', 'value' => ''];
        }

        // Helper to apply options inside nested "items"
        $applySlaveOptions = function (&$node) use (&$applySlaveOptions, $slaveOptions) {
            if (!is_array($node)) return;
            if (($node['name'] ?? '') === 'SlaveCredUrl') {
                $node['options'] = $slaveOptions;
            }
            if (isset($node['items']) && is_array($node['items'])) {
                foreach ($node['items'] as &$child) {
                    $applySlaveOptions($child);
                }
            }
            if (isset($node['elements']) && is_array($node['elements'])) {
                foreach ($node['elements'] as &$child) {
                    $applySlaveOptions($child);
                }
            }
        };

        if (isset($json['elements']) && is_array($json['elements'])) {
            foreach ($json['elements'] as &$element) {
                $applySlaveOptions($element);
                $name = $element['name'] ?? '';

                if ($name === 'HookInfo') {
                    $element['caption'] = "Portal/Sync WebHook URL: /hook/secrets_" . $this->InstanceID;
                    $element['visible'] = true;
                }

                if (in_array($name, ['LabelHookAuth', 'HookUser'], true)) {
                    $element['visible'] = $isSlave;
                }

                if (in_array($name, ['HookPassInput', 'BtnSaveHookPass'], true)) {
                    $element['visible'] = $isSlave;
                }

                // --- ANPASSUNG: Sync Token Sektion (Granular für Master/Slave/Standalone) ---
                if (in_array($name, ['LabelSyncToken', 'AuthTokenInput', 'BtnGenToken', 'BtnShowToken', 'BtnSaveAuthToken'], true)) {
                    if (in_array($name, ['BtnGenToken', 'BtnShowToken'], true)) {
                        $element['visible'] = $isMaster; // Nur Master sieht Generieren/Anzeigen
                    } else {
                        $element['visible'] = $isSyncRole; // Master und Slave sehen Label, Input und Save
                    }
                }

                if (in_array($name, ['SlaveURLs', 'PanelSlaveCreds'], true)) {
                    $element['visible'] = $isMaster;
                }

                // --- ANPASSUNG: Alten Editor komplett verstecken ---
                if (in_array($name, ['BtnLoad', 'InputJson', 'BtnEncrypt', 'BtnClear', 'LabelSecurityWarning', 'LabelSeparator', 'LabelMasterHead'], true)) {
                    $element['visible'] = false;
                }

                if ($name === 'AllowKeyTransport') {
                    $element['visible'] = $isSlave;
                }
            }
        }

        if (isset($json['actions']) && is_array($json['actions'])) {
            foreach ($json['actions'] as &$action) {
                $an = $action['name'] ?? '';
                if ($an === 'BtnSync') {
                    $action['visible'] = $isMaster;
                }
                if ($an === 'BtnRotateKey') {
                    $action['visible'] = ($isMaster || $isStandalone);
                }
            }
        }

        // --- START GRAFISCHER EXPLORER INTEGRATION ---
        if ($isEditorRole) {
            $vaultData = $this->_decryptVault() ?: [];
            $currentPath = (string)$this->GetBuffer("CurrentPath");
            $selectedRecord = (string)$this->GetBuffer("SelectedRecord");

            // Navigation zum aktuellen Zweig im Array
            $displayData = $vaultData;
            if ($currentPath !== "") {
                foreach (explode('/', $currentPath) as $part) {
                    if ($part !== "" && isset($displayData[$part]) && is_array($displayData[$part])) {
                        $displayData = $displayData[$part];
                    }
                }
            }

            // Master-Liste für aktuelle Ebene aufbereiten
            $masterList = [];
            $folderProperties = [];
            if (is_array($displayData)) {
                ksort($displayData);
                foreach ($displayData as $key => $value) {
                    if ($key === "__folder") continue;

                    if (!is_array($value)) {
                        // Hybrid Logic: Extract flat fields
                        $folderProperties[] = ["Key" => (string)$key, "Value" => (string)$value];
                    } else {
                        $isFolder = $this->CheckIfFolder($value);
                        $masterList[] = [
                            "Icon"  => $isFolder ? "📁" : "🔑",
                            "Ident" => (string)$key,
                            "Type"  => $isFolder ? "Folder" : "Record"
                        ];
                    }
                }
            }

            // UI Elemente anhängen
            $json['actions'][] = ["type" => "Label", "caption" => "________________________________________________________________________________________________"];
            $json['actions'][] = ["type" => "Label", "caption" => "📂 TRESOR-EXPLORER", "bold" => true];
            $json['actions'][] = ["type" => "Label", "caption" => "📍 Position: root" . ($currentPath !== "" ? " / " . str_replace("/", " / ", $currentPath) : "")];

            // --- HYBRID SECTION: Folder Properties ---
            if (count($folderProperties) > 0 || $currentPath !== "") {
                $json['actions'][] = ["type" => "Label", "caption" => "🔑 FELDER DIESES ORDNER:", "italic" => true];
                $json['actions'][] = [
                    "type" => "List",
                    "name" => "FolderPropsUI",
                    "rowCount" => 4,
                    "add" => true,
                    "delete" => true,
                    "columns" => [
                        ["caption" => "Feld", "name" => "Key", "width" => "150px", "add" => "", "edit" => ["type" => "ValidationTextBox"]],
                        ["caption" => "Wert", "name" => "Value", "width" => "auto", "add" => "", "edit" => ["type" => "ValidationTextBox"]]
                    ],
                    "values" => $folderProperties
                ];
                $json['actions'][] = ["type" => "Button", "caption" => "💾 Ordner-Felder speichern", "onClick" => '$D=[]; foreach($FolderPropsUI as $r){ $D[]=$r; } $Payload = ["Ident" => "", "Data" => $D]; IPS_RequestAction($id, "EXPL_SaveRecord", json_encode($Payload));'];
            }

            if ($currentPath !== "") {
                $json['actions'][] = ["type" => "Button", "caption" => "⬅️ ZURÜCK / ORDNER SCHLIESSEN", "onClick" => "IPS_RequestAction(\$id, 'EXPL_NavUp', '');"];
            }

            $json['actions'][] = [
                "type" => "List",
                "name" => "MasterListUI",
                "rowCount" => 6,
                "columns" => [
                    ["caption" => " ", "name" => "Icon", "width" => "35px"],
                    ["caption" => "Name", "name" => "Ident", "width" => "auto"],
                    ["caption" => "Typ", "name" => "Type", "width" => "100px"]
                ],
                "values" => $masterList,
                "form" => [
                    "\$item = isset(\$dynamicList) ? \$dynamicList : \$MasterListUI;",
                    "if (\$item['Type'] == 'Record') {",
                    "    return [",
                    "        ['type' => 'Label', 'caption' => 'Eintrag bearbeiten: ' . \$item['Ident']],",
                    "        ['type' => 'List', 'name' => 'RecordFields', 'rowCount' => 5, 'add' => true, 'delete' => true,",
                    "         'columns' => [",
                    "             ['caption' => 'Feld', 'name' => 'Key', 'width' => '150px', 'add' => '', 'edit' => ['type' => 'ValidationTextBox']],",
                    "             ['caption' => 'Wert', 'name' => 'Value', 'width' => 'auto', 'add' => '', 'edit' => ['type' => 'ValidationTextBox']]",
                    "         ],",
                    "         'values' => SEC_GetExplorerFields(\$id, \$item['Ident'])",
                    "        ],",
                    "        ['type' => 'Button', 'caption' => '💾 Speichern', 'onClick' => '\$D=[]; foreach(\$RecordFields as \$r){ \$D[]=\$r; } \$Payload = [\"Ident\" => \"' . \$item['Ident'] . '\", \"Data\" => \$D]; IPS_RequestAction(\$id, \"EXPL_SaveRecord\", json_encode(\$Payload));']",
                    "    ];",
                    "} else {",
                    "    return [",
                    "        ['type' => 'Label', 'caption' => 'Ordner umbenennen: ' . \$item['Ident']],",
                    "        ['type' => 'ValidationTextBox', 'name' => 'NewName', 'caption' => 'Neuer Name', 'value' => \$item['Ident'],'validate' => '^[^/]+$'],",
                    "        ['type' => 'Button', 'caption' => '💾 Umbenennen', 'onClick' => 'IPS_RequestAction(\$id, \"EXPL_RenameFolder\", json_encode([\"Old\" => \"' . \$item['Ident'] . '\", \"New\" => \$NewName]));']",
                    "    ];",
                    "}"
                ]
            ];

            $json['actions'][] = [
                "type" => "Button",
                "caption" => "➡️ ÖFFNEN / EDITIEREN",
                "onClick" => "if(isset(\$MasterListUI)) { IPS_RequestAction(\$id, 'EXPL_HandleClick', json_encode(\$MasterListUI)); } else { echo 'Bitte erst eine Zeile markieren!'; }"
            ];

            $json['actions'][] = [
                "type" => "Button",
                "caption" => "🗑️ MARKIERTE ZEILE LÖSCHEN",
                "onClick" => "if(isset(\$MasterListUI)) { IPS_RequestAction(\$id, 'EXPL_DeleteItem', \$MasterListUI['Ident']); } else { echo 'Bitte erst eine Zeile markieren!'; }"
            ];

            $json['actions'][] = ["type" => "Label", "caption" => "➕ NEU AN DIESER POSITION:"];
            $json['actions'][] = ["type" => "ValidationTextBox", "name" => "NewItemName", "caption" => "Name für Element", "validate" => "^[^/]+$"];
            $json['actions'][] = ["type" => "Button", "caption" => "📁 + Unterordner", "onClick" => "IPS_RequestAction(\$id, 'EXPL_CreateFolder', \$NewItemName);"];
            $json['actions'][] = ["type" => "Button", "caption" => "🔑 + Record", "onClick" => "IPS_RequestAction(\$id, 'EXPL_CreateRecord', \$NewItemName);"];

            $json['actions'][] = ["type" => "Label", "caption" => "________________________________________________________________________________________________"];
            $json['actions'][] = ["type" => "Label", "caption" => "📥 JSON IMPORT", "bold" => true];
            $json['actions'][] = ["type" => "ValidationTextBox", "name" => "ImportInput", "caption" => "JSON String"];
            $json['actions'][] = ["type" => "Button", "caption" => "Importieren", "onClick" => "IPS_RequestAction(\$id, 'EXPL_ImportJson', \$ImportInput);"];
        }

        return json_encode($json);
    }


    public function SaveAuthToken(string $token): void
    {
        $token = trim((string)$token);



        if ($token === "") {
            $this->LogMessage("AuthToken not saved: input is empty.", KL_ERROR);
            return;
        }

        $sys = $this->loadSystemSecrets();
        $sys['authToken'] = $token;

        if ($this->saveSystemSecrets($sys)) {
            $this->LogMessage("AuthToken saved to encrypted system file.", KL_MESSAGE);
        } else {
            $this->LogMessage("AuthToken save failed (system file).", KL_ERROR);
        }
    }


    public function ShowToken(): void
    {
        $token = $this->getAuthToken();
        if ($token === "") {
            $this->LogMessage("No AuthToken configured in system file.", KL_WARNING);
            echo "No token set."; // optional
            return;
        }
        echo "YOUR SYNC TOKEN:\n\n" . $token;
    }



    public function SaveHookPass(string $pass): void
    {
        $pass = (string)$pass;


        if ($pass === "") {
            $this->LogMessage("HookPass not saved: input is empty.", KL_ERROR);
            return;
        }

        $sys = $this->loadSystemSecrets();
        $sys['hookPass'] = $pass;

        if ($this->saveSystemSecrets($sys)) {
            $this->LogMessage("HookPass saved to encrypted system file.", KL_MESSAGE);
        } else {
            $this->LogMessage("HookPass save failed (system file).", KL_ERROR);
        }
    }


    public function SaveSlavePass(string $url, string $pass): void
    {
        $url  = trim((string)$url);
        $pass = (string)$pass;

        // DEBUG (TEMP)


        if ($url === "") {
            $this->LogMessage("Slave password not saved: no URL selected.", KL_ERROR);
            return;
        }
        if ($pass === "") {
            $this->LogMessage("Slave password not saved: empty password.", KL_ERROR);
            return;
        }

        $sys = $this->loadSystemSecrets();
        if (!isset($sys['slaves']) || !is_array($sys['slaves'])) {
            $sys['slaves'] = [];
        }
        $sys['slaves'][$url] = $pass;

        if ($this->saveSystemSecrets($sys)) {

            $this->LogMessage("Slave password saved for: " . $url, KL_MESSAGE);
        } else {
            $this->LogMessage("Slave password save failed for: " . $url, KL_ERROR);
        }
    }


    public function ApplyChanges(): void
    {
        parent::ApplyChanges();

        // 1. Variable im Baum verstecken
        $vaultID = @$this->GetIDForIdent("Vault");
        if ($vaultID) {
            IPS_SetHidden($vaultID, true);
        }

        // 2. Aktuelle Rolle prüfen
        $mode = $this->ReadPropertyInteger("OperationMode");

        // Register WebHook for all modes to support the Passkey Authentication Gate
        @$this->RegisterHook("secrets_" . $this->InstanceID);

        // (ENTFÄLLT) Disk-clean: kein DecryptedCache mehr
        // $this->SetBuffer("DecryptedCache", "");

        // 4. Validierung des Verzeichnisses
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $errorMessage = "";

        if ($folder === "") {
            $this->SetStatus(104); // IS_INACTIVE
        } elseif (!is_dir($folder)) {
            $errorMessage = "Directory does not exist: " . $folder;
            $this->SetStatus(202);
        } elseif ($mode !== 0 && !is_writable($folder)) {
            $errorMessage = "Directory is not writable: " . $folder;
            $this->SetStatus(202);
        } else {
            $this->SetStatus(102); // IS_ACTIVE
        }

        $this->UpdateFormLayout($errorMessage);
    }


    /**
     * Public wrapper for UI updates (called by form.json)
     */
    public function UpdateUI(): void
    {
        $this->UpdateFormLayout("");
    }

    /**
     * Internal helper to update static UI elements like Error Headers
     */
    private function UpdateFormLayout(string $errorMessage): void
    {
        if ($errorMessage !== "") {
            $this->UpdateFormField("HeaderError", "visible", true);
            $this->UpdateFormField("HeaderError", "caption", "!!! CONFIGURATION ERROR: " . $errorMessage . " !!!");
            $this->UpdateFormField("StatusLabel", "caption", "Error: " . $errorMessage);
        } else {
            $this->UpdateFormField("HeaderError", "visible", false);
            $this->UpdateFormField("StatusLabel", "caption", "Instance OK");
        }
    }

    private function ServePortalUI(): void
    {
        $sid = bin2hex(random_bytes(8));
        $challenge = random_bytes(32);

        // Eindeutigen Puffer für diese Session speichern
        $this->SetBuffer("PortalChallenge_" . $sid, json_encode([
            'challenge' => bin2hex($challenge),
            'expires'   => time() + 300
        ]));

        $challengeB64 = base64_encode($challenge);
        $returnUrl = $_GET['return'] ?? '';

        echo '<html><head><title>Vault Auth</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f4f7f6;}';
        echo '.box{background:#fff;padding:40px;border-radius:15px;box-shadow:0 10px 25px rgba(0,0,0,0.1);text-align:center;}';
        echo 'button{background:#4a90e2;color:white;border:none;padding:15px 30px;border-radius:8px;font-size:18px;cursor:pointer;transition:background 0.3s;}';
        echo 'button:hover{background:#357abd;}</style></head><body>';
        echo '<div class="box"><h2>🔐 Biometrischer Login</h2><p>Bitte Sensor berühren.</p>';
        echo '<button onclick="login()">Anmelden</button></div>';
        echo '<script>async function login(){';
        echo 'const challenge = Uint8Array.from(atob("' . $challengeB64 . '"), c => c.charCodeAt(0));';
        echo 'const options = { publicKey: { challenge, timeout: 60000, userVerification: "required" } };';
        echo 'try { const cred = await navigator.credentials.get(options);';
        echo 'const resp = { id: cred.id, rawId: btoa(String.fromCharCode(...new Uint8Array(cred.rawId))), response: { ';
        echo 'clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON))), ';
        echo 'authenticatorData: btoa(String.fromCharCode(...new Uint8Array(cred.response.authenticatorData))), ';
        echo 'signature: btoa(String.fromCharCode(...new Uint8Array(cred.response.signature))) }, ';
        echo 'type: cred.type, portal: 1, sid: "' . $sid . '", return: "' . addslashes($returnUrl) . '" };';
        echo 'const res = await fetch(window.location.href, { method: "POST", body: JSON.stringify(resp) });';
        echo 'const txt = await res.text(); if(txt === "OK") { window.location.href = decodeURIComponent("' . addslashes($returnUrl) . '") || "/"; } else { alert("Fehler: " + txt); }';
        echo '} catch(e) { alert("Authentifizierung fehlgeschlagen."); } }';
        echo '</script></body></html>';
    }

    // =========================================================================
    // CONFIGURATION ACTIONS (Called by Buttons)
    // =========================================================================

    public function CheckDirectory(): void
    {
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

    public function GenerateToken(): void
    {
        $token = bin2hex(random_bytes(32));
        $this->UpdateFormField("AuthTokenInput", "value", $token);
        $this->LogMessage("Sync token generated (not yet saved).", KL_MESSAGE);
    }




    // =========================================================================
    // EDITOR ACTIONS (Load / Save / Wipe)
    // =========================================================================

    public function LoadVault(): void
    {
        $cache = $this->_decryptVault();

        if ($cache === false) {
            $json = ($this->GetValue("Vault") === "") ? "{}" : "";
            if ($json === "") {
                echo "❌ Fehler: Entschlüsselung fehlgeschlagen.";
                return;
            }
        } else {
            $json = str_replace(['"__folder": true,', ',"__folder": true', '"__folder": true'], '', json_encode($cache, JSON_PRETTY_PRINT));
        }

        // WICHTIG: Wir schreiben nicht in eine Property, sondern schicken 
        // das Passwort direkt an das Textfeld in der UI.
        $this->UpdateFormField("InputJson", "value", $json);
        $this->UpdateFormField("InputJson", "visible", true);
        $this->UpdateFormField("BtnEncrypt", "visible", true);
        $this->UpdateFormField("BtnClear", "visible", true);
        $this->UpdateFormField("LabelSecurityWarning", "visible", true);
        $this->UpdateFormField("BtnLoad", "visible", false);
    }
    // Beachte den Parameter $jsonInput!
    public function EncryptAndSave(string $jsonInput): void
    {
        $mode = $this->ReadPropertyInteger("OperationMode");

        // --- SCHRITT 4: Zugriffskontrolle ---
        // Nur Master (1) und Standalone (2) dürfen lokal verschlüsseln und speichern.
        // Slaves (0) empfangen Daten nur über den WebHook.
        if ($mode === 0) {
            echo "Operation not allowed in Slave mode.";
            return;
        }

        if (trim($jsonInput) === "") {
            echo "Input empty.";
            return;
        }

        // JSON validieren
        $decoded = json_decode($jsonInput, true);
        if ($decoded === null) {
            echo "❌ JSON Syntax Error!";
            return;
        }

        // Verschlüsseln und lokal in die Variable "Vault" schreiben
        if ($this->_encryptAndSave($decoded)) {

            // UI wieder in den "Sicheren Modus" (Gesperrt) versetzen
            $this->UpdateFormField("InputJson", "value", "");
            $this->UpdateFormField("InputJson", "visible", false);
            $this->UpdateFormField("BtnEncrypt", "visible", false);
            $this->UpdateFormField("BtnClear", "visible", false);
            $this->UpdateFormField("LabelSecurityWarning", "visible", false);
            $this->UpdateFormField("BtnLoad", "visible", true);

            echo "✅ Saved & Encrypted locally.";

            // --- SCHRITT 4: Bedingter Sync ---
            // Nur wenn wir Master (1) sind, stossen wir den Sync an die Slaves an.
            // Ein Standalone-System (2) bleibt hier stehen.
            if ($mode === 1) {
                $this->SyncSlaves();
            }
        } else {
            echo "❌ Error: Encryption failed.";
        }
    }

    public function ClearVault(): void
    {
        // Einfach alles wieder verstecken und leeren
        $this->UpdateFormField("InputJson", "value", "");
        $this->UpdateFormField("InputJson", "visible", false);
        $this->UpdateFormField("BtnEncrypt", "visible", false);
        $this->UpdateFormField("BtnClear", "visible", false);
        $this->UpdateFormField("LabelSecurityWarning", "visible", false);
        $this->UpdateFormField("BtnLoad", "visible", true);
    }

    // =========================================================================
    // PUBLIC API (For Scripts)
    // =========================================================================

    public function GetKeys(): string
    {
        if ($this->GetStatus() !== 102) return json_encode([]);

        $cache = $this->_decryptVault();
        if ($cache === false || !is_array($cache)) return json_encode([]);

        $keys = array_keys($cache);

        // option 1: interne Keys ausblenden
        $keys = array_values(array_filter($keys, function ($k) {
            return (strpos((string)$k, "__") !== 0);
        }));

        return json_encode($keys);
    }



    public function GetSecret(string $ident): string
    {
        if ($this->GetStatus() !== 102) return "";

        $vault = $this->_decryptVault();
        if ($vault === false || !is_array($vault)) {
            if ($this->GetValue("Vault") !== "") {
                $this->LogMessage("Decryption failed. Check Key File.", KL_ERROR);
            }
            return "";
        }

        if (!array_key_exists($ident, $vault)) {
            trigger_error("SecretsManager: Secret '$ident' not found.", E_USER_NOTICE);
            return "";
        }

        $val = $vault[$ident];
        return (is_array($val) || is_object($val)) ? (str_replace(['"__folder":true,', ',"__folder":true', '"__folder":true'], '', json_encode($val)) ?: "") : (string)$val;
    }


    // =========================================================================
    // SYNCHRONIZATION (Master -> Slave)
    // =========================================================================

    /**
     * SYNCHRONIZATION (Master -> Slave)
     * Pushes the encrypted vault and the master key to all configured remote systems.
     */


    public function SyncSlaves(): void
    {
        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode !== 1) {
            $this->LogMessage(
                ($mode === 2) ? "Sync cancelled: Standalone systems are isolated."
                    : "Sync cancelled: Only Master instances can initiate synchronization.",
                KL_WARNING
            );
            return;
        }

        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        if (!is_array($slaves) || count($slaves) === 0) {
            $this->LogMessage("No slaves configured in the list.", KL_WARNING);
            return;
        }

        $token = $this->getAuthToken(); // encrypted system.vault
        if ($token === "") {
            $this->LogMessage("Sync aborted: missing AuthToken in encrypted system file.", KL_ERROR);
            return;
        }

        $keyHex = $this->_readKey();
        $vault  = $this->GetValue("Vault");
        if (!$keyHex || $vault === "") {
            $this->LogMessage("Sync aborted: Missing key or vault. Encrypt & Save first.", KL_ERROR);
            return;
        }

        $sys = $this->loadSystemSecrets(); // current key
        $slavePassMap = (isset($sys['slaves']) && is_array($sys['slaves'])) ? $sys['slaves'] : [];

        $successCount = 0;
        $attempted    = 0;

        foreach ($slaves as $slave) {
            $url = trim((string)($slave['Url'] ?? ''));
            if ($url === '') continue;

            $label = trim((string)($slave['Server'] ?? ''));
            $who = ($label !== '') ? $label : $url;

            $tlsMode      = (string)($slave['TlsMode'] ?? 'strict');        // http | strict | pinned
            $fpExp        = (string)($slave['Fingerprint'] ?? '');
            $keyTransport = (string)($slave['KeyTransport'] ?? 'manual');   // manual | sync

            // POLICY: Manual = Skip (vault/key not sent)
            if ($keyTransport === 'manual') {
                $this->LogMessage("⚠️ Sync skipped (manual key provisioning): $who", KL_WARNING);
                continue;
            }

            // POLICY: sync+http = skip entirely
            if ($keyTransport === 'sync' && $tlsMode === 'http') {
                $this->LogMessage("❌ Sync skipped (insecure transport for key: HTTP): $who", KL_ERROR);
                continue;
            }

            // KeyTransport=sync only allowed with strict/pinned → send key + vault
            $payloadArr = [
                'auth'  => $token,
                'vault' => $vault,
                'key'   => $keyHex
            ];
            $payload = json_encode($payloadArr);

            $headers = ['Content-Type: application/json'];

            // Optional Basic Auth per slave
            $user = trim((string)($slave['User'] ?? ''));
            if ($user !== '') {
                $pass = (string)($slavePassMap[$url] ?? '');
                if ($pass === '') {
                    $this->LogMessage("❌ Sync blocked: BasicAuth user set but no password stored for $who", KL_ERROR);
                    continue;
                }
                $headers[] = 'Authorization: Basic ' . base64_encode($user . ':' . $pass);
            }

            $attempted++;

            try {
                if ($tlsMode === 'strict') {
                    $result = $this->httpsPostJsonStrict($url, $payload, $headers);
                } elseif ($tlsMode === 'pinned') {
                    if (trim($fpExp) === '') throw new Exception("Pinned mode requires Fingerprint.");
                    $result = $this->httpsPostJsonPinned($url, $payload, $headers, $fpExp);
                } else {
                    throw new Exception("Unknown/unsupported TLS mode for key sync: " . $tlsMode);
                }

                $statusLine = (string)($result['status'] ?? 'Unknown Status');
                $body = trim((string)($result['body'] ?? ''));

                $ok = (strpos($statusLine, '200') !== false && $body === 'OK');

                if ($ok) {
                    $successCount++;
                    $this->LogMessage("✅ Sync OK [$tlsMode, key=sent] $who", KL_MESSAGE);
                } else {
                    $respShort = $body;
                    if (strlen($respShort) > 180) $respShort = substr($respShort, 0, 180) . "...";
                    $this->LogMessage("❌ Sync FAIL [$tlsMode, key=sent] $who | $statusLine | " . ($respShort ?: '(no body)'), KL_ERROR);
                }
            } catch (Throwable $e) {
                $this->LogMessage("❌ Sync EXC  [$tlsMode, key=sent] $who | " . $e->getMessage(), KL_ERROR);
            }
        }

        $this->LogMessage("Sync summary: $successCount / $attempted successful (skipped slaves not counted).", ($successCount === $attempted) ? KL_MESSAGE : KL_WARNING);
    }

    

// =========================================================================
    // NAVIGATION & LOGIK FÜR DEN EXPLORER
    // =========================================================================

    /**
     * RequestAction ist das zentrale Eingangstor für alle Buttons des Explorers.
     */
    /**
     * ZENTRALES EINGANGSTOR FÜR UI-AKTIONEN
     */
    /**
     * ZENTRALES EINGANGSTOR FÜR UI-AKTIONEN
     */
    public function RequestAction($Ident, $Value): void
    {

        if (strpos($Ident, 'EXPL_') === 0) {
            switch ($Ident) {
                case "EXPL_HandleClick":
                    // LOG: Rohdaten prüfen
                    $row = json_decode((string)$Value, true);
                    $ident = $row['Ident'] ?? 'FEHLT';
                    $type = $row['Type'] ?? 'FEHLT';

                    // LOG: Erhaltene Werte nach Dekodierung
                    $this->LogMessage("DEBUG: Klick auf Ident: " . $ident . " | Typ: " . $type, KL_MESSAGE);

                    if ($type === "Folder") {
                        $current = (string)$this->GetBuffer("CurrentPath");
                        $newPath = ($current === "") ? $ident : $current . "/" . $ident;

                        $this->SetBuffer("CurrentPath", $newPath);

                        // LOG: Erfolgsmeldung Navigation
                        $this->LogMessage("DEBUG: Navigation ERFOLGREICH. Neuer Pfad: " . $newPath, KL_MESSAGE);
                    }
                    // Hinweis: Records werden jetzt über das Zahnrad (form) editiert
                    break;

                case "EXPL_NavUp":
                    $this->LogMessage("DEBUG: Navigation EBENE HOCH", KL_MESSAGE);
                    $parts = explode('/', (string)$this->GetBuffer("CurrentPath"));
                    array_pop($parts);
                    $this->SetBuffer("CurrentPath", implode('/', $parts));
                    break;

                case "EXPL_SaveRecord":
                    $payload = json_decode((string)$Value, true);
                    $this->ProcessExplorerSave($payload['Ident'], $payload['Data']);
                    break;

                case "EXPL_RenameFolder":
                    // Verarbeitet die Umbenennung aus dem neuen Popup-Formular
                    $payload = json_decode((string)$Value, true);
                    $this->ProcessExplorerRename($payload['Old'], $payload['New']);
                    break;

                case "EXPL_CreateFolder":
                    $this->ProcessExplorerCreate((string)$Value, 'Folder');
                    break;

                case "EXPL_CreateRecord":
                    $this->ProcessExplorerCreate((string)$Value, 'Record');
                    break;

                case "EXPL_DeleteItem":
                    // Empfängt jetzt direkt den Namen (String)
                    $this->ProcessExplorerDelete((string)$Value);
                    break;

                case "EXPL_ImportJson":
                    $data = json_decode((string)$Value, true);
                    if (is_array($data)) {
                        // Use the hybrid-safe saving method to ensure structure is recognized
                        $this->SetBuffer("CurrentPath", "");
                        $this->_encryptAndSave($data);
                        echo "✅ Import erfolgreich!";
                    } else {
                        echo "❌ Fehler: Ungültiges JSON-Format.";
                    }
                    break;
            }
            $this->ReloadForm();
            return;
        }

        // Falls du das Modul später erweiterst, hier Platz für weitere Standard-Actions...
    }
    /**
     * Benennt einen Ordner oder einen Record innerhalb der aktuellen Ebene um.
     */
    private function ProcessExplorerRename(string $old, string $new): void
    {
        // Validierung: Name darf nicht leer sein und muss sich unterscheiden
        if ($new === "" || $old === $new) {
            return;
        }

        $vaultData = $this->_decryptVault();
        if ($vaultData === false) {
            return;
        }

        $currentPath = (string)$this->GetBuffer("CurrentPath");
        $temp = &$vaultData;

        // 1. Zum aktuellen Pfad navigieren
        if ($currentPath !== "") {
            $parts = explode('/', $currentPath);
            foreach ($parts as $part) {
                if (isset($temp[$part]) && is_array($temp[$part])) {
                    $temp = &$temp[$part];
                }
            }
        }

        // 2. Umbenennen-Logik
        if (isset($temp[$old])) {
            // Prüfen, ob der neue Name bereits existiert (um Überschreiben zu verhindern)
            if (isset($temp[$new])) {
                echo "❌ Fehler: Der Name '$new' existiert bereits an dieser Position.";
                return;
            }

            // Neuen Key mit altem Inhalt erstellen und alten Key löschen
            $temp[$new] = $temp[$old];
            unset($temp[$old]);

            // 3. Verschlüsselt speichern
            if ($this->_encryptAndSave($vaultData)) {
                $this->LogMessage("Explorer: '$old' wurde in '$new' umbenannt.", KL_MESSAGE);
                echo "✅ Umbenannt in '$new'";

                // Falls Master-Rolle, Slaves informieren
                if ($this->ReadPropertyInteger("OperationMode") === 1) {
                    $this->SyncSlaves();
                }
            }
        } else {
            $this->LogMessage("Explorer Fehler: Zu benennendes Element '$old' nicht gefunden.", KL_WARNING);
        }
    }      
        // Falls du das Modul später erweiterst, hier weitere Standard-Actions...
    
        // Andere Standard-Aktionen von IP-Symcon (z.B. SEC_UpdateUI) falls nötig durchreichen
        // parent::RequestAction($Ident, $Value);
    

    // =========================================================================
    // PRIVATE VERARBEITUNGSMETHODEN FÜR EXPLORER
    // =========================================================================

    /**
     * Löscht ein Element (Ordner oder Record) an der aktuellen Position.
     */
    private function ProcessExplorerDelete(string $name): void
    {
        $vaultData = $this->_decryptVault();
        if ($vaultData === false) {
            return;
        }

        $currentPath = (string)$this->GetBuffer("CurrentPath");
        $temp = &$vaultData;

        // 1. Navigation zum aktuellen Pfad
        if ($currentPath !== "") {
            $parts = explode('/', $currentPath);
            foreach ($parts as $part) {
                if (isset($temp[$part]) && is_array($temp[$part])) {
                    $temp = &$temp[$part];
                }
            }
        }

        // 2. Löschvorgang
        if (isset($temp[$name])) {
            unset($temp[$name]);

            // 3. Verschlüsselt speichern
            if ($this->_encryptAndSave($vaultData)) {
                $this->LogMessage("Explorer: '" . $name . "' an Position '$currentPath' gelöscht.", KL_MESSAGE);
                echo "🗑️ '" . $name . "' wurde gelöscht.";

                // Falls Master-Rolle, Slaves synchronisieren
                if ($this->ReadPropertyInteger("OperationMode") === 1) {
                    $this->SyncSlaves();
                }
            }
        }
    }

    private function ProcessExplorerSave(string $ident, array $fieldList): void
    {
        $vaultData = $this->_decryptVault() ?: [];

        // Path calculation: Handle empty ident for current level (Hybrid)
        $currentPath = (string)$this->GetBuffer("CurrentPath");
        $fullPath = ($ident === "") ? $currentPath : (($currentPath === "") ? $ident : $currentPath . "/" . $ident);

        $newFields = [];
        foreach ($fieldList as $row) {
            if (isset($row['Key']) && $row['Key'] !== "") {
                $newFields[(string)$row['Key']] = (string)$row['Value'];
            }
        }

        $parts = array_filter(explode('/', $fullPath), 'strlen');
        $temp = &$vaultData;
        foreach ($parts as $part) {
            if (!isset($temp[$part]) || !is_array($temp[$part])) $temp[$part] = [];
            $temp = &$temp[$part];
        }

        // --- HYBRID MERGE LOGIC ---
        // Preserve sub-folders (arrays) and internal flags, replace only flat values
        foreach ($temp as $key => $value) {
            if ($key !== "__folder" && !is_array($value)) {
                unset($temp[$key]);
            }
        }
        foreach ($newFields as $k => $v) {
            $temp[$k] = $v;
        }

        if ($this->_encryptAndSave($vaultData)) {
            echo ($ident === "") ? "✅ Ordner-Felder aktualisiert!" : "✅ Eintrag '$ident' aktualisiert!";
            if ($this->ReadPropertyInteger("OperationMode") === 1) $this->SyncSlaves();
        }
    }

    /**
     * Hilfsfunktion für das dynamische Popup-Formular
     */
    public function GetExplorerFields(string $ident): array
    {
        $vaultData = $this->_decryptVault() ?: [];
        $currentPath = (string)$this->GetBuffer("CurrentPath");
        $fullPath = ($currentPath === "") ? $ident : $currentPath . "/" . $ident;

        $fields = $this->GetNestedValue($vaultData, $fullPath);
        $result = [];
        if (is_array($fields)) {
            foreach ($fields as $k => $v) {
                if (!is_array($v) && $k !== "__folder") {
                    $result[] = ["Key" => $k, "Value" => (string)$v];
                }
            }
        }
        return $result;
    }

    private function ProcessExplorerCreate(string $name, string $type): void
    {
        // 1. Basis-Validierung
        if ($name === "") {
            return;
        }

        // 2. Sicherheits-Validierung: Schrägstriche im Namen verbieten
        if (strpos($name, '/') !== false) {
            echo "❌ Fehler: Der Name darf keinen Schrägstrich (/) enthalten!";
            return;
        }

        $vaultData = $this->_decryptVault() ?: [];
        $currentPath = (string)$this->GetBuffer("CurrentPath");

        // 3. Navigiere zum aktuellen Pfad im Array (Deep Navigation)
        $temp = &$vaultData;
        if ($currentPath !== "") {
            // array_filter entfernt leere Fragmente bei führenden/folgenden Slashes
            $parts = array_filter(explode('/', $currentPath));
            foreach ($parts as $part) {
                // Wir stellen sicher, dass jeder Teil des Pfades ein Array ist
                if (!isset($temp[$part]) || !is_array($temp[$part])) {
                    $temp[$part] = [];
                }
                $temp = &$temp[$part];
            }
        }

        // 4. Kollisionsprüfung: Existiert der Name bereits auf dieser Ebene?
        if (isset($temp[$name])) {
            echo "❌ Fehler: Ein Element mit dem Namen '$name' existiert bereits an dieser Position.";
            return;
        }

        // 5. Erstelle das neue Element
        if ($type === 'Folder') {
            // Ordner mit technischem Flag anlegen
            $temp[$name] = [];
            $this->LogMessage("Explorer: Unterordner '$name' erstellt in Pfad '$currentPath'.", KL_MESSAGE);
        } else {
            // Neuer Datensatz mit Standardfeldern
            $temp[$name] = ["User" => "", "Pass" => ""];
            $this->LogMessage("Explorer: Datensatz '$name' erstellt in Pfad '$currentPath'.", KL_MESSAGE);
        }

        // 6. Alles verschlüsselt speichern und UI aktualisieren
        if ($this->_encryptAndSave($vaultData)) {
            $this->ReloadForm();
            // Falls Master-Rolle, Slaves informieren
            if ($this->ReadPropertyInteger("OperationMode") === 1) {
                $this->SyncSlaves();
            }
        }
    }
    /**
     * Prüft, ob ein Array als Ordner (Container) oder als Datensatz (Record) zu behandeln ist.
     */
    private function CheckIfFolder($value): bool
    {
        // Kein Array -> definitiv kein Ordner
        if (!is_array($value)) {
            return false;
        }

        // Ein leeres Array ist immer ein Ordner (neuer oder geleerter Container)
        if (empty($value)) {
            return true;
        }

        // Check for the internal tag injected by _decryptVault
        if (isset($value['__folder'])) {
            return true;
        }

        // Strukturprüfung: Wenn das Array mindestens ein weiteres Array enthält,
        // ist es ein Ordner. Enthält es nur Strings (User, PW...), ist es ein Record.
        foreach ($value as $v) {
            if (is_array($v)) {
                return true;
            }
        }

        // Nur flache Werte gefunden -> es ist ein Datensatz (Record)
        return false;
    }

    private function GetNestedValue($array, $path)
    {
        $parts = explode('/', $path);
        foreach ($parts as $part) {
            if (isset($array[$part])) $array = $array[$part];
            else return null;
        }
        return $array;
    }
    private function HandleExplorerSave(array $inputList): void
    {
        $vaultData = $this->_decryptVault() ?: [];
        $selected = $this->GetSelected();
        $fullPath = ($this->GetNavPath() === "") ? $selected : $this->GetNavPath() . "/" . $selected;

        $newFields = [];
        foreach ($inputList as $row) {
            if ($row['Key'] !== "") $newFields[(string)$row['Key']] = (string)$row['Value'];
        }

        // Navigiere im Array und setze Daten
        $parts = explode('/', $fullPath);
        $temp = &$vaultData;
        foreach ($parts as $part) {
            if (!isset($temp[$part]) || !is_array($temp[$part])) $temp[$part] = [];
            $temp = &$temp[$part];
        }
        $temp = $newFields;

        if ($this->_encryptAndSave($vaultData)) {
            echo "✅ Tresor aktualisiert!";
            if ($this->ReadPropertyInteger("OperationMode") === 1) $this->SyncSlaves();
        }
    }


    private function httpPostJson(string $url, string $payload, array $headers): array
    {
        $ctx = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => implode("\r\n", $headers) . "\r\n",
                'content'       => $payload,
                'timeout'       => 5,
                'ignore_errors' => true
            ]
        ]);

        $body = @file_get_contents($url, false, $ctx);
        $status = $http_response_header[0] ?? 'Unknown Status';

        return [
            'status' => $status,
            'body'   => ($body === false) ? '' : (string)$body
        ];
    }
    private function httpsPostJsonStrict(string $url, string $payload, array $headers): array
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https') {
            throw new Exception("Strict mode requires https:// URL");
        }

        $host = (string)($parts['host'] ?? '');
        if ($host === '') throw new Exception("Invalid URL host.");

        $ctx = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => implode("\r\n", $headers) . "\r\n",
                'content'       => $payload,
                'timeout'       => 5,
                'ignore_errors' => true
            ],
            'ssl' => [
                'verify_peer'       => true,
                'verify_peer_name'  => true,
                'allow_self_signed' => false,
                'SNI_enabled'       => true,
                'peer_name'         => $host
            ]
        ]);

        $body = @file_get_contents($url, false, $ctx);
        $status = $http_response_header[0] ?? 'Unknown Status';

        return [
            'status' => $status,
            'body'   => ($body === false) ? '' : (string)$body
        ];
    }

    private function httpsPostJsonPinned(string $url, string $payload, array $headers, string $expectedFingerprint): array
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https') {
            throw new Exception("Pinned mode requires https:// URL");
        }

        $host = (string)($parts['host'] ?? '');
        if ($host === '') throw new Exception("Invalid URL host.");

        $port = (int)($parts['port'] ?? 443);
        $path = (string)($parts['path'] ?? '/');
        $query = (string)($parts['query'] ?? '');
        if ($query !== '') $path .= '?' . $query;

        $expected = $this->normalizeFingerprint($expectedFingerprint);

        $sslCtx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'SNI_enabled'       => true,
                'peer_name'         => $host
            ]
        ]);

        $fp = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $sslCtx
        );

        if ($fp === false) {
            throw new Exception("TLS connect failed: $errstr ($errno)");
        }

        // Zertifikat auslesen und Fingerprint berechnen
        $params = stream_context_get_params($fp);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$cert) {
            fclose($fp);
            throw new Exception("No peer certificate received.");
        }

        $actual = $this->certSha256Fingerprint($cert);
        if ($actual === '' || $actual !== $expected) {
            fclose($fp);
            throw new Exception("Pinned cert mismatch. Expected=$expected Actual=$actual");
        }

        // Ab hier: Cert ist OK -> jetzt erst HTTP senden
        $reqHeaders = $headers;
        $reqHeaders[] = "Host: {$host}";
        $reqHeaders[] = "Content-Length: " . strlen($payload);
        $reqHeaders[] = "Connection: close";

        $request =
            "POST {$path} HTTP/1.1\r\n" .
            implode("\r\n", $reqHeaders) . "\r\n\r\n" .
            $payload;

        fwrite($fp, $request);

        $response = stream_get_contents($fp);
        fclose($fp);

        if ($response === false) $response = '';

        // Statuszeile + Body trennen
        $statusLine = 'Unknown Status';
        $body = $response;

        $pos = strpos($response, "\r\n");
        if ($pos !== false) {
            $statusLine = substr($response, 0, $pos);
        }
        $sep = strpos($response, "\r\n\r\n");
        if ($sep !== false) {
            $body = substr($response, $sep + 4);
        }

        return [
            'status' => $statusLine,
            'body'   => (string)$body
        ];
    }


    private function normalizeFingerprint(string $fp): string
    {
        $fp = strtolower($fp);
        // erlaubt Eingaben mit ":" oder Leerzeichen – wir nehmen nur hex
        $fp = preg_replace('/[^0-9a-f]/', '', $fp) ?? '';
        return $fp;
    }

    private function certSha256Fingerprint($x509Cert): string
    {
        // Export zu PEM
        $pem = '';
        if (!openssl_x509_export($x509Cert, $pem)) {
            return '';
        }

        // PEM -> DER (Base64)
        $pem = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $pem) ?? '';
        $der = base64_decode($pem, true);
        if ($der === false) return '';

        return hash('sha256', $der);
    }

    private function ServeAdminDashboard(): void
    {
        $vault = $this->_decryptVault();
        if ($vault === false) {
            echo "Fehler: Tresor konnte nicht entschlüsselt werden.";
            return;
        }

        $regPass = $vault['RegistrationPassword']['PW'] ?? '';
        if ($regPass === '') {
            echo "Fehler: 'RegistrationPassword' -> 'PW' nicht im Tresor gefunden.";
            return;
        }

        echo '<html><head><title>Admin Dashboard</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;background:#f4f7f6;padding:20px;color:#333;}';
        echo '.box{background:#fff;padding:25px;border-radius:12px;box-shadow:0 5px 20px rgba(0,0,0,0.1);max-width:1000px;margin:auto;}';
        echo 'h1{border-bottom:2px solid #eee;padding-bottom:10px;color:#2c3e50;}';
        echo 'table{width:100%;border-collapse:collapse;margin-top:20px;} th,td{padding:12px;border-bottom:1px solid #eee;text-align:left;}';
        echo 'th{background:#f8f9fa;color:#666;font-size:13px;text-transform:uppercase;}';
        echo '.link-cell{word-break:break-all;font-family:monospace;font-size:12px;background:#f9f9f9;padding:8px;border-radius:4px;display:block;}';
        echo 'a{color:#4a90e2;text-decoration:none;} a:hover{text-decoration:underline;}';
        echo '.tag{font-size:10px;padding:2px 6px;border-radius:10px;background:#eee;color:#777;margin-left:8px;vertical-align:middle;}</style></head><body>';

        echo '<div class="box"><h1>🛠️ Admin Dashboard</h1>';
        echo '<p>Registrierungs-Links für Ihre konfigurierten Systeme:</p>';
        echo '<table><tr><th>Systemquelle / Name</th><th>Registrierungs-URL (für Passkey)</th></tr>';

        // --- 1. LOKALES SYSTEM (Automatisch ermittelt) ---
        $localDomain = $_SERVER['HTTP_HOST'];
        $localUrl = "https://$localDomain/hook/secrets_" . $this->InstanceID . "?register=1&pass=" . urlencode($regPass);
        echo '<tr><td><strong>LOKAL</strong><span class="tag">Dieser Server</span></td>';
        echo '<td><a href="' . $localUrl . '" target="_blank" class="link-cell">' . htmlspecialchars($localUrl) . "</a></td></tr>";

        // --- 2. REMOTE SLAVES (Aus der Slave-Liste) ---
        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true) ?: [];
        foreach ($slaves as $slave) {
            $url = trim($slave['Url'] ?? '');
            if ($url !== '') {
                $name = $slave['Server'] ?? 'Unbekannter Slave';
                // Parameter-Handling (? oder &)
                $sep = (strpos($url, '?') === false) ? '?' : '&';
                $fullUrl = $url . $sep . "register=1&pass=" . urlencode($regPass);

                echo '<tr><td><strong>' . htmlspecialchars($name) . '</strong><span class="tag">Slave Liste</span></td>';
                echo '<td><a href="' . $fullUrl . '" target="_blank" class="link-cell">' . htmlspecialchars($fullUrl) . "</a></td></tr>";
            }
        }

        echo '</table>';
        echo '<br><p style="color:#e74c3c;font-size:12px;">⚠️ <strong>Sicherheitshinweis:</strong> Diese Links enthalten das Registrierungs-Passwort. Nur autorisierten Personen zugänglich machen.</p>';
        echo '</div></body></html>';
    }


    /**
     * WEBHOOK DATA PROCESSING
     * This is called by IP-Symcon when data is posted to /hook/secrets_ID
     */
    protected function ProcessHookData(): void
    {
        $mode = $this->ReadPropertyInteger("OperationMode");
        $isPortal = isset($_GET['portal']);
        $isRegister = isset($_GET['register']);
        $isAdmin = isset($_GET['admin']);

        // --- GATE 1: Admin Dashboard (Password or Passkey) ---
        if ($isAdmin) {
            if ($this->IsPortalAuthenticated()) {
                $this->ServeAdminDashboard();
                return;
            }
            $vaultData = $this->_decryptVault();
            $adminPass = $vaultData['AdminPortal']['PW'] ?? '';
            if ($adminPass !== '' && ($_GET['pass'] ?? '') === $adminPass) {
                $sessionKey = "AuthSession_" . md5($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
                $this->SetBuffer($sessionKey, (string)(time() + 259200));
                $this->ServeAdminDashboard();
                return;
            }
            header("HTTP/1.1 403 Forbidden");
            echo "Access Denied: Admin authentication required.";
            return;
        }

        // --- GATE 2: Registration Password Check ---
        if ($isRegister) {
            $vaultData = $this->_decryptVault();
            $regPass = $vaultData['RegistrationPassword']['PW'] ?? '';
            if ($regPass === '' || ($_GET['pass'] ?? '') !== $regPass) {
                header("HTTP/1.1 403 Forbidden");
                echo "Access Denied: Invalid Registration Password.";
                return;
            }
        }

        // --- GATE 3: Mode & Standard Portal Access ---
        if ($mode !== 0 && !$isPortal && !$isRegister) {
            header("HTTP/1.1 403 Forbidden");
            echo "Access Denied: This instance is not configured as a Slave.";
            return;
        }

        // --- ROUTING ---
        if ($_SERVER['REQUEST_METHOD'] === 'GET' && $isRegister) {
            $this->ServeRegistrationUI();
            return;
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isRegister) {
            $this->FinishRegistration();
            return;
        }
        if ($_SERVER['REQUEST_METHOD'] === 'GET' && $isPortal) {
            $this->ServePortalUI();
            return;
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isPortal) {
            $this->VerifyPortalAccess();
            return;
        }

        // Standard Sync Logic (Slave only)
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $input = file_get_contents("php://input");
            $data = json_decode($input, true);
            $expectedToken = $this->getAuthToken();
            if (!isset($data['auth']) || $data['auth'] !== $expectedToken) {
                header("HTTP/1.1 403 Forbidden");
                echo "Invalid Sync Token";
                return;
            }
            // Merging logic here...
            if (isset($data['vault'])) {
                $currentVault = $this->_decryptVault() ?: [];
                $this->SetValue("Vault", (string)$data['vault']);
                $masterVault = $this->_decryptVault() ?: [];
                if (isset($currentVault['__AUTH__']) && is_array($currentVault['__AUTH__'])) {
                    $masterVault['__AUTH__'] = array_merge($masterVault['__AUTH__'] ?? [], $currentVault['__AUTH__']);
                }
                $this->_encryptAndSave($masterVault);
            }
            echo "OK";
        }
    }

    private function ServeRegistrationUI(): void
    {
        $challenge = random_bytes(32);
        $this->SetBuffer("RegChallenge", bin2hex($challenge));

        $challengeB64 = base64_encode($challenge);
        $rpName = "Symcon Vault (" . $_SERVER['HTTP_HOST'] . ")";

        echo '<html><head><title>Vault Register</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f4f7f6;}';
        echo '.box{background:#fff;padding:40px;border-radius:15px;box-shadow:0 10px 25px rgba(0,0,0,0.1);text-align:center;}</style></head><body>';
        echo '<div class="box"><h2>🔑 Passkey registrieren</h2><p>Klicken Sie unten, um dieses Gerät zu verknüpfen.</p>';
        echo '<button style="padding:10px 20px" onclick="register()">Dieses Gerät registrieren</button></div>';
        echo '<script>async function register(){';
        echo 'const challenge = Uint8Array.from(atob("' . $challengeB64 . '"), c => c.charCodeAt(0));';
        echo 'const userID = Uint8Array.from("user' . $this->InstanceID . '", c => c.charCodeAt(0));';
        echo 'const options = { publicKey: { rp: { name: "' . $rpName . '", id: window.location.hostname }, user: { id: userID, name: "owner", displayName: "Vault Owner" }, challenge, pubKeyCredParams: [{type: "public-key", alg: -7}], timeout: 60000, authenticatorSelection: { userVerification: "required" } } };';
        echo 'try { const cred = await navigator.credentials.create(options);';
        echo 'const resp = { id: cred.id, rawId: btoa(String.fromCharCode(...new Uint8Array(cred.rawId))), response: { attestationObject: btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject))), clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON))) }, type: cred.type };';
        echo 'const res = await fetch(window.location.href, { method: "POST", body: JSON.stringify(resp) });';
        echo 'alert(await res.text()); } catch(e) { alert("Fehler: " + e); } }';
        echo '</script></body></html>';
    }

    private function FinishRegistration(): void
    {
        $input = file_get_contents("php://input");
        $data = json_decode($input, true);
        $storedChallenge = $this->GetBuffer("RegChallenge");

        if (!$data) {
            $this->LogMessage("Passkey Reg: Keine Daten empfangen.", KL_ERROR);
            echo "Fehler: Keine Daten.";
            return;
        }

        if ($storedChallenge === "") {
            $this->LogMessage("Passkey Reg: Sicherheits-Puffer leer.", KL_ERROR);
            echo "Fehler: Puffer leer.";
            return;
        }

        $clientData = json_decode(base64_decode($data['response']['clientDataJSON']), true);
        $receivedChallenge = bin2hex(base64_decode(strtr($clientData['challenge'], '-_', '+/')));

        if ($receivedChallenge !== $storedChallenge) {
            $this->LogMessage("Passkey Reg: Challenge mismatch. Empfangen: $receivedChallenge, Erwartet: $storedChallenge", KL_ERROR);
            echo "Fehler: Challenge mismatch.";
            return;
        }

        $vaultData = $this->_decryptVault() ?: [];
        if (!isset($vaultData['__AUTH__']) || !is_array($vaultData['__AUTH__'])) {
            $vaultData['__AUTH__'] = [];
        }

        $vaultData['__AUTH__']['device_' . time()] = [
            'credentialId' => $data['rawId'],
            'attestation'  => $data['response']['attestationObject']
        ];

        if ($this->_encryptAndSave($vaultData)) {
            $this->SetBuffer("RegChallenge", "");
            $this->LogMessage("Passkey Reg: Gerät erfolgreich registriert.", KL_MESSAGE);
            echo "✅ Gerät erfolgreich registriert!";
        } else {
            echo "❌ Fehler beim Speichern.";
        }
    }

    private function VerifyPortalAccess(): void
    {
        $input = file_get_contents("php://input");
        $data = json_decode($input, true);

        $sid = $data['sid'] ?? '';
        $buffer = json_decode($this->GetBuffer("PortalChallenge_" . $sid), true);

        if (!$buffer || time() > $buffer['expires']) {
            $this->LogMessage("Portal Auth DEBUG: Puffer abgelaufen oder SID ungültig. SID: " . $sid, KL_ERROR);
            echo "Sitzung abgelaufen. Bitte Seite neu laden.";
            return;
        }

        $vaultData = $this->_decryptVault();
        if (!$vaultData || !isset($vaultData['__AUTH__'])) {
            $this->LogMessage("Portal Auth DEBUG: Keine __AUTH__ Daten im Tresor gefunden.", KL_ERROR);
            echo "Keine autorisierten Geräte im Tresor gefunden.";
            return;
        }

        $authenticated = false;
        $browserId = $data['rawId'] ?? 'FEHLT';

        // Log: Was sendet der Browser?
        $this->LogMessage("Portal Auth DEBUG: Browser-ID: " . $browserId, KL_MESSAGE);

        foreach ($vaultData['__AUTH__'] as $deviceId => $device) {
            if (!is_array($device)) continue;

            $storedId = $device['credentialId'] ?? 'FEHLT';
            // Log: Was ist im Tresor gespeichert?
            $this->LogMessage("Portal Auth DEBUG: Prüfe Tresor-Gerät ($deviceId) - ID: " . $storedId, KL_MESSAGE);

            if ($storedId === $browserId) {
                $this->LogMessage("Portal Auth DEBUG: ID Treffer! Prüfe nun Challenge...", KL_MESSAGE);

                $clientData = json_decode(base64_decode(strtr($data['response']['clientDataJSON'], '-_', '+/')), true);
                $receivedChallenge = bin2hex(base64_decode(strtr($clientData['challenge'], '-_', '+/')));
                $expectedChallenge = $buffer['challenge'];

                // Log: Challenge-Vergleich
                $this->LogMessage("Portal Auth DEBUG: Challenge Empfangen: " . $receivedChallenge, KL_MESSAGE);
                $this->LogMessage("Portal Auth DEBUG: Challenge Erwartet:  " . $expectedChallenge, KL_MESSAGE);

                if ($receivedChallenge === $expectedChallenge) {
                    $authenticated = true;
                    break;
                }
            }
        }

        if ($authenticated) {
            $sessionKey = "AuthSession_" . md5($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
            $this->SetBuffer($sessionKey, (string)(time() + 259200));
            $this->SetBuffer("PortalChallenge_" . $sid, "");
            echo "OK";
        } else {
            $this->LogMessage("Portal Auth DEBUG: Keine Übereinstimmung gefunden.", KL_ERROR);
            header("HTTP/1.1 401 Unauthorized");
            echo "Biometrische Verifizierung fehlgeschlagen.";
        }
    }

    public function IsPortalAuthenticated(): bool
    {
        // Prüfen, ob wir in einem Web-Kontext sind (verhindert Warnungen im Hintergrund)
        if (!isset($_SERVER['REMOTE_ADDR']) || !isset($_SERVER['HTTP_USER_AGENT'])) {
            return false;
        }

        $sessionKey = "AuthSession_" . md5($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
        $expiry = $this->GetBuffer($sessionKey);

        if ($expiry === "" || time() > (int)$expiry) {
            return false;
        }

        return true;
    }


    // =========================================================================
    // INTERNAL CRYPTO HELPERS
    // =========================================================================


    private const SYSTEM_VAULT_FILENAME = 'system.vault';

    private function getSystemVaultPath(): string
    {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if ($folder === "") return "";
        return rtrim($folder, '/\\') . DIRECTORY_SEPARATOR . self::SYSTEM_VAULT_FILENAME;
    }

    private function decryptVaultWithKeyHex(string $keyHex)
    {
        $vaultJson = $this->GetValue("Vault");
        if (!$vaultJson) return false;

        $meta = json_decode($vaultJson, true);
        if (!is_array($meta) || !isset($meta['data'], $meta['iv'], $meta['tag'])) return false;

        $cipher = $meta['cipher'] ?? "aes-128-gcm";

        $decrypted = openssl_decrypt(
            (string)$meta['data'],
            $cipher,
            hex2bin($keyHex),
            0,
            hex2bin((string)$meta['iv']),
            hex2bin((string)$meta['tag'])
        );

        if ($decrypted === false) return false;

        $arr = json_decode($decrypted, true);
        return is_array($arr) ? $arr : false;
    }

    private function encryptVaultToJsonWithKeyHex(array $dataArray, string $keyHex)
    {
        $plain = json_encode($dataArray);
        if ($plain === false) return false;

        $cipher = "aes-128-gcm";
        $iv = random_bytes(12);
        $tag = "";

        $cipherText = openssl_encrypt($plain, $cipher, hex2bin($keyHex), 0, $iv, $tag);
        if ($cipherText === false) return false;

        return json_encode([
            'cipher' => $cipher,
            'iv'     => bin2hex($iv),
            'tag'    => bin2hex($tag),
            'data'   => $cipherText
        ]);
    }

    private function loadSystemSecretsUsingKeyHex(string $keyHex): ?array
    {
        $path = $this->getSystemVaultPath();
        if ($path === "") return null;

        if (!file_exists($path)) {
            return []; // not existing is fine
        }

        $json = @file_get_contents($path);
        if ($json === false || trim($json) === '') return [];

        $meta = json_decode($json, true);
        if (!is_array($meta) || !isset($meta['data'], $meta['iv'], $meta['tag'])) return null;

        $cipher = $meta['cipher'] ?? "aes-128-gcm";

        $decrypted = openssl_decrypt(
            (string)$meta['data'],
            $cipher,
            hex2bin($keyHex),
            0,
            hex2bin((string)$meta['iv']),
            hex2bin((string)$meta['tag'])
        );

        if ($decrypted === false) return null;

        $arr = json_decode($decrypted, true);
        return is_array($arr) ? $arr : [];
    }

    private function saveSystemSecretsUsingKeyHex(array $data, string $keyHex): bool
    {
        $path = $this->getSystemVaultPath();
        if ($path === "") return false;

        $plain = json_encode($data);
        if ($plain === false) return false;

        $cipher = "aes-128-gcm";
        $iv = random_bytes(12);
        $tag = "";

        $cipherText = openssl_encrypt($plain, $cipher, hex2bin($keyHex), 0, $iv, $tag);
        if ($cipherText === false) return false;

        $out = json_encode([
            'cipher' => $cipher,
            'iv'     => bin2hex($iv),
            'tag'    => bin2hex($tag),
            'data'   => $cipherText
        ]);

        return $this->writeFileAtomic($path, $out, 0600);
    }

    private function rotateKeyFileAtomic(string $newKeyHex): bool
    {
        $keyPath = $this->_getFullPath();
        if ($keyPath === "") return false;

        $dir = dirname($keyPath);
        if (!is_dir($dir)) return false;

        $newPath = $keyPath . ".new";
        $bakPath = $keyPath . ".bak";

        if (!$this->writeFileAtomic($newPath, $newKeyHex, 0600)) {
            return false;
        }

        // move current to .bak (best effort)
        if (file_exists($keyPath)) {
            @rename($keyPath, $bakPath);
        }

        // activate new
        if (!@rename($newPath, $keyPath)) {
            // rollback attempt
            @rename($bakPath, $keyPath);
            @unlink($newPath);
            return false;
        }

        @chmod($keyPath, 0600);
        return true;
    }

    private function restoreKeyFromBak(): void
    {
        $keyPath = $this->_getFullPath();
        if ($keyPath === "") return;

        $bakPath = $keyPath . ".bak";
        if (file_exists($bakPath)) {
            @rename($bakPath, $keyPath);
            @chmod($keyPath, 0600);
        }
    }

    private function writeFileAtomic(string $path, string $content, int $chmod = 0600): bool
    {
        $dir = dirname($path);
        if (!is_dir($dir)) return false;

        $tmp = $path . ".tmp_" . bin2hex(random_bytes(4));

        $ok = (@file_put_contents($tmp, $content) !== false);
        if (!$ok) {
            @unlink($tmp);
            return false;
        }

        @chmod($tmp, $chmod);

        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }

        @chmod($path, $chmod);
        return true;
    }


    private function applySlaveUrlOptionsRecursive(array &$node, array $slaveOptions): void
    {
        // Node kann ein Element sein oder ein Container mit children/items
        if (isset($node['name']) && $node['name'] === 'SlaveCredUrl') {
            $node['options'] = $slaveOptions;
        }

        // ExpansionPanel: "items"
        if (isset($node['items']) && is_array($node['items'])) {
            foreach ($node['items'] as &$child) {
                $this->applySlaveUrlOptionsRecursive($child, $slaveOptions);
            }
        }

        // Falls es irgendwo "elements" in Unterknoten geben sollte (future-proof)
        if (isset($node['elements']) && is_array($node['elements'])) {
            foreach ($node['elements'] as &$child) {
                $this->applySlaveUrlOptionsRecursive($child, $slaveOptions);
            }
        }
    }

    private function getSystemPath(): string
    {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if ($folder === "") return "";
        return rtrim($folder, '/\\') . DIRECTORY_SEPARATOR . self::SYSTEM_FILENAME;
    }

    private function loadSystemSecrets(): array
    {
        $path = $this->getSystemPath();
        if ($path === "" || !file_exists($path)) return [];

        $keyHex = $this->_readKey();
        if (!$keyHex) return [];

        $blob = @file_get_contents($path);
        if ($blob === false || trim($blob) === "") return [];

        $meta = json_decode($blob, true);
        if (!is_array($meta) || !isset($meta['data'], $meta['iv'], $meta['tag'])) return [];

        $plain = openssl_decrypt(
            (string)$meta['data'],
            "aes-128-gcm",
            hex2bin($keyHex),
            0,
            hex2bin((string)$meta['iv']),
            hex2bin((string)$meta['tag'])
        );

        if ($plain === false) return [];

        $arr = json_decode($plain, true);
        return is_array($arr) ? $arr : [];
    }

    private function saveSystemSecrets(array $data): bool
    {
        $path = $this->getSystemPath();
        if ($path === "") return false;

        $keyHex = $this->_readKey();
        if (!$keyHex) return false;

        $iv = random_bytes(12);
        $tag = "";
        $cipherText = openssl_encrypt(
            json_encode($data),
            "aes-128-gcm",
            hex2bin($keyHex),
            0,
            $iv,
            $tag
        );
        if ($cipherText === false) return false;

        $blob = json_encode([
            'cipher' => 'aes-128-gcm',
            'iv'     => bin2hex($iv),
            'tag'    => bin2hex($tag),
            'data'   => $cipherText
        ]);

        return (@file_put_contents($path, $blob) !== false);
    }

    private function getAuthToken(): string
    {
        $sys = $this->loadSystemSecrets();
        return (string)($sys['authToken'] ?? '');
    }

    private function getHookPass(): string
    {
        $sys = $this->loadSystemSecrets();
        return (string)($sys['hookPass'] ?? '');
    }



    private function _getFullPath(): string
    {
        $folder = $this->ReadPropertyString("KeyFolderPath");
        if ($folder === "") return "";
        return rtrim($folder, '/\\') . DIRECTORY_SEPARATOR . self::KEY_FILENAME;
    }

    private function _encryptAndSave(array $dataArray): bool
    {
        $keyHex = $this->_loadOrGenerateKey();
        if (!$keyHex) return false;

        $newKeyBin = hex2bin($keyHex);
        $plain = str_replace(['"__folder":true,', ',"__folder":true', '"__folder":true'], '', json_encode($dataArray));

        $cipher = "aes-128-gcm";
        $iv = random_bytes(openssl_cipher_iv_length($cipher));
        $tag = "";

        $cipherText = openssl_encrypt($plain, $cipher, $newKeyBin, 0, $iv, $tag);
        if ($cipherText === false) return false;

        $vaultData = json_encode([
            'cipher' => $cipher,
            'iv'     => bin2hex($iv),
            'tag'    => bin2hex($tag),
            'data'   => $cipherText
        ]);

        $this->SetValue("Vault", $vaultData);

        // (ENTFÄLLT) Disk-clean: kein Klartext-Cache
        // $this->_setCache($dataArray);

        return true;
    }


    private function _decryptVault()
    {
        $vaultJson = $this->GetValue("Vault");
        if (!$vaultJson || $vaultJson === "") return false;

        $meta = json_decode($vaultJson, true);
        $keyHex = $this->_readKey();

        if (!$keyHex || !$meta || !isset($meta['data'])) return false;

        $decrypted = openssl_decrypt(
            (string)$meta['data'],
            $meta['cipher'] ?? "aes-128-gcm",
            hex2bin($keyHex),
            0,
            hex2bin((string)$meta['iv']),
            hex2bin((string)$meta['tag'])
        );

        // --- KORREKTUR: Erst prüfen, ob Entschlüsselung erfolgreich war ---
        if ($decrypted === false) {
            return false;
        }

        $data = json_decode($decrypted, true);

        // --- NORMALIZATION: Inject internal folder flags for UI logic ---
        if (is_array($data)) {
            $normalize = function (&$item) use (&$normalize) {
                if (!is_array($item)) return;
                $isFolder = false;
                foreach ($item as $k => &$v) {
                    if (is_array($v)) {
                        $isFolder = true;
                        $normalize($v);
                    }
                }
                if ($isFolder || empty($item)) {
                    $item['__folder'] = true;
                }
            };
            $normalize($data);
        }

        return $data;
    }


    // --- NEU: EXPLORER HELPER ---
    private function GetNavPath(): string
    {
        return (string)$this->GetBuffer("CurrentPath");
    }
    private function SetNavPath(string $path): void
    {
        $this->SetBuffer("CurrentPath", $path);
    }

    private function _loadOrGenerateKey()
    {
        $path = $this->_getFullPath();
        if ($path === "") return false;

        // Wenn die Datei schon existiert, laden wir sie einfach
        if (file_exists($path)) {
            return trim(file_get_contents($path));
        }

        // --- KORREKTUR HIER ---
        // Ein Schlüssel darf generiert werden, wenn wir Master (1) ODER Standalone (2) sind.
        $mode = $this->ReadPropertyInteger("OperationMode");
        if ($mode === 1 || $mode === 2) {
            $newKey = bin2hex(random_bytes(16));
            if (file_put_contents($path, $newKey) === false) {
                return false; // Verzeichnis eventuell nicht schreibbar
            }
            return $newKey;
        }

        return false;
    }

    private function _readKey()
    {
        return $this->_loadOrGenerateKey();
    }

    private function _writeKey(string $hexKey): void
    {
        $path = $this->_getFullPath();
        if ($path !== "") {
            file_put_contents($path, $hexKey);
        }
    }
}
