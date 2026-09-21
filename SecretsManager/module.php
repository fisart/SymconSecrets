<?php

declare(strict_types=1);

require_once __DIR__ . '/libs/PortalSecurity.php';
require_once __DIR__ . '/libs/WebAuthn/src/WebAuthn.php';

// Version 5.4.0
class SecretsManager extends IPSModuleStrict
{

    // The name of the key file stored on the OS
    private const KEY_FILENAME = 'master.key';
    private const SYSTEM_FILENAME = 'system.vault';

    private const LOCAL_AUTH_KEY    = '__AUTH__';
    private const LOCAL_SECRETS_KEY = '__LOCAL__';

    private const PORTAL_CHALLENGE_TTL_SECONDS = 300;
    private const PORTAL_RATE_WINDOW_SECONDS = 600;
    private const PORTAL_RATE_MAX_PER_CLIENT = 10;
    private const PORTAL_RATE_MAX_GLOBAL = 100;
    private const PORTAL_RATE_MAX_ENTRIES = 256;
    private const PORTAL_CHALLENGE_BUFFER = 'PortalChallengesV2';
    private const PORTAL_CHALLENGE_MAX_ENTRIES = 192;
    private const PORTAL_ASSERTION_CHALLENGES_PER_ORIGIN = 64;
    private const PORTAL_PRIVILEGED_CHALLENGES_PER_ORIGIN = 16;
    private const PORTAL_SESSION_BUFFER = 'PortalSessionsV2';
    private const PORTAL_RATE_BUFFER = 'PortalRateLimitsV2';
    private const PORTAL_REVOCATION_BUFFER = 'PortalRevocationGenerationV2';
    private const PORTAL_REVOCATION_PENDING_BUFFER = 'PortalRevocationPendingV2';
    private const PORTAL_ENABLED_BUFFER = 'PortalEnabledLastV2';
    private const PORTAL_COOKIE_PREFIX = 'SEC_PORTAL_V2_';
    private const PORTAL_SESSION_MAX_ENTRIES = 50;
    private const PORTAL_LOCK_WAIT_MILLISECONDS = 5000;
    // Keep sync bounded without rejecting vaults that were valid before this
    // hardening release. The encrypted vault itself remains capped at 16 MiB.
    private const SYNC_MAX_REQUEST_BYTES = 18874368;
    private const PORTAL_JSON_MAX_REQUEST_BYTES = 131072;
    private const VAULT_MAX_BYTES = 16777216;

    private int $vaultLockDepth = 0;

    public function Create(): void
    {
        parent::Create();

        $this->RegisterPropertyInteger("OperationMode", 0);

        // Key Storage
        $this->RegisterPropertyString("KeyFolderPath", "");

        // Legacy setting retained so existing installations can be opened and
        // migrated without losing their configuration.
        $this->RegisterPropertyInteger("PortalSessionLifetimeHours", 72);

        // WebAuthn portal is deliberately disabled after upgrading. It can
        // only be enabled after a canonical RP ID and exact HTTPS origin have
        // been configured and legacy credentials have been cryptographically
        // migrated (or newly enrolled later, if the administrator chooses).
        $this->RegisterPropertyBoolean("PortalEnabled", false);
        $this->RegisterPropertyString("PortalOrigin", "");
        $this->RegisterPropertyString("PortalBackupOrigin", "");
        $this->RegisterPropertyInteger("PortalSessionLifetimeMinutes", 60);

        // IMPORTANT: AuthToken / HookPass werden NICHT mehr als Property gespeichert

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

        // --- LOCAL SECRETS BACKUP / RESTORE ---
        $json['actions'][] = ["type" => "Label", "caption" => "________________________________________________________________________________________________"];
        $json['actions'][] = ["type" => "Label", "caption" => "💾 LOCAL SECRETS BACKUP / RESTORE", "bold" => true];
        $json['actions'][] = ["type" => "Label", "caption" => "Exportiert und importiert nur lokale Daten dieses Systems (__AUTH__ und __LOCAL__)."];

        $json['actions'][] = [
            "type" => "Button",
            "caption" => "📤 Export Local Secrets",
            "onClick" => "\$json = SEC_ExportLocalSecrets(\$id); IPS_RequestAction(\$id, 'LOCALUI_SetExportJson', \$json);"
        ];

        $json['actions'][] = [
            "type" => "ValidationTextBox",
            "name" => "LocalSecretsExportJson",
            "caption" => "Export JSON",
            "value" => (string)$this->GetBuffer("LocalSecretsExportJson")
        ];

        $json['actions'][] = [
            "type" => "ValidationTextBox",
            "name" => "LocalSecretsImportJson",
            "caption" => "Import JSON",
            "value" => (string)$this->GetBuffer("LocalSecretsImportJson")
        ];

        $json['actions'][] = [
            "type" => "Button",
            "caption" => "📥 Import Local Secrets",
            "onClick" => "IPS_RequestAction(\$id, 'LOCALUI_ImportJson', \$LocalSecretsImportJson);"
        ];

        // --- LOCAL SECRET STORE BOOTSTRAP / RECOVERY ---
        if ($isSlave) {
            $json['actions'][] = ["type" => "Label", "caption" => "________________________________________________________________________________________________"];
            $json['actions'][] = ["type" => "Label", "caption" => "🧰 LOCAL SECRET STORE BOOTSTRAP / RECOVERY", "bold" => true];
            $json['actions'][] = ["type" => "Label", "caption" => "Use this only to initialize or repair the local Secret Store of this Slave without changing the InstanceID."];

            $json['actions'][] = [
                "type" => "Button",
                "caption" => "🔎 Check Local Secret Store",
                "onClick" => "IPS_RequestAction(\$id, 'LOCALSTORE_Check', '');"
            ];

            $json['actions'][] = [
                "type" => "ValidationTextBox",
                "name" => "BootstrapSyncToken",
                "caption" => "Bootstrap Sync Token from Master"
            ];

            $json['actions'][] = [
                "type" => "Button",
                "caption" => "🧰 Initialize / Repair Slave Secret Store",
                "onClick" => "IPS_RequestAction(\$id, 'LOCALSTORE_InitializeSlave', \$BootstrapSyncToken);"
            ];
        }

        // --- LOCAL PASSKEY DEVICES ---
        $passkeyRows = [];
        $vaultDataForPasskeys = $this->_decryptVault() ?: [];
        $authData = $vaultDataForPasskeys[self::LOCAL_AUTH_KEY] ?? [];

        if (is_array($authData)) {
            ksort($authData);
            foreach ($authData as $deviceKey => $deviceData) {
                if ($deviceKey === "__folder") {
                    continue;
                }
                if (!is_array($deviceData)) {
                    continue;
                }

                $credentialId   = (string)($deviceData['credentialId'] ?? '');
                $registeredHost = (string)($deviceData['RegisteredHost'] ?? '');
                $registeredAt   = (int)($deviceData['RegisteredAt'] ?? 0);
                $userAgent      = (string)($deviceData['UserAgent'] ?? '');

                $registeredAtText = ($registeredAt > 0) ? date('Y-m-d H:i:s', $registeredAt) : '';
                $shortCredential  = ($credentialId !== '') ? substr($credentialId, 0, 24) . (strlen($credentialId) > 24 ? "..." : "") : "(no credentialId)";
                $shortUserAgent   = ($userAgent !== '') ? substr($userAgent, 0, 40) . (strlen($userAgent) > 40 ? "..." : "") : '';

                $passkeyRows[] = [
                    "DeviceKey"      => (string)$deviceKey,
                    "CredentialId"   => $credentialId,
                    "RegisteredHost" => $registeredHost,
                    "RegisteredAt"   => $registeredAtText,
                    "UserAgent"      => $shortUserAgent,
                    "Info"           => $shortCredential
                ];
            }
        }

        $json['actions'][] = ["type" => "Label", "caption" => "________________________________________________________________________________________________"];
        $json['actions'][] = ["type" => "Label", "caption" => "🔐 LOCAL PASSKEY DEVICES", "bold" => true];
        $json['actions'][] = ["type" => "Label", "caption" => "Zeigt alle lokal registrierten Passkey-Geräte dieses Systems. Löschen entfernt genau ein Gerät aus __AUTH__."];

        $json['actions'][] = [
            "type" => "List",
            "name" => "LocalPasskeyDevicesUI",
            "rowCount" => 8,
            "columns" => [
                ["caption" => "Device Key", "name" => "DeviceKey", "width" => "200px"],
                ["caption" => "Registered Host", "name" => "RegisteredHost", "width" => "180px"],
                ["caption" => "Registered At", "name" => "RegisteredAt", "width" => "160px"],
                ["caption" => "User Agent", "name" => "UserAgent", "width" => "220px"],
                ["caption" => "Credential ID", "name" => "Info", "width" => "220px"]
            ],
            "values" => $passkeyRows
        ];

        $json['actions'][] = [
            "type" => "Button",
            "caption" => "🗑️ Delete selected local passkey",
            "onClick" => "if(isset(\$LocalPasskeyDevicesUI)) { IPS_RequestAction(\$id, 'LOCALUI_DeletePasskey', \$LocalPasskeyDevicesUI['DeviceKey']); } else { echo 'Bitte erst ein Gerät markieren!'; }"
        ];

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

        $portalEnabled = $this->ReadPropertyBoolean('PortalEnabled');
        $previousPortalEnabled = $this->GetBuffer(self::PORTAL_ENABLED_BUFFER);
        $revocationPending = $this->GetBuffer(self::PORTAL_REVOCATION_PENDING_BUFFER) === '1';
        if ($revocationPending || ($previousPortalEnabled === '1' && !$portalEnabled)) {
            if ($this->EnterPortalStateLock()) {
                try {
                    $this->RevokeAllPortalStateUnlocked();
                    $revocationPending = false;
                } finally {
                    $this->LeavePortalStateLock();
                }
            } else {
                $this->SetBuffer(self::PORTAL_REVOCATION_PENDING_BUFFER, '1');
                $revocationPending = true;
            }
        }
        $this->SetBuffer(self::PORTAL_ENABLED_BUFFER, $portalEnabled ? '1' : '0');

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
            $this->NormalizeStoredCredentialEncodings();
        }

        if ($portalEnabled && $revocationPending) {
            $errorMessage = 'Portal remains blocked because session revocation is pending. Apply the configuration again.';
            $this->SetStatus(202);
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
        if (!$this->RequirePortalReady()) {
            return;
        }
        $profileError = '';
        $profile = $this->GetCurrentPortalProfile($profileError);
        if ($profile === null) {
            $this->SendPortalError(503, $profileError);
            return;
        }
        if (!$this->CheckPortalRateLimit('challenge-issuance', true, 30, 300)) {
            $this->SendPortalError(429, 'Too many login page requests. Please try again later.');
            return;
        }
        $credentials = $this->GetVerifiedPortalCredentials($profile['rpId'], $profile['origin']);
        if (count($credentials) === 0) {
            $this->SendPortalError(409, 'No verified passkeys are available for this origin. Use verified migration in the admin dashboard.');
            return;
        }

        $challenge = random_bytes(32);
        $returnUrl = SecretsPortalSecurity::sanitizeReturnUrl((string)($_GET['return'] ?? '/'));
        $rpId = $profile['rpId'];
        $origin = $profile['origin'];

        $allowedCredentialIds = array_keys($credentials);
        $sid = $this->StorePortalChallenge('assertion', [
            'challenge'            => SecretsPortalSecurity::base64UrlEncode($challenge),
            'return'               => $returnUrl,
            'rpId'                 => $rpId,
            'origin'               => $origin,
            'allowedCredentialIds' => $allowedCredentialIds
        ]);
        if ($sid === null) {
            $this->SendPortalError(503, 'Authentication state is busy. Please try again.');
            return;
        }

        $allowCredentials = [];
        foreach ($allowedCredentialIds as $credentialId) {
            $allowCredentials[] = [
                'type' => 'public-key',
                'id'   => $credentialId
            ];
        }

        $configJson = json_encode([
            'sid'              => $sid,
            'challenge'        => SecretsPortalSecurity::base64UrlEncode($challenge),
            'rpId'             => $rpId,
            'allowCredentials' => $allowCredentials
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

        $nonce = SecretsPortalSecurity::base64UrlEncode(random_bytes(18));
        $this->SendPortalSecurityHeaders($nonce);

        echo '<html><head><title>Vault Auth</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f4f7f6;}';
        echo '.box{background:#fff;padding:40px;border-radius:15px;box-shadow:0 10px 25px rgba(0,0,0,0.1);text-align:center;}';
        echo 'button{background:#4a90e2;color:white;border:none;padding:15px 30px;border-radius:8px;font-size:18px;cursor:pointer;transition:background 0.3s;}';
        echo 'button:hover{background:#357abd;}</style></head><body>';
        echo '<div class="box"><h2>🔐 Biometrischer Login</h2><p>Bitte Sensor berühren.</p>';
        echo '<button id="loginButton" type="button">Anmelden</button><p id="status" role="status"></p></div>';
        echo '<script nonce="' . htmlspecialchars($nonce, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">';
        echo 'const config=' . $configJson . ';';
        echo 'const fromB64u=v=>{v=v.replace(/-/g,"+").replace(/_/g,"/");while(v.length%4)v+="=";const b=atob(v);return Uint8Array.from(b,c=>c.charCodeAt(0));};';
        echo 'const toB64u=v=>{let s="";new Uint8Array(v).forEach(b=>s+=String.fromCharCode(b));return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");};';
        echo 'async function login(){const status=document.getElementById("status");status.textContent="";try{';
        echo 'const publicKey={challenge:fromB64u(config.challenge),rpId:config.rpId,timeout:60000,userVerification:"required",allowCredentials:config.allowCredentials.map(i=>({type:i.type,id:fromB64u(i.id)}))};';
        echo 'const cred=await navigator.credentials.get({publicKey});';
        echo 'const payload={sid:config.sid,type:cred.type,rawId:toB64u(cred.rawId),response:{clientDataJSON:toB64u(cred.response.clientDataJSON),authenticatorData:toB64u(cred.response.authenticatorData),signature:toB64u(cred.response.signature),userHandle:cred.response.userHandle===null?null:toB64u(cred.response.userHandle)}};';
        echo 'const res=await fetch(location.pathname+"?portal=1",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});';
        echo 'const body=await res.json().catch(()=>({error:"Authentication failed."}));if(!res.ok||!body.ok)throw new Error(body.error||"Authentication failed.");location.assign(body.redirect||"/");';
        echo '}catch(e){status.textContent="Authentifizierung fehlgeschlagen: "+e.message;}}';
        echo 'document.getElementById("loginButton").addEventListener("click",login);';
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

    public function RevokePortalSessions(): void
    {
        if (!$this->EnterPortalStateLock()) {
            $this->SetBuffer(self::PORTAL_REVOCATION_PENDING_BUFFER, '1');
            echo "❌ Portal security state is busy. Try again.";
            return;
        }
        try {
            $this->RevokeAllPortalStateUnlocked();
        } finally {
            $this->LeavePortalStateLock();
        }
        $this->ClearPortalSessionCookie();
        $this->LogMessage('All portal sessions and pending WebAuthn ceremonies were revoked.', KL_WARNING);
        echo "✅ All portal sessions and pending passkey operations were revoked.";
    }

    public function RemoveAllPasskeys(): void
    {
        if (!$this->EnterPortalStateLock()) {
            echo "❌ Portal security state is busy. No passkeys were changed.";
            return;
        }
        if (!$this->EnterVaultLock()) {
            $this->LeavePortalStateLock();
            echo "❌ The vault is busy. No passkeys were changed.";
            return;
        }

        $removed = 0;
        try {
            $vaultRevision = null;
            $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
            if (!is_array($vaultData)) {
                echo "❌ The vault could not be decrypted. No passkeys were changed.";
                return;
            }

            if (isset($vaultData[self::LOCAL_AUTH_KEY]) && is_array($vaultData[self::LOCAL_AUTH_KEY])) {
                foreach ($vaultData[self::LOCAL_AUTH_KEY] as $key => $value) {
                    if ($key !== '__folder' && is_array($value)) {
                        $removed++;
                    }
                }
            }
            $vaultData[self::LOCAL_AUTH_KEY] = [];

            if (!$this->_encryptAndSave($vaultData, $vaultRevision)) {
                echo "❌ Passkeys could not be removed because the encrypted vault save failed.";
                return;
            }

            $this->RevokeAllPortalStateUnlocked();
            $this->SetBuffer(self::PORTAL_RATE_BUFFER, '{}');
        } finally {
            $this->LeaveVaultLock();
            $this->LeavePortalStateLock();
        }
        $this->ClearPortalSessionCookie();
        $this->LogMessage('All WebAuthn credentials and portal sessions were removed. Count=' . $removed, KL_WARNING);
        echo "✅ Removed $removed passkey record(s) and revoked all portal sessions.";
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

    public function SetRecordFields(string $path, array $fields, string $scope): bool
    {
        if ($this->GetStatus() !== 102) {
            $this->LogMessage("SetRecordFields aborted: instance is not active.", KL_ERROR);
            return false;
        }

        $normalizedScope = $this->NormalizeWriteScope($scope);
        if ($normalizedScope === null) {
            $this->LogMessage("SetRecordFields aborted: invalid scope '" . $scope . "'.", KL_ERROR);
            return false;
        }

        if (!$this->IsWriteAllowedForScope($normalizedScope)) {
            $this->LogMessage("SetRecordFields aborted: scope '" . $normalizedScope . "' is not allowed in the current operation mode.", KL_ERROR);
            return false;
        }

        $normalizedPath = $this->NormalizeVaultPath($path);
        if ($normalizedPath === null) {
            $this->LogMessage("SetRecordFields aborted: invalid path '" . $path . "'.", KL_ERROR);
            return false;
        }

        $normalizedFields = $this->NormalizeRecordFields($fields);
        if ($normalizedFields === null) {
            $this->LogMessage("SetRecordFields aborted: invalid fields for path '" . $normalizedPath . "'.", KL_ERROR);
            return false;
        }

        $vaultRevision = null;
        $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
        if ($vaultData === false) {
            if ($this->GetValue("Vault") === "") {
                $vaultData = [];
            } else {
                $this->LogMessage("SetRecordFields aborted: vault decryption failed.", KL_ERROR);
                return false;
            }
        }

        if (!$this->WriteRecordFieldsToVault($vaultData, $normalizedPath, $normalizedFields, $normalizedScope)) {
            $this->LogMessage("SetRecordFields aborted: could not write fields to vault path '" . $normalizedPath . "'.", KL_ERROR);
            return false;
        }

        if (!$this->_encryptAndSave($vaultData, $vaultRevision)) {
            $this->LogMessage("SetRecordFields aborted: encrypted save failed for path '" . $normalizedPath . "'.", KL_ERROR);
            return false;
        }

        if ($normalizedScope === 'global' && $this->ReadPropertyInteger("OperationMode") === 1) {
            $this->SyncSlaves();
        }

        $this->LogMessage("SetRecordFields successful for scope '" . $normalizedScope . "' and path '" . $normalizedPath . "'.", KL_MESSAGE);
        return true;
    }

    public function ExportLocalSecrets(): string
    {
        if ($this->GetStatus() !== 102) {
            $this->LogMessage("ExportLocalSecrets aborted: instance is not active.", KL_ERROR);
            return "";
        }

        $vaultData = $this->_decryptVault();
        if ($vaultData === false) {
            if ($this->GetValue("Vault") === "") {
                $vaultData = [];
            } else {
                $this->LogMessage("ExportLocalSecrets aborted: vault decryption failed.", KL_ERROR);
                return "";
            }
        }

        $export = $this->BuildLocalSecretsExport($vaultData);
        $json = json_encode($export, JSON_PRETTY_PRINT);

        if ($json === false) {
            $this->LogMessage("ExportLocalSecrets aborted: JSON encoding failed.", KL_ERROR);
            return "";
        }

        return $json;
    }

    public function ImportLocalSecrets(string $json): bool
    {
        if ($this->GetStatus() !== 102) {
            $this->LogMessage("ImportLocalSecrets aborted: instance is not active.", KL_ERROR);
            return false;
        }

        $importData = json_decode($json, true);
        if (!is_array($importData)) {
            $this->LogMessage("ImportLocalSecrets aborted: invalid JSON input.", KL_ERROR);
            return false;
        }

        $vaultRevision = null;
        $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
        if ($vaultData === false) {
            if ($this->GetValue("Vault") === "") {
                $vaultData = [];
            } else {
                $this->LogMessage("ImportLocalSecrets aborted: vault decryption failed.", KL_ERROR);
                return false;
            }
        }

        if (!$this->MergeImportedLocalSecrets($vaultData, $importData)) {
            $this->LogMessage("ImportLocalSecrets aborted: merge failed.", KL_ERROR);
            return false;
        }

        if (!$this->_encryptAndSave($vaultData, $vaultRevision)) {
            $this->LogMessage("ImportLocalSecrets aborted: encrypted save failed.", KL_ERROR);
            return false;
        }

        $this->LogMessage("ImportLocalSecrets successful.", KL_MESSAGE);
        return true;
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

        switch ($Ident) {
            case 'LOCALUI_SetExportJson':
                $this->SetBuffer("LocalSecretsExportJson", (string)$Value);
                $this->ReloadForm();
                return;

            case 'LOCALUI_ImportJson':
                $this->SetBuffer("LocalSecretsImportJson", (string)$Value);
                if ($this->ImportLocalSecrets((string)$Value)) {
                    echo "✅ Local secrets imported successfully.";
                } else {
                    echo "❌ Import of local secrets failed.";
                }
                $this->ReloadForm();
                return;

            case 'LOCALUI_DeletePasskey':
                if ($this->DeleteLocalPasskey((string)$Value)) {
                    echo "✅ Local passkey deleted successfully.";
                } else {
                    echo "❌ Deletion of local passkey failed.";
                }
                $this->ReloadForm();
                return;

            case 'LOCALSTORE_Check':
                echo $this->CheckLocalSecretStore();
                $this->ReloadForm();
                return;

            case 'LOCALSTORE_InitializeSlave':
                $this->InitializeSlaveSecretStore((string)$Value);
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

        $vaultRevision = null;
        $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
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
            if ($this->_encryptAndSave($vaultData, $vaultRevision)) {
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
        $vaultRevision = null;
        $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
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
            if ($this->_encryptAndSave($vaultData, $vaultRevision)) {
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
        $vaultRevision = null;
        $vaultData = $this->_decryptVaultWithRevision($vaultRevision) ?: [];

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

        if ($this->_encryptAndSave($vaultData, $vaultRevision)) {
            echo ($ident === "") ? "✅ Ordner-Felder aktualisiert!" : "✅ Eintrag '$ident' aktualisiert!";
            if ($this->ReadPropertyInteger("OperationMode") === 1) $this->SyncSlaves();
        }
    }

    private function NormalizeWriteScope(string $scope): ?string
    {
        $scope = strtolower(trim($scope));

        if ($scope === 'local' || $scope === 'global') {
            return $scope;
        }

        return null;
    }



    private function IsWriteAllowedForScope(string $scope): bool
    {
        $mode = $this->ReadPropertyInteger("OperationMode");

        if ($scope === 'global') {
            return ($mode === 1);
        }

        if ($scope === 'local') {
            return in_array($mode, [0, 1, 2], true);
        }

        return false;
    }

    private function WriteRecordFieldsToVault(array &$vaultData, string $path, array $fields, string $scope): bool
    {
        $parts = array_filter(explode('/', $path), 'strlen');
        if (count($parts) === 0) {
            return false;
        }

        if ($scope === 'local') {
            if (!isset($vaultData[self::LOCAL_SECRETS_KEY]) || !is_array($vaultData[self::LOCAL_SECRETS_KEY])) {
                $vaultData[self::LOCAL_SECRETS_KEY] = [];
            }
            $temp = &$vaultData[self::LOCAL_SECRETS_KEY];
        } else {
            $temp = &$vaultData;
        }

        foreach ($parts as $part) {
            if (!isset($temp[$part]) || !is_array($temp[$part])) {
                $temp[$part] = [];
            }
            $temp = &$temp[$part];
        }

        foreach ($temp as $key => $value) {
            if ($key !== "__folder" && !is_array($value)) {
                unset($temp[$key]);
            }
        }

        foreach ($fields as $key => $value) {
            $temp[$key] = $value;
        }

        return true;
    }

    private function BuildLocalSecretsExport(array $vaultData): array
    {
        $export = [];

        if (isset($vaultData[self::LOCAL_AUTH_KEY]) && is_array($vaultData[self::LOCAL_AUTH_KEY])) {
            $export[self::LOCAL_AUTH_KEY] = $vaultData[self::LOCAL_AUTH_KEY];
        }

        if (isset($vaultData[self::LOCAL_SECRETS_KEY]) && is_array($vaultData[self::LOCAL_SECRETS_KEY])) {
            $export[self::LOCAL_SECRETS_KEY] = $vaultData[self::LOCAL_SECRETS_KEY];
        }

        return $export;
    }

    private function MergeImportedLocalSecrets(array &$vaultData, array $importData): bool
    {
        if (isset($importData[self::LOCAL_AUTH_KEY])) {
            if (!is_array($importData[self::LOCAL_AUTH_KEY])) {
                return false;
            }
            $vaultData[self::LOCAL_AUTH_KEY] = $importData[self::LOCAL_AUTH_KEY];
        }

        if (isset($importData[self::LOCAL_SECRETS_KEY])) {
            if (!is_array($importData[self::LOCAL_SECRETS_KEY])) {
                return false;
            }
            $vaultData[self::LOCAL_SECRETS_KEY] = $importData[self::LOCAL_SECRETS_KEY];
        }

        return true;
    }

    private function PreserveLocalVaultAreas(array $currentVault, array &$incomingVault): void
    {
        if (isset($currentVault[self::LOCAL_AUTH_KEY]) && is_array($currentVault[self::LOCAL_AUTH_KEY])) {
            $incomingVault[self::LOCAL_AUTH_KEY] = array_merge(
                $incomingVault[self::LOCAL_AUTH_KEY] ?? [],
                $currentVault[self::LOCAL_AUTH_KEY]
            );
        }

        if (isset($currentVault[self::LOCAL_SECRETS_KEY]) && is_array($currentVault[self::LOCAL_SECRETS_KEY])) {
            $incomingVault[self::LOCAL_SECRETS_KEY] = $currentVault[self::LOCAL_SECRETS_KEY];
        }
    }

    private function NormalizeVaultPath(string $path): ?string
    {
        $path = trim($path);

        if ($path === '') {
            return null;
        }

        if ($path[0] === '/' || substr($path, -1) === '/') {
            return null;
        }

        $parts = explode('/', $path);
        $normalized = [];

        foreach ($parts as $part) {
            $part = trim($part);

            if ($part === '' || strpos($part, '/') !== false) {
                return null;
            }

            $normalized[] = $part;
        }

        return implode('/', $normalized);
    }

    private function NormalizeRecordFields(array $fields): ?array
    {
        $normalized = [];

        foreach ($fields as $key => $value) {
            if (!is_string($key) && !is_int($key)) {
                return null;
            }

            $fieldName = trim((string)$key);
            if ($fieldName === '') {
                return null;
            }

            if ($fieldName === '__folder' || strpos($fieldName, '__') === 0) {
                return null;
            }

            if (is_array($value) || is_object($value)) {
                return null;
            }

            $normalized[$fieldName] = (string)$value;
        }

        return $normalized;
    }

    private function DeleteLocalPasskey(string $deviceKey): bool
    {
        $deviceKey = trim($deviceKey);

        if ($deviceKey === '') {
            $this->LogMessage("DeleteLocalPasskey aborted: empty device key.", KL_ERROR);
            return false;
        }

        if ($deviceKey === '__folder') {
            $this->LogMessage("DeleteLocalPasskey aborted: invalid device key '__folder'.", KL_ERROR);
            return false;
        }

        if (!$this->EnterPortalStateLock()) {
            $this->LogMessage('DeleteLocalPasskey aborted: portal security state is busy.', KL_ERROR);
            return false;
        }
        if (!$this->EnterVaultLock()) {
            $this->LeavePortalStateLock();
            $this->LogMessage('DeleteLocalPasskey aborted: vault is busy.', KL_ERROR);
            return false;
        }

        try {
            $vaultRevision = null;
            $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
            if ($vaultData === false) {
                if ($this->GetValue("Vault") === "") {
                    $vaultData = [];
                } else {
                    $this->LogMessage("DeleteLocalPasskey aborted: vault decryption failed.", KL_ERROR);
                    return false;
                }
            }

            if (
                !isset($vaultData[self::LOCAL_AUTH_KEY]) ||
                !is_array($vaultData[self::LOCAL_AUTH_KEY])
            ) {
                $this->LogMessage("DeleteLocalPasskey aborted: no local passkey container found.", KL_ERROR);
                return false;
            }

            if (!array_key_exists($deviceKey, $vaultData[self::LOCAL_AUTH_KEY])) {
                $this->LogMessage("DeleteLocalPasskey aborted: device key '" . $deviceKey . "' not found.", KL_ERROR);
                return false;
            }

            $deleted = $vaultData[self::LOCAL_AUTH_KEY][$deviceKey];
            $deletedCanonicalId = '';
            if (is_array($deleted)) {
                $deletedCanonicalId = (string)($deleted['credentialIdV2'] ?? '');
                if ($deletedCanonicalId === '') {
                    $decoded = $this->DecodeLegacyStoredBinary((string)($deleted['credentialId'] ?? ''));
                    $deletedCanonicalId = $decoded === null ? '' : SecretsPortalSecurity::base64UrlEncode($decoded);
                }
            }
            unset($vaultData[self::LOCAL_AUTH_KEY][$deviceKey]);

            $remainingKeys = array_filter(array_keys($vaultData[self::LOCAL_AUTH_KEY]), static function ($key): bool {
                return $key !== '__folder';
            });
            if (count($remainingKeys) === 0) {
                unset($vaultData[self::LOCAL_AUTH_KEY]);
            }

            if (!$this->_encryptAndSave($vaultData, $vaultRevision)) {
                $this->LogMessage("DeleteLocalPasskey aborted: encrypted save failed for device key '" . $deviceKey . "'.", KL_ERROR);
                return false;
            }

            $sessions = json_decode($this->GetBuffer(self::PORTAL_SESSION_BUFFER), true);
            if (!is_array($sessions)) {
                $sessions = [];
            }
            $revokedSessionHashes = [];
            foreach ($sessions as $sessionHash => $session) {
                if (is_array($session) && hash_equals((string)($session['credentialDeviceKey'] ?? ''), $deviceKey)) {
                    $revokedSessionHashes[] = (string)$sessionHash;
                    unset($sessions[$sessionHash]);
                }
            }

            $challenges = json_decode($this->GetBuffer(self::PORTAL_CHALLENGE_BUFFER), true);
            if (!is_array($challenges)) {
                $challenges = [];
            }
            foreach ($challenges as $sid => $challenge) {
                $allowed = is_array($challenge) ? ($challenge['allowedCredentialIds'] ?? []) : [];
                $sessionHash = is_array($challenge) ? (string)($challenge['authorizationSessionHash'] ?? '') : '';
                if (
                    ($deletedCanonicalId !== '' && is_array($allowed) && in_array($deletedCanonicalId, $allowed, true)) ||
                    ($sessionHash !== '' && in_array($sessionHash, $revokedSessionHashes, true))
                ) {
                    unset($challenges[$sid]);
                }
            }
            $this->SetBuffer(self::PORTAL_SESSION_BUFFER, (string)json_encode($sessions));
            $this->SetBuffer(self::PORTAL_CHALLENGE_BUFFER, (string)json_encode($challenges));

            $this->LogMessage("DeleteLocalPasskey successful for device key '" . $deviceKey . "'.", KL_MESSAGE);
            return true;
        } finally {
            $this->LeaveVaultLock();
            $this->LeavePortalStateLock();
        }
    }


    public function CheckLocalSecretStore(): string
    {
        $mode = $this->ReadPropertyInteger("OperationMode");
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $keyPath = $this->_getFullPath();
        $systemPath = $this->getSystemPath();

        $lines = [];
        $lines[] = "LOCAL SECRET STORE DIAGNOSTIC";
        $lines[] = "";
        $lines[] = "System Role: " . (($mode === 0) ? "Slave (Receiver)" : (($mode === 1) ? "Master (Sender)" : "Standalone (Local Vault)"));
        $lines[] = "KeyFolderPath: " . (($folder !== "") ? $folder : "(not configured)");
        $lines[] = "";

        if ($folder === "") {
            $lines[] = "❌ KeyFolderPath is not configured.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Enter the directory path where this Slave should store master.key and system.vault.";
            $lines[] = "2. Click Apply Changes.";
            $lines[] = "3. Run this diagnostic again.";
            return implode("\n", $lines);
        }

        if (!is_dir($folder)) {
            $lines[] = "❌ KeyFolderPath does not exist.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Create the directory on the Symcon host.";
            $lines[] = "2. Make sure the Symcon process can read and write this directory.";
            $lines[] = "3. Click Apply Changes.";
            $lines[] = "4. Run this diagnostic again.";
            return implode("\n", $lines);
        }

        $lines[] = "✅ KeyFolderPath exists.";

        if (!is_writable($folder)) {
            $lines[] = "❌ KeyFolderPath is not writable by the Symcon process.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Fix owner/group/permissions of the configured KeyFolderPath.";
            $lines[] = "2. Make sure Symcon can create and update files in this directory.";
            $lines[] = "3. Run this diagnostic again.";
            return implode("\n", $lines);
        }

        $lines[] = "✅ KeyFolderPath is writable.";

        if ($keyPath === "") {
            $lines[] = "❌ master.key path cannot be calculated.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Check KeyFolderPath.";
            $lines[] = "2. Click Apply Changes.";
            $lines[] = "3. Run this diagnostic again.";
            return implode("\n", $lines);
        }

        if (!file_exists($keyPath)) {
            $lines[] = "❌ master.key is missing.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Copy the correct master.key from the Master or from the last working backup into the configured KeyFolderPath.";
            $lines[] = "2. Click Apply Changes.";
            $lines[] = "3. Run this diagnostic again.";
            $lines[] = "4. Then enter the Sync Token from the Master and run Initialize / Repair Slave Secret Store.";
            $lines[] = "5. After successful initialization, start the sync from the Master.";
            return implode("\n", $lines);
        }

        if (!is_readable($keyPath)) {
            $lines[] = "❌ master.key exists but cannot be read by Symcon.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Fix file permissions for master.key.";
            $lines[] = "2. Make sure the Symcon process can read it.";
            $lines[] = "3. Run this diagnostic again.";
            return implode("\n", $lines);
        }

        $keyHex = trim((string)@file_get_contents($keyPath));
        if (!preg_match('/^[0-9a-fA-F]{32}$/', $keyHex)) {
            $lines[] = "❌ master.key exists but does not contain a valid AES-128 key.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Restore the correct master.key from the last working backup of this Slave.";
            $lines[] = "2. If no backup exists, manually move the broken master.key and system.vault out of the KeyFolderPath.";
            $lines[] = "3. Then run Initialize / Repair Slave Secret Store with the Sync Token from the Master.";
            $lines[] = "4. After that, start the sync from the Master and re-register local passkeys / re-import local secrets if needed.";
            return implode("\n", $lines);
        }

        $lines[] = "✅ master.key exists and has a valid format.";

        if ($systemPath === "") {
            $lines[] = "❌ system.vault path cannot be calculated.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Check KeyFolderPath.";
            $lines[] = "2. Click Apply Changes.";
            $lines[] = "3. Run this diagnostic again.";
            return implode("\n", $lines);
        }

        if (!file_exists($systemPath)) {
            $lines[] = "⚠️ system.vault is missing.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Enter the Sync Token from the Master into Bootstrap Sync Token.";
            $lines[] = "2. Run Initialize / Repair Slave Secret Store.";
            $lines[] = "3. After successful initialization, start the sync from the Master.";
            return implode("\n", $lines);
        }

        $error = "";
        $systemSecrets = $this->LoadExistingSystemSecretsForBootstrap($keyHex, $error);
        if ($systemSecrets === null) {
            $lines[] = "❌ system.vault exists but cannot be decrypted with the current master.key.";
            $lines[] = "Details: " . $error;
            $lines[] = "";
            $lines[] = "No files were changed.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online, choose one option:";
            $lines[] = "";
            $lines[] = "Option 1 - Restore:";
            $lines[] = "Copy the matching master.key and system.vault from the last working backup of this Slave into the configured KeyFolderPath.";
            $lines[] = "";
            $lines[] = "Option 2 - Repair file permissions:";
            $lines[] = "Check that the Symcon process can read master.key and system.vault and can write to the KeyFolderPath.";
            $lines[] = "";
            $lines[] = "Option 3 - Reinitialize as a new Slave:";
            $lines[] = "If no backup exists, manually rename or move the broken master.key and system.vault files out of the KeyFolderPath, then run Initialize / Repair Slave Secret Store with the Sync Token from the Master.";
            $lines[] = "After that, start the sync from the Master and re-register local passkeys / re-import local secrets if needed.";
            return implode("\n", $lines);
        }

        $lines[] = "✅ system.vault exists and can be decrypted.";

        if ((string)($systemSecrets['authToken'] ?? '') === "") {
            $lines[] = "⚠️ Sync Token is not stored in system.vault.";
            $lines[] = "";
            $lines[] = "To bring this Slave back online:";
            $lines[] = "1. Open the SecretsManager instance on the Master.";
            $lines[] = "2. Click Show/Copy Token.";
            $lines[] = "3. Paste the token into Bootstrap Sync Token on this Slave.";
            $lines[] = "4. Run Initialize / Repair Slave Secret Store.";
            $lines[] = "5. After successful initialization, start the sync from the Master.";
            return implode("\n", $lines);
        }

        $lines[] = "✅ Sync Token is stored locally and readable.";
        $lines[] = "";
        $lines[] = "Result: This Slave local Secret Store is ready for Master sync.";

        return implode("\n", $lines);
    }

    public function InitializeSlaveSecretStore(string $syncToken): bool
    {
        $syncToken = trim($syncToken);
        $mode = $this->ReadPropertyInteger("OperationMode");
        $folder = $this->ReadPropertyString("KeyFolderPath");
        $systemPath = $this->getSystemPath();

        if ($mode !== 0) {
            echo "❌ This action is only available in Slave mode.\n\n";
            echo "This instance is currently not configured as a Slave.\n";
            echo "No files were changed.\n\n";
            echo "To initialize this system as a Slave:\n";
            echo "1. Set System Role to Slave (Receiver).\n";
            echo "2. Click Apply Changes.\n";
            echo "3. Enter the Sync Token from the Master into Bootstrap Sync Token.\n";
            echo "4. Run Initialize / Repair Slave Secret Store again.\n";
            echo "5. After successful initialization, start the sync from the Master.\n\n";
            echo "If this instance is intended to be Master or Standalone, do not use this Slave initialization function.";
            $this->LogMessage("InitializeSlaveSecretStore aborted: instance is not in Slave mode.", KL_ERROR);
            return false;
        }

        if ($syncToken === "") {
            echo "❌ No Sync Token entered.\n\n";
            echo "The Slave cannot be initialized because it needs the same Sync Token that is stored on the Master.\n";
            echo "No files were changed.\n\n";
            echo "To bring this Slave back online:\n";
            echo "1. Open the SecretsManager instance on the Master.\n";
            echo "2. Click Show/Copy Token.\n";
            echo "3. Copy the token.\n";
            echo "4. Paste it into Bootstrap Sync Token on this Slave.\n";
            echo "5. Run Initialize / Repair Slave Secret Store again.\n";
            echo "6. After successful initialization, start the sync from the Master.\n\n";
            echo "If the Master token is unknown, generate and save a new token on the Master first. Then use the same new token to initialize every Slave.";
            $this->LogMessage("InitializeSlaveSecretStore aborted: empty Sync Token.", KL_ERROR);
            return false;
        }

        if ($folder === "" || !is_dir($folder) || !is_writable($folder)) {
            echo "❌ KeyFolderPath is not ready.\n\n";
            echo "The Slave cannot create or update its local Secret Store.\n";
            echo "No files were changed.\n\n";
            echo "To bring this Slave back online:\n";
            echo "1. Enter a valid KeyFolderPath.\n";
            echo "2. Make sure the directory exists on the Symcon host.\n";
            echo "3. Make sure the Symcon process can write to this directory.\n";
            echo "4. Click Apply Changes.\n";
            echo "5. Run Initialize / Repair Slave Secret Store again.";
            $this->LogMessage("InitializeSlaveSecretStore aborted: KeyFolderPath is missing, invalid, or not writable.", KL_ERROR);
            return false;
        }

        $error = "";
        $keyHex = $this->ReadExistingLocalKeyForBootstrap($error);
        if ($keyHex === null) {
            echo "❌ Local master.key is missing or invalid.\n\n";
            echo $error . "\n";
            echo "No files were changed.\n\n";
            echo "To bring this Slave back online:\n";
            echo "1. Copy the correct master.key from the Master or from the last working backup into the configured KeyFolderPath.\n";
            echo "2. Click Apply Changes.\n";
            echo "3. Run Initialize / Repair Slave Secret Store again with the Sync Token from the Master.\n";
            echo "4. After successful initialization, start the sync from the Master.\n";
            echo "5. If this was a replacement system, re-register local passkeys or import local secrets if needed.";
            $this->LogMessage("InitializeSlaveSecretStore aborted: local key missing or invalid. " . $error, KL_ERROR);
            return false;
        }

        if ($systemPath === "") {
            echo "❌ system.vault path cannot be calculated.\n\n";
            echo "No files were changed.\n\n";
            echo "To bring this Slave back online:\n";
            echo "1. Check KeyFolderPath.\n";
            echo "2. Click Apply Changes.\n";
            echo "3. Run Initialize / Repair Slave Secret Store again.";
            $this->LogMessage("InitializeSlaveSecretStore aborted: system.vault path cannot be calculated.", KL_ERROR);
            return false;
        }

        if (file_exists($systemPath)) {
            $systemSecrets = $this->LoadExistingSystemSecretsForBootstrap($keyHex, $error);
            if ($systemSecrets === null) {
                echo "❌ Slave local store cannot be read.\n\n";
                echo "The file system.vault exists, but it cannot be decrypted with the current master.key.\n";
                echo "Details: " . $error . "\n";
                echo "No files were changed.\n\n";
                echo "To bring this Slave back online, do one of the following:\n\n";
                echo "Option 1 - Restore:\n";
                echo "Copy the matching master.key and system.vault from the last working backup of this Slave into the configured KeyFolderPath.\n\n";
                echo "Option 2 - Repair file permissions:\n";
                echo "Check that the Symcon process can read master.key and system.vault and can write to the KeyFolderPath.\n\n";
                echo "Option 3 - Reinitialize as a new Slave:\n";
                echo "If no Slave backup exists, copy the correct master.key from the Master, manually rename or move the broken system.vault file out of the KeyFolderPath, then run this initialization again with the Sync Token from the Master.\n";
                echo "After that, run a Master sync and re-register local passkeys / re-import local secrets if needed.";
                $this->LogMessage("InitializeSlaveSecretStore aborted: existing system.vault cannot be decrypted. " . $error, KL_ERROR);
                return false;
            }
        } else {
            $systemSecrets = [];
        }

        $systemSecrets['authToken'] = $syncToken;

        if (!$this->saveSystemSecretsUsingKeyHex($systemSecrets, $keyHex)) {
            echo "❌ Failed to write system.vault.\n\n";
            echo "No sync was performed.\n\n";
            echo "To bring this Slave back online:\n";
            echo "1. Check that the KeyFolderPath is writable by the Symcon process.\n";
            echo "2. Check free disk space.\n";
            echo "3. Run Initialize / Repair Slave Secret Store again.";
            $this->LogMessage("InitializeSlaveSecretStore aborted: saveSystemSecretsUsingKeyHex failed.", KL_ERROR);
            return false;
        }

        $this->LogMessage("InitializeSlaveSecretStore successful: local authToken stored and Slave is ready for Master sync.", KL_MESSAGE);

        echo "✅ Slave local Secret Store initialized / repaired successfully.\n\n";
        echo "What was done:\n";
        echo "- The existing local master.key was used.\n";
        echo "- The Sync Token was stored encrypted in system.vault.\n";
        echo "- No global Vault data, passkeys, or __LOCAL__ secrets were changed.\n\n";
        echo "Next steps to bring this Slave fully online:\n";
        echo "1. Open the SecretsManager instance on the Master.\n";
        echo "2. Start Manually Sync to Slaves.\n";
        echo "3. Check that this Slave reports Sync OK on the Master.\n";
        echo "4. If this was a replacement system, re-register local passkeys or import local secrets if needed.";

        return true;
    }

    private function ReadExistingLocalKeyForBootstrap(string &$error): ?string
    {
        $keyPath = $this->_getFullPath();
        if ($keyPath === "") {
            $error = "The master.key path cannot be calculated because KeyFolderPath is not configured.";
            return null;
        }

        if (!file_exists($keyPath)) {
            $error = "master.key is missing. This module version uses the same master.key for the synced Vault and the local system.vault, so the correct key must be restored or copied before initialization.";
            return null;
        }

        if (!is_readable($keyPath)) {
            $error = "master.key exists but cannot be read by the Symcon process.";
            return null;
        }

        $keyHex = trim((string)@file_get_contents($keyPath));
        if (!preg_match('/^[0-9a-fA-F]{32}$/', $keyHex)) {
            $error = "master.key exists but does not contain a valid AES-128 key.";
            return null;
        }

        return strtolower($keyHex);
    }

    private function LoadExistingSystemSecretsForBootstrap(string $keyHex, string &$error): ?array
    {
        $path = $this->getSystemPath();
        if ($path === "") {
            $error = "The system.vault path cannot be calculated because KeyFolderPath is not configured.";
            return null;
        }

        if (!file_exists($path)) {
            return [];
        }

        if (!is_readable($path)) {
            $error = "system.vault exists but cannot be read by the Symcon process.";
            return null;
        }

        $json = @file_get_contents($path);
        if ($json === false || trim($json) === "") {
            $error = "system.vault exists but is empty or cannot be read.";
            return null;
        }

        $meta = json_decode($json, true);
        if (!is_array($meta) || !isset($meta['data'], $meta['iv'], $meta['tag'])) {
            $error = "system.vault does not contain a valid encrypted vault structure.";
            return null;
        }

        $cipher = $meta['cipher'] ?? "aes-128-gcm";
        $keyBin = hex2bin($keyHex);
        $ivBin = hex2bin((string)$meta['iv']);
        $tagBin = hex2bin((string)$meta['tag']);

        if ($keyBin === false || $ivBin === false || $tagBin === false) {
            $error = "system.vault contains invalid hex encoding for key, iv, or tag.";
            return null;
        }

        $plain = openssl_decrypt(
            (string)$meta['data'],
            $cipher,
            $keyBin,
            0,
            $ivBin,
            $tagBin
        );

        if ($plain === false) {
            $error = "system.vault cannot be decrypted with the current master.key.";
            return null;
        }

        $arr = json_decode($plain, true);
        if (!is_array($arr)) {
            $error = "system.vault was decrypted, but the plaintext is not valid JSON data.";
            return null;
        }

        return $arr;
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

        $vaultRevision = null;
        $vaultData = $this->_decryptVaultWithRevision($vaultRevision) ?: [];
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
        if ($this->_encryptAndSave($vaultData, $vaultRevision)) {
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
        $vaultRevision = null;
        $vaultData = $this->_decryptVaultWithRevision($vaultRevision) ?: [];
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

        if ($this->_encryptAndSave($vaultData, $vaultRevision)) {
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
        if (!$this->RequirePortalReady(false)) {
            return;
        }
        $profileError = '';
        $profile = $this->GetCurrentPortalProfile($profileError);
        if ($profile === null) {
            $this->SendPortalError(503, $profileError);
            return;
        }

        $vault = $this->_decryptVault();
        if (!is_array($vault)) {
            $this->SendPortalError(500, 'The vault could not be decrypted.');
            return;
        }

        $origin = $profile['origin'];
        $localUrl = $origin . '/hook/secrets_' . $this->InstanceID . '?register=1';
        $migrationUrl = $origin . '/hook/secrets_' . $this->InstanceID . '?migrate=1';
        $credentialStatus = $this->GetPortalCredentialStatus($profile['rpId'], $origin);
        $legacyCount = $credentialStatus['migratable'];
        $slaves = json_decode($this->ReadPropertyString('SlaveURLs'), true);
        if (!is_array($slaves)) {
            $slaves = [];
        }

        $nonce = SecretsPortalSecurity::base64UrlEncode(random_bytes(18));
        $this->SendPortalSecurityHeaders($nonce);

        echo '<html><head><title>Admin Dashboard</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;background:#f4f7f6;padding:20px;color:#333}.box{background:#fff;padding:25px;border-radius:12px;box-shadow:0 5px 20px rgba(0,0,0,.1);max-width:1000px;margin:auto}h1{border-bottom:2px solid #eee;padding-bottom:10px;color:#2c3e50}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{padding:12px;border-bottom:1px solid #eee;text-align:left}th{background:#f8f9fa;color:#666;font-size:13px;text-transform:uppercase}.link-cell{word-break:break-all;font-family:monospace;font-size:12px;background:#f9f9f9;padding:8px;border-radius:4px;display:block}a{color:#4a90e2;text-decoration:none}a:hover{text-decoration:underline}.tag{font-size:10px;padding:2px 6px;border-radius:10px;background:#eee;color:#777;margin-left:8px}</style></head><body>';
        echo '<div class="box"><h1>🛠️ Admin Dashboard</h1>';
        echo '<p>Current WebAuthn profile: <code>' . htmlspecialchars($origin, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code></p>';
        echo '<p>Registration links never contain long-term passwords. A target system asks for its registration password unless this browser already has an authenticated session there.</p>';
        if ($legacyCount > 0) {
            echo '<p><strong>' . $legacyCount . ' legacy passkey(s) can be upgraded without re-enrolment.</strong> <a href="' . htmlspecialchars($migrationUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">Start verified migration</a>.</p>';
        }
        if ($credentialStatus['incompatible'] > 0) {
            echo '<p class="error"><strong>' . $credentialStatus['incompatible'] . ' legacy passkey record(s) require attention.</strong> They were preserved but cannot currently be migrated, so migration is not complete.</p>';
        }
        echo '<p>Verified for this origin: ' . $credentialStatus['verified'] . '; registered for another origin: ' . $credentialStatus['otherOrigin'] . '.</p>';
        echo '<table><tr><th>System</th><th>Passkey registration URL</th></tr>';
        echo '<tr><td><strong>LOCAL</strong><span class="tag">This server</span></td><td><a class="link-cell" href="' . htmlspecialchars($localUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">' . htmlspecialchars($localUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</a></td></tr>';

        foreach ($slaves as $slave) {
            if (!is_array($slave)) {
                continue;
            }
            $url = trim((string)($slave['Url'] ?? ''));
            if ($url === '') {
                continue;
            }
            $baseUrl = explode('?', $url, 2)[0];
            $registerUrl = $baseUrl . '?register=1';
            $name = trim((string)($slave['Server'] ?? 'Remote system'));
            echo '<tr><td><strong>' . htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</strong><span class="tag">Remote</span></td>';
            echo '<td><a class="link-cell" href="' . htmlspecialchars($registerUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">' . htmlspecialchars($registerUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</a></td></tr>';
        }

        echo '</table></div></body></html>';
    }

    private function ServeAdminLoginPage(string $error = ''): void
    {
        if (!$this->RequirePortalReady(false)) {
            return;
        }
        $profileError = '';
        $profile = $this->GetCurrentPortalProfile($profileError);
        if ($profile === null) {
            $this->SendPortalError(503, $profileError);
            return;
        }

        $nonce = SecretsPortalSecurity::base64UrlEncode(random_bytes(18));
        $this->SendPortalSecurityHeaders($nonce);
        echo '<html><head><title>Vault Admin Login</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f4f7f6}.box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 5px 20px rgba(0,0,0,.1);width:min(420px,90vw)}input,button,a{box-sizing:border-box;width:100%;padding:12px;margin-top:12px}a{display:block;text-align:center}.error{color:#b00020}</style></head><body><div class="box">';
        echo '<h2>Vault administration</h2>';
        if ($error !== '') {
            echo '<p class="error">' . htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';
        }
        echo '<form method="post" action="?admin=1"><input type="hidden" name="action" value="admin-login">';
        echo '<label>Admin password<input type="password" name="password" autocomplete="current-password" required></label>';
        echo '<button type="submit">Sign in with admin password</button></form>';
        echo '</div></body></html>';
    }

    private function HandleAdminLogin(): void
    {
        if (!$this->RequirePortalReady(false)) {
            return;
        }
        if (!$this->CheckPortalRateLimit('admin-password', true)) {
            $this->SendPortalError(429, 'Too many attempts. Please try again later.');
            return;
        }

        $vault = $this->_decryptVault();
        $expected = is_array($vault) ? (string)($vault['AdminPortal']['PW'] ?? '') : '';
        $provided = (string)($_POST['password'] ?? '');

        if ($expected === '' || $provided === '' || !hash_equals($expected, $provided)) {
            $this->LogPortalFailure('admin-password');
            http_response_code(401);
            $this->ServeAdminLoginPage('Authentication failed.');
            return;
        }

        $this->ResetPortalRateLimit('admin-password');
        if (!$this->CreatePortalSession('admin-password', ['admin', 'register', 'migrate'])) {
            $this->SendPortalError(500, 'The session could not be created.');
            return;
        }

        header('Location: /hook/secrets_' . $this->InstanceID . '?admin=1', true, 303);
    }

    /**
     * WEBHOOK DATA PROCESSING
     * This is called by IP-Symcon when data is posted to /hook/secrets_ID
     */
    protected function ProcessHookData(): void
    {
        $mode = $this->ReadPropertyInteger('OperationMode');
        $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $isPortal = isset($_GET['portal']);
        $isRegister = isset($_GET['register']);
        $isAdmin = isset($_GET['admin']);
        $isMigrate = isset($_GET['migrate']);

        if ($isAdmin) {
            if ($method === 'GET') {
                if ($this->IsPortalSessionValid(false, ['admin'], ['admin-password'])) {
                    $this->ServeAdminDashboard();
                } else {
                    $this->ServeAdminLoginPage();
                }
                return;
            }
            if ($method === 'POST' && (string)($_POST['action'] ?? '') === 'admin-login') {
                $this->HandleAdminLogin();
                return;
            }
            $this->SendMethodNotAllowed(['GET', 'POST']);
            return;
        }

        if ($isRegister) {
            if ($method === 'GET') {
                $registrationSession = $this->GetPortalSessionContext(false, ['register'], ['admin-password']);
                if ($registrationSession !== null) {
                    $this->ServeRegistrationUI('admin-password', (string)$registrationSession['tokenHash']);
                } else {
                    $this->ServeRegistrationPasswordPage();
                }
                return;
            }

            if ($method === 'POST' && $this->IsJsonRequest()) {
                $this->FinishRegistration();
                return;
            }

            if ($method === 'POST' && (string)($_POST['action'] ?? '') === 'registration-login') {
                $this->HandleRegistrationPassword();
                return;
            }

            $this->SendMethodNotAllowed(['GET', 'POST']);
            return;
        }

        if ($isMigrate) {
            if (!$this->IsPortalSessionValid(false, ['migrate'], ['admin-password'])) {
                $this->SendPortalError(403, 'Admin authentication is required before legacy passkeys can be migrated.');
                return;
            }
            if ($method === 'GET') {
                $this->ServeLegacyMigrationUI();
                return;
            }
            if ($method === 'POST' && $this->IsJsonRequest()) {
                $this->VerifyLegacyMigration();
                return;
            }
            $this->SendMethodNotAllowed(['GET', 'POST']);
            return;
        }

        if ($isPortal) {
            if ($method === 'GET') {
                if ($this->IsPortalAuthenticated()) {
                    $returnUrl = SecretsPortalSecurity::sanitizeReturnUrl((string)($_GET['return'] ?? '/'));
                    header('Location: ' . $returnUrl, true, 303);
                } else {
                    $this->ServePortalUI();
                }
                return;
            }
            if ($method === 'POST') {
                $this->VerifyPortalAccess();
                return;
            }
            $this->SendMethodNotAllowed(['GET', 'POST']);
            return;
        }

        if ($mode !== 0) {
            $this->SendPortalError(403, 'Access denied: this instance is not configured as a Slave.');
            return;
        }

        if ($method !== 'POST') {
            $this->SendMethodNotAllowed(['POST']);
            return;
        }

        // Standard sync logic (Slave only)
        $input = $this->ReadRequestBody(self::SYNC_MAX_REQUEST_BYTES);
        if (!is_string($input)) {
            http_response_code(413);
            echo 'Sync payload too large';
            return;
        }
        $data = json_decode((string)$input, true);
        $expectedToken = $this->getAuthToken();
        if (
            $expectedToken === '' ||
            !is_array($data) ||
            !isset($data['auth']) ||
            !is_string($data['auth']) ||
            $data['auth'] === '' ||
            !hash_equals($expectedToken, $data['auth'])
        ) {
            http_response_code(403);
            echo 'Invalid Sync Token';
            return;
        }

        if (isset($data['vault'])) {
            if (!is_string($data['vault']) || !$this->EnterVaultLock()) {
                http_response_code(503);
                echo 'Vault sync state unavailable';
                return;
            }
            try {
                $vaultRevision = null;
                $currentVault = $this->_decryptVaultWithRevision($vaultRevision);
                if ($currentVault === false && $this->GetValue('Vault') !== '') {
                    http_response_code(500);
                    echo 'Current vault could not be decrypted';
                    return;
                }
                $masterVault = $this->DecryptVaultJson((string)$data['vault']);
                if (!is_array($masterVault)) {
                    http_response_code(400);
                    echo 'Incoming vault could not be authenticated';
                    return;
                }
                $currentVault = is_array($currentVault) ? $currentVault : [];
                $this->PreserveLocalVaultAreas($currentVault, $masterVault);
                if (!$this->_encryptAndSave($masterVault, $vaultRevision)) {
                    http_response_code(500);
                    echo 'Incoming vault could not be saved';
                    return;
                }
            } finally {
                $this->LeaveVaultLock();
            }
        }
        echo 'OK';
    }

    private function ServeRegistrationPasswordPage(string $error = ''): void
    {
        if (!$this->RequirePortalReady(false)) {
            return;
        }

        $nonce = SecretsPortalSecurity::base64UrlEncode(random_bytes(18));
        $this->SendPortalSecurityHeaders($nonce);
        echo '<html><head><title>Register Passkey</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f4f7f6}.box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 5px 20px rgba(0,0,0,.1);width:min(420px,90vw)}input,button{box-sizing:border-box;width:100%;padding:12px;margin-top:12px}.error{color:#b00020}</style></head><body><div class="box"><h2>Register a passkey</h2>';
        if ($error !== '') {
            echo '<p class="error">' . htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';
        }
        echo '<form method="post" action="?register=1"><input type="hidden" name="action" value="registration-login">';
        echo '<label>Registration password<input type="password" name="password" autocomplete="one-time-code" required></label>';
        echo '<button type="submit">Continue</button></form></div></body></html>';
    }

    private function HandleRegistrationPassword(): void
    {
        if (!$this->RequirePortalReady(false)) {
            return;
        }
        if (!$this->CheckPortalRateLimit('registration-password', true)) {
            $this->SendPortalError(429, 'Too many attempts. Please try again later.');
            return;
        }

        $vault = $this->_decryptVault();
        $expected = is_array($vault) ? (string)($vault['RegistrationPassword']['PW'] ?? '') : '';
        $provided = (string)($_POST['password'] ?? '');

        if ($expected === '' || $provided === '' || !hash_equals($expected, $provided)) {
            $this->LogPortalFailure('registration-password');
            http_response_code(401);
            $this->ServeRegistrationPasswordPage('Authentication failed.');
            return;
        }

        $this->ResetPortalRateLimit('registration-password');
        $this->ServeRegistrationUI('registration-password', null);
    }

    private function ServeLegacyMigrationUI(): void
    {
        if (!$this->RequirePortalReady(false)) {
            return;
        }
        $adminSession = $this->GetPortalSessionContext(false, ['migrate'], ['admin-password']);
        if ($adminSession === null) {
            $this->SendPortalError(403, 'A current admin-password session is required.');
            return;
        }
        $profileError = '';
        $profile = $this->GetCurrentPortalProfile($profileError);
        if ($profile === null) {
            $this->SendPortalError(503, $profileError);
            return;
        }

        $legacyCredentials = $this->GetMigratableLegacyCredentials($profile['rpId']);
        $credentialStatus = $this->GetPortalCredentialStatus($profile['rpId'], $profile['origin']);
        if (count($legacyCredentials) === 0) {
            $nonce = SecretsPortalSecurity::base64UrlEncode(random_bytes(18));
            $this->SendPortalSecurityHeaders($nonce);
            if ($credentialStatus['incompatible'] > 0) {
                echo '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Passkey migration</title></head><body><h2>Passkey migration requires attention</h2><p>' . $credentialStatus['incompatible'] . ' legacy passkey record(s) for this origin could not be parsed or verified. They were preserved and the migration is not complete.</p><p><a href="?admin=1">Return to the admin dashboard</a></p></body></html>';
            } elseif ($credentialStatus['verified'] > 0) {
                echo '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Passkey migration</title></head><body><h2>Passkey migration complete for this origin</h2><p>' . $credentialStatus['verified'] . ' verified passkey(s) are available. Repeat migration through any configured backup origin before enabling the portal.</p><p><a href="?admin=1">Return to the admin dashboard</a></p></body></html>';
            } else {
                echo '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Passkey migration</title></head><body><h2>No passkeys found for this origin</h2><p>No verified or safely migratable passkeys were found. This is not confirmation that migration succeeded.</p><p><a href="?admin=1">Return to the admin dashboard</a></p></body></html>';
            }
            return;
        }

        $challenge = random_bytes(32);
        $rpId = $profile['rpId'];
        $origin = $profile['origin'];
        $allowedIds = array_keys($legacyCredentials);

        $sid = $this->StorePortalChallenge('migration', [
            'challenge'            => SecretsPortalSecurity::base64UrlEncode($challenge),
            'rpId'                 => $rpId,
            'origin'               => $origin,
            'allowedCredentialIds' => $allowedIds,
            'authorizationMethod'  => 'admin-password',
            'authorizationSessionHash' => (string)$adminSession['tokenHash']
        ]);
        if ($sid === null) {
            $this->SendPortalError(503, 'Migration state is busy. Please try again.');
            return;
        }

        $allowCredentials = [];
        foreach ($allowedIds as $credentialId) {
            $allowCredentials[] = ['type' => 'public-key', 'id' => $credentialId];
        }
        $configJson = json_encode([
            'sid'              => $sid,
            'challenge'        => SecretsPortalSecurity::base64UrlEncode($challenge),
            'rpId'             => $rpId,
            'remaining'        => count($legacyCredentials),
            'allowCredentials' => $allowCredentials
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

        $nonce = SecretsPortalSecurity::base64UrlEncode(random_bytes(18));
        $this->SendPortalSecurityHeaders($nonce);
        echo '<html><head><title>Passkey migration</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f4f7f6}.box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 5px 20px rgba(0,0,0,.1);text-align:center;max-width:520px}button,a{padding:12px 20px}.ok{color:#087f23}.error{color:#b00020}</style></head><body>';
        echo '<div class="box"><h2>Upgrade existing passkey</h2><p>A new passkey will not be created. Touch the authenticator once to prove possession and upgrade its stored public key.</p>';
        echo '<p>' . count($legacyCredentials) . ' migratable credential(s) remain.</p><button id="migrateButton" type="button">Verify and upgrade one passkey</button><p id="status" role="status"></p><p><a href="?admin=1">Admin dashboard</a></p></div>';
        echo '<script nonce="' . htmlspecialchars($nonce, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">';
        echo 'const config=' . $configJson . ';';
        echo 'const fromB64u=v=>{v=v.replace(/-/g,"+").replace(/_/g,"/");while(v.length%4)v+="=";const b=atob(v);return Uint8Array.from(b,c=>c.charCodeAt(0));};';
        echo 'const toB64u=v=>{let s="";new Uint8Array(v).forEach(b=>s+=String.fromCharCode(b));return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");};';
        echo 'async function migrate(){const status=document.getElementById("status");status.className="";status.textContent="";try{';
        echo 'const publicKey={challenge:fromB64u(config.challenge),rpId:config.rpId,timeout:60000,userVerification:"required",allowCredentials:config.allowCredentials.map(i=>({type:i.type,id:fromB64u(i.id)}))};';
        echo 'const cred=await navigator.credentials.get({publicKey});';
        echo 'const payload={sid:config.sid,type:cred.type,rawId:toB64u(cred.rawId),response:{clientDataJSON:toB64u(cred.response.clientDataJSON),authenticatorData:toB64u(cred.response.authenticatorData),signature:toB64u(cred.response.signature),userHandle:cred.response.userHandle===null?null:toB64u(cred.response.userHandle)}};';
        echo 'const res=await fetch(location.pathname+"?migrate=1",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});';
        echo 'const body=await res.json().catch(()=>({error:"Migration failed."}));if(!res.ok||!body.ok)throw new Error(body.error||"Migration failed.");status.className="ok";status.innerHTML="✅ Passkey upgraded. <a href=\\"?migrate=1\\">Continue with the next passkey</a>.";';
        echo '}catch(e){status.className="error";status.textContent="Migration failed: "+e.message;}}';
        echo 'document.getElementById("migrateButton").addEventListener("click",migrate);';
        echo '</script></body></html>';
    }

    private function VerifyLegacyMigration(): void
    {
        if (!$this->IsPortalSessionValid(false, ['migrate'], ['admin-password'])) {
            $this->SendPortalJson(403, ['ok' => false, 'error' => 'Admin authentication is required.']);
            return;
        }
        if (!$this->RequirePortalReady(false)) {
            return;
        }
        if (!$this->CheckPortalRateLimit('migration', true)) {
            $this->SendPortalJson(429, ['ok' => false, 'error' => 'Too many attempts. Please try again later.']);
            return;
        }

        $requestBody = $this->ReadRequestBody(self::PORTAL_JSON_MAX_REQUEST_BYTES);
        if (!is_string($requestBody)) {
            $this->SendPortalJson(413, ['ok' => false, 'error' => 'Request payload too large.']);
            return;
        }
        $data = SecretsPortalSecurity::decodeJsonRequest($requestBody);
        $sid = is_array($data) ? (string)($data['sid'] ?? '') : '';
        if (preg_match('/^[A-Za-z0-9_-]{20,64}$/D', $sid) !== 1) {
            $this->RejectPortalRequest('migration-request');
            return;
        }

        $buffer = $this->ConsumePortalChallenge($sid, 'migration');
        if ($buffer === null || !$this->ChallengeMatchesCurrentPortalProfile($buffer)) {
            $this->RejectPortalRequest('migration-expired');
            return;
        }

        $challenge = SecretsPortalSecurity::base64UrlDecode((string)($buffer['challenge'] ?? ''));
        $rawId = SecretsPortalSecurity::base64UrlDecode((string)($data['rawId'] ?? ''));
        $clientDataJson = SecretsPortalSecurity::base64UrlDecode((string)($data['response']['clientDataJSON'] ?? ''));
        $authenticatorData = SecretsPortalSecurity::base64UrlDecode((string)($data['response']['authenticatorData'] ?? ''));
        $signature = SecretsPortalSecurity::base64UrlDecode((string)($data['response']['signature'] ?? ''));
        if (($data['type'] ?? null) !== 'public-key' || $challenge === null || $rawId === null || $clientDataJson === null || $authenticatorData === null || $signature === null) {
            $this->RejectPortalRequest('migration-payload');
            return;
        }

        $credentialId = SecretsPortalSecurity::base64UrlEncode($rawId);
        $allowed = $buffer['allowedCredentialIds'] ?? [];
        $rpId = (string)($buffer['rpId'] ?? '');
        $origin = (string)($buffer['origin'] ?? '');
        $legacyCredentials = $this->GetMigratableLegacyCredentials($rpId);
        if (!is_array($allowed) || !in_array($credentialId, $allowed, true) || !isset($legacyCredentials[$credentialId])) {
            $this->RejectPortalRequest('migration-credential');
            return;
        }

        $legacy = $legacyCredentials[$credentialId];
        $submittedUserHandle = $data['response']['userHandle'] ?? null;
        if ($submittedUserHandle !== null) {
            $userHandle = is_string($submittedUserHandle) ? SecretsPortalSecurity::base64UrlDecode($submittedUserHandle) : null;
            $expectedUserHandle = 'user' . $this->InstanceID;
            if ($userHandle === null || !hash_equals($expectedUserHandle, $userHandle)) {
                $this->RejectPortalRequest('migration-user-handle');
                return;
            }
        }
        if (SecretsPortalSecurity::validateClientData($clientDataJson, 'webauthn.get', $challenge, $origin) === null) {
            $this->RejectPortalRequest('migration-client-data');
            return;
        }

        try {
            $webAuthn = $this->CreateWebAuthnVerifier($rpId);
            $webAuthn->processGet(
                $clientDataJson,
                $authenticatorData,
                $signature,
                (string)$legacy['credentialPublicKey'],
                $challenge,
                null,
                true,
                true
            );
            $newCounter = $webAuthn->getSignatureCounter();
            $verifiedAuthenticatorData = new \lbuchs\WebAuthn\Attestation\AuthenticatorData($authenticatorData);
            $backupEligible = (bool)$verifiedAuthenticatorData->getIsBackupEligible();
            $backedUp = (bool)$verifiedAuthenticatorData->getIsBackup();
            if (!SecretsPortalSecurity::validateBackupFlags($backupEligible, $backedUp)) {
                throw new RuntimeException('Credential backup flags are inconsistent.');
            }
        } catch (Throwable $e) {
            $this->RejectPortalRequest('migration-cryptographic-verification');
            return;
        }

        $deviceKey = (string)$legacy['deviceKey'];
        if (!$this->EnterAuthorizedCeremonyCommit($buffer, 'migrate')) {
            $this->RejectPortalRequest('migration-authorization');
            return;
        }
        if (!$this->EnterVaultLock()) {
            $this->LeavePortalStateLock();
            $this->SendPortalJson(503, ['ok' => false, 'error' => 'The vault is busy. Please try again.']);
            return;
        }

        try {
            $vaultRevision = null;
            $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
            $old = is_array($vaultData) ? ($vaultData[self::LOCAL_AUTH_KEY][$deviceKey] ?? null) : null;
            $currentLegacyId = is_array($old) ? $this->DecodeLegacyStoredBinary((string)($old['credentialId'] ?? '')) : null;
            if (
                !is_array($old) ||
                (int)($old['schemaVersion'] ?? 0) === SecretsPortalSecurity::CREDENTIAL_SCHEMA_VERSION ||
                $currentLegacyId === null ||
                !hash_equals($rawId, $currentLegacyId)
            ) {
                $this->RejectPortalRequest('migration-state');
                return;
            }

            // Preserve the complete legacy record. The secure verifier uses
            // credentialIdV2 while the unchanged rollback branch uses the
            // original padded-Base64 credentialId and attestation.
            $migrated = $old;
            $migrated['schemaVersion'] = SecretsPortalSecurity::CREDENTIAL_SCHEMA_VERSION;
            $migrated['credentialIdV2'] = $credentialId;
            $migrated['credentialPublicKey'] = (string)$legacy['credentialPublicKey'];
            $migrated['signatureCounter'] = (int)($newCounter ?? 0);
            $migrated['rpId'] = $rpId;
            $migrated['origin'] = $origin;
            $migrated['userHandle'] = SecretsPortalSecurity::base64UrlEncode('user' . $this->InstanceID);
            $migrated['aaguid'] = (string)($legacy['aaguid'] ?? '');
            $migrated['attestationFormat'] = (string)($legacy['attestationFormat'] ?? '');
            $migrated['backupEligible'] = $backupEligible;
            $migrated['backedUp'] = $backedUp;
            $migrated['backupEligibilityVerified'] = true;
            $migrated['RegisteredAt'] = (int)($old['RegisteredAt'] ?? time());
            $migrated['MigratedAt'] = time();
            $migrated['UserAgent'] = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512);
            $vaultData[self::LOCAL_AUTH_KEY][$deviceKey] = $migrated;

            if (!$this->_encryptAndSave($vaultData, $vaultRevision)) {
                $this->SendPortalJson(500, ['ok' => false, 'error' => 'The verified migrated credential could not be saved.']);
                return;
            }
        } finally {
            $this->LeaveVaultLock();
            $this->LeavePortalStateLock();
        }

        $this->ResetPortalRateLimit('migration');
        $this->LogMessage('Legacy WebAuthn credential upgraded after live signature verification. DeviceKey=' . $deviceKey, KL_MESSAGE);
        $this->SendPortalJson(200, ['ok' => true]);
    }

    private function ServeRegistrationUI(string $authorizationMethod, ?string $authorizationSessionHash): void
    {
        if (!$this->RequirePortalReady(false)) {
            return;
        }
        $profileError = '';
        $profile = $this->GetCurrentPortalProfile($profileError);
        if ($profile === null) {
            $this->SendPortalError(503, $profileError);
            return;
        }

        $challenge = random_bytes(32);
        $rpId = $profile['rpId'];
        $origin = $profile['origin'];

        $sid = $this->StorePortalChallenge('registration', [
            'challenge'               => SecretsPortalSecurity::base64UrlEncode($challenge),
            'rpId'                    => $rpId,
            'origin'                  => $origin,
            'authorizationMethod'     => $authorizationMethod,
            'authorizationSessionHash'=> $authorizationSessionHash
        ]);
        if ($sid === null) {
            $this->SendPortalError(503, 'Registration state is busy. Please try again.');
            return;
        }

        $excludeCredentials = [];
        foreach (array_keys($this->GetVerifiedPortalCredentials($rpId, $origin)) as $credentialId) {
            $excludeCredentials[] = ['type' => 'public-key', 'id' => $credentialId];
        }

        $userHandle = SecretsPortalSecurity::base64UrlEncode(hash('sha256', 'symcon-vault-owner:' . $this->InstanceID, true));
        $configJson = json_encode([
            'sid'                => $sid,
            'challenge'          => SecretsPortalSecurity::base64UrlEncode($challenge),
            'rpId'               => $rpId,
            'userId'             => $userHandle,
            'excludeCredentials' => $excludeCredentials
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

        $nonce = SecretsPortalSecurity::base64UrlEncode(random_bytes(18));
        $this->SendPortalSecurityHeaders($nonce);

        echo '<html><head><title>Vault Register</title><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f4f7f6}.box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 5px 20px rgba(0,0,0,.1);text-align:center}button{padding:12px 20px}.ok{color:#087f23}.error{color:#b00020}</style></head><body>';
        echo '<div class="box"><h2>🔑 Passkey registrieren</h2><p>Register this device for the configured portal origin.</p>';
        echo '<button id="registerButton" type="button">Dieses Gerät registrieren</button><p id="status" role="status"></p></div>';
        echo '<script nonce="' . htmlspecialchars($nonce, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">';
        echo 'const config=' . $configJson . ';';
        echo 'const fromB64u=v=>{v=v.replace(/-/g,"+").replace(/_/g,"/");while(v.length%4)v+="=";const b=atob(v);return Uint8Array.from(b,c=>c.charCodeAt(0));};';
        echo 'const toB64u=v=>{let s="";new Uint8Array(v).forEach(b=>s+=String.fromCharCode(b));return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");};';
        echo 'async function register(){const status=document.getElementById("status");status.className="";status.textContent="";try{';
        echo 'const publicKey={rp:{name:"Symcon Vault",id:config.rpId},user:{id:fromB64u(config.userId),name:"owner",displayName:"Vault Owner"},challenge:fromB64u(config.challenge),pubKeyCredParams:[{type:"public-key",alg:-7},{type:"public-key",alg:-257}],timeout:60000,attestation:"none",authenticatorSelection:{residentKey:"preferred",requireResidentKey:false,userVerification:"required"},excludeCredentials:config.excludeCredentials.map(i=>({type:i.type,id:fromB64u(i.id)}))};';
        echo 'const cred=await navigator.credentials.create({publicKey});';
        echo 'const payload={sid:config.sid,type:cred.type,rawId:toB64u(cred.rawId),response:{attestationObject:toB64u(cred.response.attestationObject),clientDataJSON:toB64u(cred.response.clientDataJSON)}};';
        echo 'const res=await fetch(location.pathname+"?register=1",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});';
        echo 'const body=await res.json().catch(()=>({error:"Registration failed."}));if(!res.ok||!body.ok)throw new Error(body.error||"Registration failed.");status.className="ok";status.textContent="✅ Device successfully registered. The portal can now be enabled.";';
        echo '}catch(e){status.className="error";status.textContent="Registration failed: "+e.message;}}';
        echo 'document.getElementById("registerButton").addEventListener("click",register);';
        echo '</script></body></html>';
    }

    private function FinishRegistration(): void
    {
        if (!$this->RequirePortalReady(false)) {
            return;
        }
        if (!$this->CheckPortalRateLimit('registration', true)) {
            $this->SendPortalJson(429, ['ok' => false, 'error' => 'Too many attempts. Please try again later.']);
            return;
        }

        $requestBody = $this->ReadRequestBody(self::PORTAL_JSON_MAX_REQUEST_BYTES);
        if (!is_string($requestBody)) {
            $this->SendPortalJson(413, ['ok' => false, 'error' => 'Request payload too large.']);
            return;
        }
        $data = SecretsPortalSecurity::decodeJsonRequest($requestBody);
        $sid = is_array($data) ? (string)($data['sid'] ?? '') : '';
        if (preg_match('/^[A-Za-z0-9_-]{20,64}$/D', $sid) !== 1) {
            $this->RejectPortalRequest('registration-request');
            return;
        }

        $buffer = $this->ConsumePortalChallenge($sid, 'registration');
        if ($buffer === null || !$this->ChallengeMatchesCurrentPortalProfile($buffer)) {
            $this->RejectPortalRequest('registration-expired');
            return;
        }

        $challenge = SecretsPortalSecurity::base64UrlDecode((string)($buffer['challenge'] ?? ''));
        $rawId = SecretsPortalSecurity::base64UrlDecode((string)($data['rawId'] ?? ''));
        $clientDataJson = SecretsPortalSecurity::base64UrlDecode((string)($data['response']['clientDataJSON'] ?? ''));
        $attestationObject = SecretsPortalSecurity::base64UrlDecode((string)($data['response']['attestationObject'] ?? ''));

        if (($data['type'] ?? null) !== 'public-key' || $challenge === null || $rawId === null || $clientDataJson === null || $attestationObject === null) {
            $this->RejectPortalRequest('registration-payload');
            return;
        }

        $origin = (string)($buffer['origin'] ?? '');
        $rpId = (string)($buffer['rpId'] ?? '');
        if (SecretsPortalSecurity::validateClientData($clientDataJson, 'webauthn.create', $challenge, $origin) === null) {
            $this->RejectPortalRequest('registration-client-data');
            return;
        }

        try {
            $webAuthn = $this->CreateWebAuthnVerifier($rpId);
            $registration = $webAuthn->processCreate(
                $clientDataJson,
                $attestationObject,
                $challenge,
                true,
                true,
                false,
                false
            );
        } catch (Throwable $e) {
            $this->RejectPortalRequest('registration-cryptographic-verification');
            return;
        }

        $verifiedCredentialId = (string)($registration->credentialId ?? '');
        $publicKey = (string)($registration->credentialPublicKey ?? '');
        $backupEligible = (bool)($registration->isBackupEligible ?? false);
        $backedUp = (bool)($registration->isBackedUp ?? false);
        if (
            $verifiedCredentialId === '' ||
            !hash_equals($verifiedCredentialId, $rawId) ||
            $publicKey === '' ||
            !SecretsPortalSecurity::validateBackupFlags($backupEligible, $backedUp)
        ) {
            $this->RejectPortalRequest('registration-credential');
            return;
        }

        $credentialId = SecretsPortalSecurity::base64UrlEncode($verifiedCredentialId);
        if (!$this->EnterAuthorizedCeremonyCommit($buffer, 'register')) {
            $this->RejectPortalRequest('registration-authorization');
            return;
        }
        if (!$this->EnterVaultLock()) {
            $this->LeavePortalStateLock();
            $this->SendPortalJson(503, ['ok' => false, 'error' => 'The vault is busy. Please try again.']);
            return;
        }

        $deviceKey = '';
        try {
            $vaultRevision = null;
            $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
            if (!is_array($vaultData)) {
                $this->SendPortalJson(500, ['ok' => false, 'error' => 'The vault could not be decrypted.']);
                return;
            }
            if (!isset($vaultData[self::LOCAL_AUTH_KEY]) || !is_array($vaultData[self::LOCAL_AUTH_KEY])) {
                $vaultData[self::LOCAL_AUTH_KEY] = [];
            }

            foreach ($vaultData[self::LOCAL_AUTH_KEY] as $existing) {
                if (!is_array($existing)) {
                    continue;
                }
                $existingCredentialId = $this->GetCredentialCanonicalId($existing);
                if (
                    (string)($existing['rpId'] ?? '') === $rpId &&
                    $existingCredentialId !== '' &&
                    hash_equals($existingCredentialId, $credentialId)
                ) {
                    $this->SendPortalJson(409, ['ok' => false, 'error' => 'This passkey is already registered.']);
                    return;
                }
            }

            $aaguid = (string)($registration->AAGUID ?? '');
            $deviceKey = 'device_' . bin2hex(random_bytes(8));
            $vaultData[self::LOCAL_AUTH_KEY][$deviceKey] = [
                'schemaVersion'       => SecretsPortalSecurity::CREDENTIAL_SCHEMA_VERSION,
                'credentialId'        => base64_encode($verifiedCredentialId),
                'credentialIdV2'      => $credentialId,
                'credentialPublicKey' => $publicKey,
                'signatureCounter'    => (int)($registration->signatureCounter ?? 0),
                'rpId'                => $rpId,
                'origin'              => $origin,
                'userHandle'          => SecretsPortalSecurity::base64UrlEncode(hash('sha256', 'symcon-vault-owner:' . $this->InstanceID, true)),
                'aaguid'              => ($aaguid === '') ? '' : SecretsPortalSecurity::base64UrlEncode($aaguid),
                'attestation'         => base64_encode($attestationObject),
                'attestationFormat'   => (string)($registration->attestationFormat ?? ''),
                'backupEligible'      => $backupEligible,
                'backedUp'            => $backedUp,
                'backupEligibilityVerified' => true,
                'RegisteredAt'        => time(),
                'UserAgent'           => substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512)
            ];

            if (!$this->_encryptAndSave($vaultData, $vaultRevision)) {
                $this->SendPortalJson(500, ['ok' => false, 'error' => 'The verified passkey could not be saved.']);
                return;
            }
        } finally {
            $this->LeaveVaultLock();
            $this->LeavePortalStateLock();
        }

        $this->ResetPortalRateLimit('registration');
        $this->LogMessage('WebAuthn passkey registered after complete server-side verification. DeviceKey=' . $deviceKey, KL_MESSAGE);
        $this->SendPortalJson(200, ['ok' => true]);
    }

    private function VerifyPortalAccess(): void
    {
        if (!$this->RequirePortalReady()) {
            return;
        }
        if (!$this->CheckPortalRateLimit('assertion', true)) {
            $this->SendPortalJson(429, ['ok' => false, 'error' => 'Too many attempts. Please try again later.']);
            return;
        }

        $requestBody = $this->ReadRequestBody(self::PORTAL_JSON_MAX_REQUEST_BYTES);
        if (!is_string($requestBody)) {
            $this->SendPortalJson(413, ['ok' => false, 'error' => 'Request payload too large.']);
            return;
        }
        $data = SecretsPortalSecurity::decodeJsonRequest($requestBody);
        $sid = is_array($data) ? (string)($data['sid'] ?? '') : '';
        if (preg_match('/^[A-Za-z0-9_-]{20,64}$/D', $sid) !== 1) {
            $this->RejectPortalRequest('assertion-request');
            return;
        }

        $buffer = $this->ConsumePortalChallenge($sid, 'assertion');
        if ($buffer === null || !$this->ChallengeMatchesCurrentPortalProfile($buffer)) {
            $this->RejectPortalRequest('assertion-expired');
            return;
        }

        $challenge = SecretsPortalSecurity::base64UrlDecode((string)($buffer['challenge'] ?? ''));
        $rawId = SecretsPortalSecurity::base64UrlDecode((string)($data['rawId'] ?? ''));
        $clientDataJson = SecretsPortalSecurity::base64UrlDecode((string)($data['response']['clientDataJSON'] ?? ''));
        $authenticatorData = SecretsPortalSecurity::base64UrlDecode((string)($data['response']['authenticatorData'] ?? ''));
        $signature = SecretsPortalSecurity::base64UrlDecode((string)($data['response']['signature'] ?? ''));

        if (($data['type'] ?? null) !== 'public-key' || $challenge === null || $rawId === null || $clientDataJson === null || $authenticatorData === null || $signature === null) {
            $this->RejectPortalRequest('assertion-payload');
            return;
        }

        $credentialId = SecretsPortalSecurity::base64UrlEncode($rawId);
        $allowed = $buffer['allowedCredentialIds'] ?? [];
        if (!is_array($allowed) || !in_array($credentialId, $allowed, true)) {
            $this->RejectPortalRequest('assertion-credential');
            return;
        }

        $origin = (string)($buffer['origin'] ?? '');
        $rpId = (string)($buffer['rpId'] ?? '');
        $credentials = $this->GetVerifiedPortalCredentials($rpId, $origin);
        if (!isset($credentials[$credentialId])) {
            $this->RejectPortalRequest('assertion-credential');
            return;
        }

        $credentialEntry = $credentials[$credentialId];
        $credential = $credentialEntry['data'];
        $submittedUserHandle = $data['response']['userHandle'] ?? null;
        if ($submittedUserHandle !== null) {
            $userHandle = is_string($submittedUserHandle) ? SecretsPortalSecurity::base64UrlDecode($submittedUserHandle) : null;
            $expectedUserHandle = SecretsPortalSecurity::base64UrlDecode((string)($credential['userHandle'] ?? ''));
            if ($userHandle === null || $expectedUserHandle === null || !hash_equals($expectedUserHandle, $userHandle)) {
                $this->RejectPortalRequest('assertion-user-handle');
                return;
            }
        }
        if (SecretsPortalSecurity::validateClientData($clientDataJson, 'webauthn.get', $challenge, $origin) === null) {
            $this->RejectPortalRequest('assertion-client-data');
            return;
        }

        try {
            $webAuthn = $this->CreateWebAuthnVerifier($rpId);
            $webAuthn->processGet(
                $clientDataJson,
                $authenticatorData,
                $signature,
                (string)$credential['credentialPublicKey'],
                $challenge,
                (int)($credential['signatureCounter'] ?? 0),
                true,
                true
            );
            $newCounter = $webAuthn->getSignatureCounter();
            $verifiedAuthenticatorData = new \lbuchs\WebAuthn\Attestation\AuthenticatorData($authenticatorData);
            $backupEligible = (bool)$verifiedAuthenticatorData->getIsBackupEligible();
            $backedUp = (bool)$verifiedAuthenticatorData->getIsBackup();
            $expectedBackupEligible = (bool)($credential['backupEligibilityVerified'] ?? false)
                ? (bool)($credential['backupEligible'] ?? false)
                : null;
            if (!SecretsPortalSecurity::validateBackupFlags($backupEligible, $backedUp, $expectedBackupEligible)) {
                throw new RuntimeException('Credential backup flags are inconsistent.');
            }
        } catch (Throwable $e) {
            $this->RejectPortalRequest('assertion-cryptographic-verification');
            return;
        }

        $deviceKey = (string)$credentialEntry['deviceKey'];
        if (!$this->EnterAuthorizedCeremonyCommit($buffer)) {
            $this->RejectPortalRequest('assertion-revoked');
            return;
        }
        if (!$this->EnterVaultLock()) {
            $this->LeavePortalStateLock();
            $this->SendPortalJson(503, ['ok' => false, 'error' => 'Authentication state is busy. Please try again.']);
            return;
        }
        $createdSession = null;
        try {
            $vaultRevision = null;
            $vaultData = $this->_decryptVaultWithRevision($vaultRevision);
            $current = is_array($vaultData) ? ($vaultData[self::LOCAL_AUTH_KEY][$deviceKey] ?? null) : null;
            if (
                !is_array($current) ||
                $this->GetCredentialCanonicalId($current) !== $credentialId ||
                !hash_equals((string)($current['credentialPublicKey'] ?? ''), (string)$credential['credentialPublicKey']) ||
                (string)($current['rpId'] ?? '') !== $rpId ||
                (string)($current['origin'] ?? '') !== $origin
            ) {
                $this->RejectPortalRequest('assertion-state');
                return;
            }

            $currentCounter = (int)($current['signatureCounter'] ?? 0);
            if ($newCounter !== null && $currentCounter >= (int)$newCounter) {
                $this->RejectPortalRequest('assertion-counter-race');
                return;
            }
            if ($newCounter !== null) {
                $vaultData[self::LOCAL_AUTH_KEY][$deviceKey]['signatureCounter'] = (int)$newCounter;
            }
            $vaultData[self::LOCAL_AUTH_KEY][$deviceKey]['backupEligible'] = $backupEligible;
            $vaultData[self::LOCAL_AUTH_KEY][$deviceKey]['backedUp'] = $backedUp;
            $vaultData[self::LOCAL_AUTH_KEY][$deviceKey]['backupEligibilityVerified'] = true;
            $vaultData[self::LOCAL_AUTH_KEY][$deviceKey]['LastUsedAt'] = time();

            if (!$this->_encryptAndSave($vaultData, $vaultRevision)) {
                $this->SendPortalJson(500, ['ok' => false, 'error' => 'Authentication state could not be saved.']);
                return;
            }

            // The portal lock is still held here. Deleting this credential
            // therefore either happens before the re-read above (and fails
            // authentication) or after this session exists (and removes it).
            $createdSession = $this->CreatePortalSessionStateLocked(
                'passkey',
                ['portal'],
                $origin,
                $deviceKey,
                (int)$buffer['generation']
            );
            if ($createdSession === null) {
                $this->SendPortalJson(500, ['ok' => false, 'error' => 'Authentication session could not be saved.']);
                return;
            }
        } finally {
            $this->LeaveVaultLock();
            $this->LeavePortalStateLock();
        }
        if (!$this->SetPortalSessionCookie($createdSession)) {
            $this->RemovePortalSessionByHash((string)$createdSession['tokenHash']);
            $this->SendPortalJson(500, ['ok' => false, 'error' => 'Authentication cookie could not be created.']);
            return;
        }

        $this->ResetPortalRateLimit('assertion');
        $this->LogMessage('WebAuthn portal authentication succeeded after signature verification.', KL_MESSAGE);
        $this->SendPortalJson(200, [
            'ok'       => true,
            'redirect' => SecretsPortalSecurity::sanitizeReturnUrl((string)($buffer['return'] ?? '/'))
        ]);
    }

    public function IsPortalAuthenticated(): bool
    {
        if (!$this->ReadPropertyBoolean('PortalEnabled')) {
            return false;
        }
        return $this->IsPortalSessionValid(true, ['portal']);
    }

    /**
     * @param string[] $requiredScopes
     * @param string[]|null $allowedMethods
     */
    private function IsPortalSessionValid(bool $requireEnabled, array $requiredScopes = [], ?array $allowedMethods = null): bool
    {
        return $this->GetPortalSessionContext($requireEnabled, $requiredScopes, $allowedMethods) !== null;
    }

    /**
     * Return the validated server-side session plus its token hash. Sessions
     * are scoped so an ordinary portal assertion cannot manage credentials.
     *
     * @param string[] $requiredScopes
     * @param string[]|null $allowedMethods
     * @return array<string, mixed>|null
     */
    private function GetPortalSessionContext(bool $requireEnabled, array $requiredScopes = [], ?array $allowedMethods = null): ?array
    {
        // A failed revocation attempt must block every consumer of portal
        // sessions, including external scripts that call IsPortalAuthenticated.
        // ApplyChanges will retry the generation bump and state purge.
        if ($this->GetBuffer(self::PORTAL_REVOCATION_PENDING_BUFFER) === '1') {
            return null;
        }
        if ($requireEnabled && !$this->ReadPropertyBoolean('PortalEnabled')) {
            return null;
        }

        $profileError = '';
        $profile = $this->GetCurrentPortalProfile($profileError);
        if ($profile === null) {
            return null;
        }

        $tokenHash = $this->GetCurrentPortalSessionTokenHash();
        if ($tokenHash === null || !$this->EnterPortalStateLock()) {
            return null;
        }

        try {
            $sessions = json_decode($this->GetBuffer(self::PORTAL_SESSION_BUFFER), true);
            if (!is_array($sessions)) {
                return null;
            }

            $now = time();
            $changed = false;
            foreach ($sessions as $key => $session) {
                if (!is_array($session) || (int)($session['expires'] ?? 0) <= $now) {
                    unset($sessions[$key]);
                    $changed = true;
                }
            }

            $session = $sessions[$tokenHash] ?? null;
            if ($changed) {
                $this->SetBuffer(self::PORTAL_SESSION_BUFFER, json_encode($sessions));
            }
            if (!$this->PortalSessionMatchesRequirements($session, $profile['origin'], $requiredScopes, $allowedMethods, $now)) {
                return null;
            }

            $session['tokenHash'] = $tokenHash;
            return $session;
        } finally {
            $this->LeavePortalStateLock();
        }
    }

    /**
     * @param mixed $session
     * @param string[] $requiredScopes
     * @param string[]|null $allowedMethods
     */
    private function PortalSessionMatchesRequirements($session, string $origin, array $requiredScopes, ?array $allowedMethods, int $now): bool
    {
        if (
            !is_array($session) ||
            (int)($session['expires'] ?? 0) <= $now ||
            (int)($session['generation'] ?? -1) !== $this->GetPortalRevocationGenerationUnlocked() ||
            !hash_equals((string)($session['origin'] ?? ''), $origin) ||
            !hash_equals((string)($session['userAgentHash'] ?? ''), $this->GetCurrentUserAgentHash())
        ) {
            return false;
        }

        if ($allowedMethods !== null && !in_array((string)($session['method'] ?? ''), $allowedMethods, true)) {
            return false;
        }

        $scopes = $session['scopes'] ?? [];
        if (!is_array($scopes)) {
            return false;
        }
        foreach ($requiredScopes as $scope) {
            if (!in_array($scope, $scopes, true)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param string[] $scopes
     */
    private function CreatePortalSession(string $authenticationMethod, array $scopes, ?string $credentialDeviceKey = null, ?int $expectedGeneration = null): bool
    {
        $profileError = '';
        $profile = $this->GetCurrentPortalProfile($profileError);
        if ($profile === null) {
            return false;
        }

        if (!$this->EnterPortalStateLock()) {
            return false;
        }
        try {
            $createdSession = $this->CreatePortalSessionStateLocked(
                $authenticationMethod,
                $scopes,
                $profile['origin'],
                $credentialDeviceKey,
                $expectedGeneration
            );
        } finally {
            $this->LeavePortalStateLock();
        }

        if ($createdSession === null) {
            return false;
        }
        if (!$this->SetPortalSessionCookie($createdSession)) {
            $this->RemovePortalSessionByHash((string)$createdSession['tokenHash']);
            return false;
        }
        return true;
    }

    /**
     * The caller must hold the portal-state lock.
     *
     * @param string[] $scopes
     * @return array{token:string,tokenHash:string,expires:int,secure:bool}|null
     */
    private function CreatePortalSessionStateLocked(
        string $authenticationMethod,
        array $scopes,
        string $origin,
        ?string $credentialDeviceKey = null,
        ?int $expectedGeneration = null
    ): ?array {
        $generation = $this->GetPortalRevocationGenerationUnlocked();
        if ($expectedGeneration !== null && $generation !== $expectedGeneration) {
            return null;
        }

        $token = SecretsPortalSecurity::base64UrlEncode(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $now = time();
        $expiry = $now + ($this->GetPortalSessionLifetimeMinutes() * 60);
        $sessions = json_decode($this->GetBuffer(self::PORTAL_SESSION_BUFFER), true);
        if (!is_array($sessions)) {
            $sessions = [];
        }
        foreach ($sessions as $key => $session) {
            if (!is_array($session) || (int)($session['expires'] ?? 0) <= $now) {
                unset($sessions[$key]);
            }
        }
        if (count($sessions) >= self::PORTAL_SESSION_MAX_ENTRIES) {
            uasort($sessions, static function (array $a, array $b): int {
                return ((int)($a['expires'] ?? 0)) <=> ((int)($b['expires'] ?? 0));
            });
            $sessions = array_slice($sessions, -(self::PORTAL_SESSION_MAX_ENTRIES - 1), null, true);
        }

        $sessions[$tokenHash] = [
            'expires'             => $expiry,
            'created'             => $now,
            'method'              => $authenticationMethod,
            'scopes'              => array_values(array_unique($scopes)),
            'origin'              => $origin,
            'generation'          => $generation,
            'credentialDeviceKey' => $credentialDeviceKey,
            'userAgentHash'       => $this->GetCurrentUserAgentHash()
        ];
        $encoded = json_encode($sessions);
        if ($encoded === false) {
            return null;
        }
        $this->SetBuffer(self::PORTAL_SESSION_BUFFER, $encoded);

        return [
            'token'     => $token,
            'tokenHash' => $tokenHash,
            'expires'   => $expiry,
            'secure'    => str_starts_with($origin, 'https://')
        ];
    }

    /**
     * @param array{token:string,tokenHash:string,expires:int,secure:bool} $session
     */
    private function SetPortalSessionCookie(array $session): bool
    {
        return setcookie(self::PORTAL_COOKIE_PREFIX . $this->InstanceID, $session['token'], [
            'expires'  => $session['expires'],
            'path'     => '/',
            'secure'   => $session['secure'],
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }

    private function RemovePortalSessionByHash(string $tokenHash): void
    {
        if ($tokenHash === '' || !$this->EnterPortalStateLock()) {
            return;
        }
        try {
            $sessions = json_decode($this->GetBuffer(self::PORTAL_SESSION_BUFFER), true);
            if (!is_array($sessions)) {
                return;
            }
            unset($sessions[$tokenHash]);
            $this->SetBuffer(self::PORTAL_SESSION_BUFFER, (string)json_encode($sessions));
        } finally {
            $this->LeavePortalStateLock();
        }
    }

    private function ClearPortalSessionCookie(): void
    {
        if (!isset($_SERVER['REQUEST_METHOD'])) {
            return;
        }
        $profileError = '';
        $profile = $this->GetCurrentPortalProfile($profileError);
        $secure = $profile === null || str_starts_with($profile['origin'], 'https://');
        setcookie(self::PORTAL_COOKIE_PREFIX . $this->InstanceID, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }

    private function GetPortalSessionLifetimeMinutes(): int
    {
        $minutes = $this->ReadPropertyInteger('PortalSessionLifetimeMinutes');
        return max(5, min(1440, $minutes));
    }

    private function RequirePortalReady(bool $requireEnabled = true): bool
    {
        if ($this->GetBuffer(self::PORTAL_REVOCATION_PENDING_BUFFER) === '1') {
            $this->SendPortalError(503, 'The portal is blocked until pending session revocation completes. Apply the module configuration again.');
            return false;
        }
        if ($requireEnabled && !$this->ReadPropertyBoolean('PortalEnabled')) {
            $this->SendPortalError(503, 'The WebAuthn portal is disabled until credential migration is complete.');
            return false;
        }
        if (PHP_VERSION_ID < 80000 || !extension_loaded('openssl')) {
            $this->SendPortalError(503, 'WebAuthn requires PHP 8.0+ and OpenSSL.');
            return false;
        }

        $error = '';
        if ($this->GetCurrentPortalProfile($error) === null) {
            $this->SendPortalError(503, $error);
            return false;
        }

        return true;
    }

    /**
     * @return array<int, array<string, string>>
     */
    private function GetConfiguredPortalProfiles(string &$error): array
    {
        $error = '';
        $pairs = [
            [
                'name'   => 'primary',
                'origin' => $this->ReadPropertyString('PortalOrigin')
            ],
            [
                'name'   => 'backup',
                'origin' => $this->ReadPropertyString('PortalBackupOrigin')
            ]
        ];

        $profiles = [];
        $authorities = [];
        foreach ($pairs as $index => $pair) {
            $origin = trim((string)$pair['origin']);
            if ($index === 1 && $origin === '') {
                continue;
            }
            if ($origin === '') {
                $error = ucfirst((string)$pair['name']) . ' portal origin is required.';
                return [];
            }

            $parts = parse_url(rtrim($origin, '/'));
            $rpId = is_array($parts) ? strtolower((string)($parts['host'] ?? '')) : '';
            if ($rpId === '') {
                $error = ucfirst((string)$pair['name']) . ' portal origin does not contain a valid hostname.';
                return [];
            }

            $profileError = '';
            $profile = SecretsPortalSecurity::normalizeRpProfile($rpId, $origin, $profileError);
            if ($profile === null) {
                $error = ucfirst((string)$pair['name']) . ' profile: ' . $profileError;
                return [];
            }
            if (isset($authorities[$profile['authority']])) {
                $error = 'Primary and backup portal origins must be different.';
                return [];
            }

            $profile['name'] = (string)$pair['name'];
            $profiles[] = $profile;
            $authorities[$profile['authority']] = true;
        }

        return $profiles;
    }

    /**
     * @return array<string, string>|null
     */
    private function GetCurrentPortalProfile(string &$error): ?array
    {
        $profiles = $this->GetConfiguredPortalProfiles($error);
        if (count($profiles) === 0) {
            if ($error === '') {
                $error = 'No WebAuthn portal profile is configured.';
            }
            return null;
        }

        $profile = SecretsPortalSecurity::selectRpProfile(
            $profiles,
            (string)($_SERVER['HTTP_HOST'] ?? '')
        );
        if ($profile === null) {
            $error = 'This request host is not an explicitly configured WebAuthn portal origin.';
            return null;
        }

        return $profile;
    }

    /**
     * Ensure a one-time ceremony issued for one hostname can never be posted
     * through the other configured hostname.
     *
     * @param array<string, mixed> $challenge
     */
    private function ChallengeMatchesCurrentPortalProfile(array $challenge): bool
    {
        $error = '';
        $profile = $this->GetCurrentPortalProfile($error);
        return $profile !== null &&
            hash_equals($profile['rpId'], (string)($challenge['rpId'] ?? '')) &&
            hash_equals($profile['origin'], (string)($challenge['origin'] ?? ''));
    }

    private function CreateWebAuthnVerifier(string $rpId): \lbuchs\WebAuthn\WebAuthn
    {
        return new \lbuchs\WebAuthn\WebAuthn(
            'Symcon Vault',
            $rpId,
            $this->GetAllowedAttestationFormats(),
            true
        );
    }

    /**
     * @return string[]
     */
    private function GetAllowedAttestationFormats(): array
    {
        return ['none', 'packed', 'apple', 'fido-u2f', 'tpm', 'android-key', 'android-safetynet'];
    }

    /**
     * @return array<string, array{deviceKey:string,data:array<string,mixed>}>
     */
    private function GetVerifiedPortalCredentials(string $rpId, string $origin): array
    {
        $vault = $this->_decryptVault();
        $authData = is_array($vault) ? ($vault[self::LOCAL_AUTH_KEY] ?? []) : [];
        if (!is_array($authData)) {
            return [];
        }

        $result = [];

        foreach ($authData as $deviceKey => $device) {
            if ($deviceKey === '__folder' || !is_array($device)) {
                continue;
            }
            if ((int)($device['schemaVersion'] ?? 0) !== SecretsPortalSecurity::CREDENTIAL_SCHEMA_VERSION) {
                continue; // legacy ID-only registrations fail closed
            }

            // Migrated records retain credentialId in the exact encoding used
            // by the old branch for rollback compatibility. V2 verification
            // addresses the same credential by canonical Base64URL instead.
            $credentialId = $this->GetCredentialCanonicalId($device);
            $publicKey = (string)($device['credentialPublicKey'] ?? '');
            if (
                SecretsPortalSecurity::base64UrlDecode($credentialId) === null ||
                $publicKey === '' ||
                (string)($device['rpId'] ?? '') !== $rpId ||
                (string)($device['origin'] ?? '') !== $origin
            ) {
                continue;
            }

            $result[$credentialId] = [
                'deviceKey' => (string)$deviceKey,
                'data'      => $device
            ];
        }

        return $result;
    }

    /**
     * @return array{verified:int,migratable:int,incompatible:int,otherOrigin:int}
     */
    private function GetPortalCredentialStatus(string $rpId, string $origin): array
    {
        $status = ['verified' => 0, 'migratable' => 0, 'incompatible' => 0, 'otherOrigin' => 0];
        $vault = $this->_decryptVault();
        $authData = is_array($vault) ? ($vault[self::LOCAL_AUTH_KEY] ?? []) : [];
        if (!is_array($authData)) {
            return $status;
        }

        $migratable = $this->GetMigratableLegacyCredentials($rpId);
        $migratableDeviceKeys = [];
        foreach ($migratable as $entry) {
            if (is_array($entry)) {
                $migratableDeviceKeys[(string)($entry['deviceKey'] ?? '')] = true;
            }
        }

        foreach ($authData as $deviceKey => $device) {
            if ($deviceKey === '__folder' || !is_array($device)) {
                continue;
            }
            if ((int)($device['schemaVersion'] ?? 0) === SecretsPortalSecurity::CREDENTIAL_SCHEMA_VERSION) {
                if ((string)($device['rpId'] ?? '') === $rpId && (string)($device['origin'] ?? '') === $origin) {
                    $credentialId = $this->GetCredentialCanonicalId($device);
                    if (
                        $credentialId !== '' &&
                        (string)($device['credentialPublicKey'] ?? '') !== '' &&
                        SecretsPortalSecurity::base64UrlDecode((string)($device['userHandle'] ?? '')) !== null
                    ) {
                        $status['verified']++;
                    } else {
                        $status['incompatible']++;
                    }
                } else {
                    $status['otherOrigin']++;
                }
                continue;
            }

            $registeredHost = strtolower(preg_replace('/:\d+$/D', '', (string)($device['RegisteredHost'] ?? '')) ?? '');
            if ($registeredHost !== '' && $registeredHost !== strtolower($rpId)) {
                $status['otherOrigin']++;
            } elseif (isset($migratableDeviceKeys[(string)$deviceKey])) {
                $status['migratable']++;
            } else {
                $status['incompatible']++;
            }
        }

        return $status;
    }

    /**
     * Extract public keys from legacy attestation objects. These keys are not
     * trusted until VerifyLegacyMigration completes a fresh signed assertion
     * in an admin-authenticated session.
     *
     * @return array<string, array<string, mixed>>
     */
    private function GetMigratableLegacyCredentials(string $rpId): array
    {
        $vault = $this->_decryptVault();
        $authData = is_array($vault) ? ($vault[self::LOCAL_AUTH_KEY] ?? []) : [];
        if (!is_array($authData)) {
            return [];
        }

        if ($rpId === '') {
            return [];
        }
        $expectedRpIdHash = hash('sha256', $rpId, true);
        $result = [];

        foreach ($authData as $deviceKey => $device) {
            if ($deviceKey === '__folder' || !is_array($device)) {
                continue;
            }
            if ((int)($device['schemaVersion'] ?? 0) === SecretsPortalSecurity::CREDENTIAL_SCHEMA_VERSION) {
                continue;
            }

            $storedCredentialId = $this->DecodeLegacyStoredBinary((string)($device['credentialId'] ?? ''));
            $storedAttestation = $this->DecodeLegacyStoredBinary((string)($device['attestation'] ?? ''));
            if ($storedCredentialId === null || $storedAttestation === null) {
                continue;
            }

            try {
                $attestation = new \lbuchs\WebAuthn\Attestation\AttestationObject(
                    $storedAttestation,
                    $this->GetAllowedAttestationFormats()
                );
                if (!$attestation->validateRpIdHash($expectedRpIdHash)) {
                    continue;
                }
                $authenticatorData = $attestation->getAuthenticatorData();
                $attestedCredentialId = (string)$authenticatorData->getCredentialId();
                $publicKey = (string)$authenticatorData->getPublicKeyPem();
                if ($attestedCredentialId === '' || $publicKey === '' || !hash_equals($attestedCredentialId, $storedCredentialId)) {
                    continue;
                }
                $aaguid = (string)$authenticatorData->getAAGUID();
            } catch (Throwable $e) {
                continue;
            }

            $credentialId = SecretsPortalSecurity::base64UrlEncode($attestedCredentialId);
            $result[$credentialId] = [
                'deviceKey'            => (string)$deviceKey,
                'credentialPublicKey'  => $publicKey,
                'attestationFormat'    => (string)$attestation->getAttestationFormatName(),
                'aaguid'               => ($aaguid === '') ? '' : SecretsPortalSecurity::base64UrlEncode($aaguid)
            ];
        }

        return $result;
    }

    private function DecodeLegacyStoredBinary(string $encoded): ?string
    {
        if ($encoded === '' || strlen($encoded) > 131072) {
            return null;
        }

        $standard = base64_decode($encoded, true);
        if ($standard !== false) {
            return $standard;
        }

        return SecretsPortalSecurity::base64UrlDecode($encoded);
    }

    private function GetCredentialCanonicalId(array $credential): string
    {
        $canonical = (string)($credential['credentialIdV2'] ?? '');
        if ($canonical !== '' && SecretsPortalSecurity::base64UrlDecode($canonical) !== null) {
            return $canonical;
        }
        $binary = $this->DecodeLegacyStoredBinary((string)($credential['credentialId'] ?? ''));
        return $binary === null ? '' : SecretsPortalSecurity::base64UrlEncode($binary);
    }

    private function EnterPortalStateLock(): bool
    {
        return IPS_SemaphoreEnter('SymconSecrets.PortalState.' . $this->InstanceID, self::PORTAL_LOCK_WAIT_MILLISECONDS);
    }

    private function LeavePortalStateLock(): void
    {
        IPS_SemaphoreLeave('SymconSecrets.PortalState.' . $this->InstanceID);
    }

    private function EnterVaultLock(): bool
    {
        if ($this->vaultLockDepth > 0) {
            $this->vaultLockDepth++;
            return true;
        }
        if (!IPS_SemaphoreEnter('SymconSecrets.Vault.' . $this->InstanceID, self::PORTAL_LOCK_WAIT_MILLISECONDS)) {
            return false;
        }
        $this->vaultLockDepth = 1;
        return true;
    }

    private function LeaveVaultLock(): void
    {
        if ($this->vaultLockDepth <= 0) {
            return;
        }
        $this->vaultLockDepth--;
        if ($this->vaultLockDepth === 0) {
            IPS_SemaphoreLeave('SymconSecrets.Vault.' . $this->InstanceID);
        }
    }

    private function GetPortalRevocationGenerationUnlocked(): int
    {
        return max(0, (int)$this->GetBuffer(self::PORTAL_REVOCATION_BUFFER));
    }

    private function RevokeAllPortalStateUnlocked(): void
    {
        $this->SetBuffer(self::PORTAL_REVOCATION_BUFFER, (string)($this->GetPortalRevocationGenerationUnlocked() + 1));
        $this->SetBuffer(self::PORTAL_SESSION_BUFFER, '{}');
        $this->SetBuffer(self::PORTAL_CHALLENGE_BUFFER, '{}');
        $this->SetBuffer(self::PORTAL_REVOCATION_PENDING_BUFFER, '0');
    }

    private function GetCurrentUserAgentHash(): string
    {
        return hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    }

    private function GetCurrentPortalSessionTokenHash(): ?string
    {
        $token = (string)($_COOKIE[self::PORTAL_COOKIE_PREFIX . $this->InstanceID] ?? '');
        if ($token === '' || SecretsPortalSecurity::base64UrlDecode($token) === null) {
            return null;
        }
        return hash('sha256', $token);
    }

    /**
     * Store all pending ceremonies in one expiry-pruned, size-bounded buffer.
     * This prevents unauthenticated portal page loads from creating an
     * unbounded number of persistent IP-Symcon buffer names.
     *
     * @param array<string, mixed> $data
     */
    private function StorePortalChallenge(string $purpose, array $data): ?string
    {
        if (!$this->EnterPortalStateLock()) {
            return null;
        }

        $now = time();
        try {
            $challenges = json_decode($this->GetBuffer(self::PORTAL_CHALLENGE_BUFFER), true);
            if (!is_array($challenges)) {
                $challenges = [];
            }

            foreach ($challenges as $key => $entry) {
                if (!is_array($entry) || (int)($entry['expires'] ?? 0) <= $now) {
                    unset($challenges[$key]);
                }
            }

            $bucket = $this->GetPortalChallengeBucket($purpose, $data);
            $bucketLimit = $purpose === 'assertion'
                ? self::PORTAL_ASSERTION_CHALLENGES_PER_ORIGIN
                : self::PORTAL_PRIVILEGED_CHALLENGES_PER_ORIGIN;
            $bucketEntries = [];
            foreach ($challenges as $key => $entry) {
                if (is_array($entry) && (string)($entry['bucket'] ?? '') === $bucket) {
                    $bucketEntries[$key] = $entry;
                }
            }
            uasort($bucketEntries, static function (array $a, array $b): int {
                return ((int)($a['expires'] ?? 0)) <=> ((int)($b['expires'] ?? 0));
            });
            while (count($bucketEntries) >= $bucketLimit) {
                $oldestKey = array_key_first($bucketEntries);
                if ($oldestKey === null) {
                    break;
                }
                unset($bucketEntries[$oldestKey], $challenges[$oldestKey]);
            }
            if (count($challenges) >= self::PORTAL_CHALLENGE_MAX_ENTRIES) {
                return null;
            }

            $sid = SecretsPortalSecurity::base64UrlEncode(random_bytes(16));
            $data['purpose'] = $purpose;
            $data['expires'] = $now + self::PORTAL_CHALLENGE_TTL_SECONDS;
            $data['generation'] = $this->GetPortalRevocationGenerationUnlocked();
            $data['userAgentHash'] = $this->GetCurrentUserAgentHash();
            $data['bucket'] = $bucket;
            $challenges[$sid] = $data;
            $encoded = json_encode($challenges);
            if ($encoded === false) {
                return null;
            }
            $this->SetBuffer(self::PORTAL_CHALLENGE_BUFFER, $encoded);

            return $sid;
        } finally {
            $this->LeavePortalStateLock();
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    private function GetPortalChallengeBucket(string $purpose, array $data): string
    {
        $origin = strtolower((string)($data['origin'] ?? 'unknown'));
        return $purpose . ':' . hash('sha256', $origin);
    }

    /**
     * Consume a ceremony before validating its response. Invalid and replayed
     * assertions therefore cannot retry the same server challenge.
     *
     * @return array<string, mixed>|null
     */
    private function ConsumePortalChallenge(string $sid, string $purpose): ?array
    {
        if (!$this->EnterPortalStateLock()) {
            return null;
        }

        $now = time();
        try {
            $challenges = json_decode($this->GetBuffer(self::PORTAL_CHALLENGE_BUFFER), true);
            if (!is_array($challenges)) {
                return null;
            }

            $selected = $challenges[$sid] ?? null;
            unset($challenges[$sid]);
            foreach ($challenges as $key => $entry) {
                if (!is_array($entry) || (int)($entry['expires'] ?? 0) <= $now) {
                    unset($challenges[$key]);
                }
            }
            $this->SetBuffer(self::PORTAL_CHALLENGE_BUFFER, (string)json_encode($challenges));

            if (
                !is_array($selected) ||
                (string)($selected['purpose'] ?? '') !== $purpose ||
                (int)($selected['expires'] ?? 0) <= $now ||
                (int)($selected['generation'] ?? -1) !== $this->GetPortalRevocationGenerationUnlocked() ||
                !hash_equals((string)($selected['userAgentHash'] ?? ''), $this->GetCurrentUserAgentHash())
            ) {
                return null;
            }

            return $selected;
        } finally {
            $this->LeavePortalStateLock();
        }
    }

    /**
     * Acquire the portal-state lock and revalidate a consumed ceremony just
     * before its durable state change. The caller must release the lock.
     */
    private function EnterAuthorizedCeremonyCommit(array $challenge, string $requiredScope = ''): bool
    {
        if (!$this->EnterPortalStateLock()) {
            return false;
        }

        $valid =
            (int)($challenge['generation'] ?? -1) === $this->GetPortalRevocationGenerationUnlocked() &&
            hash_equals((string)($challenge['userAgentHash'] ?? ''), $this->GetCurrentUserAgentHash());

        if ($valid && $requiredScope !== '') {
            $method = (string)($challenge['authorizationMethod'] ?? '');
            if ($method === 'registration-password' && $requiredScope === 'register') {
                return true;
            }

            $sessionHash = (string)($challenge['authorizationSessionHash'] ?? '');
            $sessions = json_decode($this->GetBuffer(self::PORTAL_SESSION_BUFFER), true);
            $session = is_array($sessions) ? ($sessions[$sessionHash] ?? null) : null;
            $valid = $method === 'admin-password' && $sessionHash !== '' && $this->PortalSessionMatchesRequirements(
                $session,
                (string)($challenge['origin'] ?? ''),
                [$requiredScope],
                ['admin-password'],
                time()
            );
        }

        if (!$valid) {
            $this->LeavePortalStateLock();
        }
        return $valid;
    }

    private function IsJsonRequest(): bool
    {
        return str_contains(strtolower((string)($_SERVER['CONTENT_TYPE'] ?? '')), 'application/json');
    }

    /**
     * @return string|false
     */
    private function ReadRequestBody(int $maxBytes)
    {
        $declaredLength = (string)($_SERVER['CONTENT_LENGTH'] ?? '');
        if ($declaredLength !== '' && ctype_digit($declaredLength) && (int)$declaredLength > $maxBytes) {
            return false;
        }

        $stream = @fopen('php://input', 'rb');
        if ($stream === false) {
            return false;
        }
        try {
            $input = SecretsPortalSecurity::readStreamLimited($stream, $maxBytes);
            return $input === null ? false : $input;
        } finally {
            fclose($stream);
        }
    }

    private function SendPortalSecurityHeaders(string $nonce): void
    {
        header('Cache-Control: no-store, max-age=0');
        header('Pragma: no-cache');
        header('Referrer-Policy: no-referrer');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header("Content-Security-Policy: default-src 'none'; script-src 'nonce-" . $nonce . "'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function SendPortalJson(int $status, array $payload): void
    {
        http_response_code($status);
        $this->SendPortalSecurityHeaders(SecretsPortalSecurity::base64UrlEncode(random_bytes(18)));
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    }

    private function SendPortalError(int $status, string $message): void
    {
        if ($this->IsJsonRequest()) {
            $this->SendPortalJson($status, ['ok' => false, 'error' => $message]);
            return;
        }

        http_response_code($status);
        $nonce = SecretsPortalSecurity::base64UrlEncode(random_bytes(18));
        $this->SendPortalSecurityHeaders($nonce);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecretsManager</title></head><body><h2>SecretsManager</h2><p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p></body></html>';
    }

    /**
     * @param string[] $methods
     */
    private function SendMethodNotAllowed(array $methods): void
    {
        header('Allow: ' . implode(', ', $methods));
        $this->SendPortalError(405, 'Method not allowed.');
    }

    private function RejectPortalRequest(string $reason): void
    {
        $this->LogPortalFailure($reason);
        $this->SendPortalJson(401, ['ok' => false, 'error' => 'Authentication failed. Reload the page and try again.']);
    }

    private function LogPortalFailure(string $reason): void
    {
        $this->LogMessage('WebAuthn portal request rejected. Reason=' . $reason, KL_WARNING);
    }

    private function CheckPortalRateLimit(
        string $bucket,
        bool $consume,
        int $perClientMaximum = self::PORTAL_RATE_MAX_PER_CLIENT,
        int $globalMaximum = self::PORTAL_RATE_MAX_GLOBAL
    ): bool
    {
        $now = time();
        $client = hash('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $origin = hash('sha256', strtolower((string)($_SERVER['HTTP_HOST'] ?? 'unknown')));
        if (!$this->EnterPortalStateLock()) {
            return false;
        }

        try {
            $limits = json_decode($this->GetBuffer(self::PORTAL_RATE_BUFFER), true);
            if (!is_array($limits)) {
                $limits = [];
            }
            foreach ($limits as $key => $entry) {
                if (!is_array($entry) || $now - (int)($entry['started'] ?? 0) >= self::PORTAL_RATE_WINDOW_SECONDS) {
                    unset($limits[$key]);
                }
            }

            $checks = [
                'global:' . $origin . ':' . $bucket => $globalMaximum,
                'client:' . $origin . ':' . $bucket . ':' . $client => $perClientMaximum
            ];

            foreach ($checks as $key => $maximum) {
                $entry = $limits[$key] ?? ['started' => $now, 'count' => 0, 'logged' => false];
                if ((int)$entry['count'] >= $maximum) {
                    if (!(bool)($entry['logged'] ?? false)) {
                        $entry['logged'] = true;
                        $this->LogMessage('Portal rate limit reached. Bucket=' . $bucket, KL_WARNING);
                    }
                    $limits[$key] = $entry;
                    $this->SetBuffer(self::PORTAL_RATE_BUFFER, (string)json_encode($limits));
                    return false;
                }
            }

            if ($consume) {
                $newKeys = 0;
                foreach (array_keys($checks) as $key) {
                    if (!array_key_exists($key, $limits)) {
                        $newKeys++;
                    }
                }
                if (count($limits) + $newKeys > self::PORTAL_RATE_MAX_ENTRIES) {
                    $this->LogMessage('Portal rate-limit state capacity reached.', KL_WARNING);
                    $this->SetBuffer(self::PORTAL_RATE_BUFFER, (string)json_encode($limits));
                    return false;
                }
                foreach ($checks as $key => $maximum) {
                    $entry = $limits[$key] ?? ['started' => $now, 'count' => 0, 'logged' => false];
                    $entry['count'] = (int)$entry['count'] + 1;
                    $limits[$key] = $entry;
                }
            }

            $this->SetBuffer(self::PORTAL_RATE_BUFFER, (string)json_encode($limits));
            return true;
        } finally {
            $this->LeavePortalStateLock();
        }
    }

    private function ResetPortalRateLimit(string $bucket): void
    {
        $client = hash('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $origin = hash('sha256', strtolower((string)($_SERVER['HTTP_HOST'] ?? 'unknown')));
        if (!$this->EnterPortalStateLock()) {
            return;
        }
        try {
            $limits = json_decode($this->GetBuffer(self::PORTAL_RATE_BUFFER), true);
            if (!is_array($limits)) {
                return;
            }
            unset($limits['client:' . $origin . ':' . $bucket . ':' . $client]);
            $globalKey = 'global:' . $origin . ':' . $bucket;
            if (isset($limits[$globalKey]) && is_array($limits[$globalKey])) {
                $limits[$globalKey]['count'] = max(0, (int)($limits[$globalKey]['count'] ?? 0) - 1);
                if ((int)$limits[$globalKey]['count'] === 0) {
                    unset($limits[$globalKey]);
                }
            }
            $this->SetBuffer(self::PORTAL_RATE_BUFFER, (string)json_encode($limits));
        } finally {
            $this->LeavePortalStateLock();
        }
    }

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

    private function NormalizeStoredCredentialEncodings(): void
    {
        if ($this->GetValue('Vault') === '' || !$this->EnterVaultLock()) {
            return;
        }
        try {
            $vaultRevision = null;
            $vault = $this->_decryptVaultWithRevision($vaultRevision);
            if (!is_array($vault)) {
                return;
            }
            if ($this->NormalizeCredentialRecordsForRollback($vault)) {
                $this->_encryptAndSave($vault, $vaultRevision);
            }
        } finally {
            $this->LeaveVaultLock();
        }
    }

    private function NormalizeCredentialRecordsForRollback(array &$vault): bool
    {
        if (!isset($vault[self::LOCAL_AUTH_KEY]) || !is_array($vault[self::LOCAL_AUTH_KEY])) {
            return false;
        }

        $changed = false;
        foreach ($vault[self::LOCAL_AUTH_KEY] as &$credential) {
            if (!is_array($credential) || (int)($credential['schemaVersion'] ?? 0) !== SecretsPortalSecurity::CREDENTIAL_SCHEMA_VERSION) {
                continue;
            }

            $canonical = (string)($credential['credentialIdV2'] ?? '');
            if ($canonical === '') {
                $binary = $this->DecodeLegacyStoredBinary((string)($credential['credentialId'] ?? ''));
                if ($binary === null) {
                    continue;
                }
                $canonical = SecretsPortalSecurity::base64UrlEncode($binary);
            }
            $binary = SecretsPortalSecurity::base64UrlDecode($canonical);
            if ($binary === null) {
                continue;
            }

            $legacy = base64_encode($binary);
            if ((string)($credential['credentialIdV2'] ?? '') !== $canonical) {
                $credential['credentialIdV2'] = $canonical;
                $changed = true;
            }
            if ((string)($credential['credentialId'] ?? '') !== $legacy) {
                $credential['credentialId'] = $legacy;
                $changed = true;
            }
            if ((string)($credential['userHandle'] ?? '') === '') {
                $credential['userHandle'] = isset($credential['MigratedAt'])
                    ? SecretsPortalSecurity::base64UrlEncode('user' . $this->InstanceID)
                    : SecretsPortalSecurity::base64UrlEncode(hash('sha256', 'symcon-vault-owner:' . $this->InstanceID, true));
                $changed = true;
            }
            if (!array_key_exists('backupEligibilityVerified', $credential)) {
                $credential['backupEligibilityVerified'] = !isset($credential['MigratedAt']);
                $changed = true;
            }
        }
        unset($credential);
        return $changed;
    }

    private function _encryptAndSave(array $dataArray, ?string $expectedRevision = null): bool
    {
        if (!$this->EnterVaultLock()) {
            return false;
        }
        try {
            if ($expectedRevision !== null) {
                $currentVaultJson = (string)$this->GetValue('Vault');
                if (!hash_equals($expectedRevision, hash('sha256', $currentVaultJson))) {
                    $this->LogMessage('Vault save rejected because the encrypted state changed concurrently.', KL_WARNING);
                    return false;
                }
            }

        $keyHex = $this->_loadOrGenerateKey();
        if (!$keyHex) return false;

        $this->NormalizeCredentialRecordsForRollback($dataArray);
        $newKeyBin = hex2bin($keyHex);
        $encodedPlain = json_encode($dataArray);
        if ($newKeyBin === false || $encodedPlain === false) {
            return false;
        }
        $plain = str_replace(['"__folder":true,', ',"__folder":true', '"__folder":true'], '', $encodedPlain);

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

        if (!is_string($vaultData) || strlen($vaultData) > self::VAULT_MAX_BYTES) {
            $this->LogMessage('Vault save rejected because the encrypted result exceeds the configured size limit.', KL_WARNING);
            return false;
        }

        $this->SetValue("Vault", $vaultData);

        // (ENTFÄLLT) Disk-clean: kein Klartext-Cache
        // $this->_setCache($dataArray);

            return true;
        } finally {
            $this->LeaveVaultLock();
        }
    }


    private function _decryptVault()
    {
        $vaultJson = $this->GetValue("Vault");
        if (!is_string($vaultJson)) {
            return false;
        }
        return $this->DecryptVaultJson($vaultJson);
    }

    private function _decryptVaultWithRevision(?string &$revision)
    {
        $vaultJson = $this->GetValue("Vault");
        if (!is_string($vaultJson)) {
            $revision = null;
            return false;
        }
        $revision = hash('sha256', $vaultJson);
        return $this->DecryptVaultJson($vaultJson);
    }

    private function DecryptVaultJson(string $vaultJson)
    {
        if ($vaultJson === '' || strlen($vaultJson) > self::VAULT_MAX_BYTES) {
            return false;
        }

        $meta = json_decode($vaultJson, true);
        $keyHex = $this->_readKey();
        if (
            !$keyHex ||
            !is_array($meta) ||
            ($meta['cipher'] ?? '') !== 'aes-128-gcm' ||
            !isset($meta['data'], $meta['iv'], $meta['tag']) ||
            !is_string($meta['data']) ||
            !is_string($meta['iv']) ||
            !is_string($meta['tag']) ||
            preg_match('/^[0-9a-fA-F]{24}$/D', $meta['iv']) !== 1 ||
            preg_match('/^[0-9a-fA-F]{32}$/D', $meta['tag']) !== 1
        ) {
            return false;
        }

        $iv = hex2bin($meta['iv']);
        $tag = hex2bin($meta['tag']);
        $key = hex2bin($keyHex);
        if ($iv === false || $tag === false || $key === false) {
            return false;
        }

        $decrypted = openssl_decrypt($meta['data'], 'aes-128-gcm', $key, 0, $iv, $tag);
        if ($decrypted === false) {
            return false;
        }

        $data = json_decode($decrypted, true);
        if (!is_array($data)) {
            return false;
        }

        $normalize = function (&$item) use (&$normalize): void {
            if (!is_array($item)) {
                return;
            }
            $isFolder = false;
            foreach ($item as &$value) {
                if (is_array($value)) {
                    $isFolder = true;
                    $normalize($value);
                }
            }
            unset($value);
            if ($isFolder || empty($item)) {
                $item['__folder'] = true;
            }
        };
        $normalize($data);

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
