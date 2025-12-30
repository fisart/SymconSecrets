<?php

declare(strict_types=1);

class SecretsManager extends IPSModuleStrict {

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

        $isUnlocked = false; // stateless editor

        // Build slave URL options for credential editor
        $slaveOptions = [];
        $slaves = json_decode($this->ReadPropertyString("SlaveURLs"), true);
        if (is_array($slaves)) {
            foreach ($slaves as $s) {
                $u = trim((string)($s['Url'] ?? ''));
                if ($u !== '') {
                    $slaveOptions[] = ['caption' => $u, 'value' => $u];
                }
            }
        }
        if (count($slaveOptions) === 0) {
            $slaveOptions[] = ['caption' => '(no slaves configured)', 'value' => ''];
        }

        foreach ($json['elements'] as &$element) {
            $name = $element['name'] ?? '';

            if ($name === 'HookInfo') {
                $element['caption'] = "WebHook URL für diesen Slave: /hook/secrets_" . $this->InstanceID;
                $element['visible'] = $isSlave;
            }

            if (in_array($name, ['LabelHookAuth', 'HookUser'])) {
                $element['visible'] = $isSlave;
            }

            // NEW: HookPassInput + SaveHookPass button only on Slave
            if (in_array($name, ['HookPassInput', 'BtnSaveHookPass'])) {
                $element['visible'] = $isSlave;
            }

            // NEW: AuthToken input/buttons for Master+Slave (sync role)
            if (in_array($name, ['AuthTokenInput', 'BtnGenToken', 'BtnShowToken', 'BtnSaveAuthToken'])) {
                $element['visible'] = $isSyncRole;
            }

            // Master only: slave list + slave password editor
            if (in_array($name, ['SlaveURLs', 'LabelSeparator', 'LabelMasterHead', 'PanelSlaveCreds'])) {
                $element['visible'] = $isMaster;
            }

            // Fill options for slave credential select
            if ($name === 'SlaveCredUrl') {
                $element['options'] = $slaveOptions;
            }

            // Editor workflow
            if (in_array($name, ['BtnLoad', 'InputJson', 'BtnEncrypt', 'BtnClear', 'LabelSecurityWarning'])) {
                $element['visible'] = $isEditorRole ? $isUnlocked : false;
                if ($name === 'BtnLoad') {
                    $element['visible'] = ($isEditorRole && !$isUnlocked);
                }
            }

            // AllowKeyTransport toggle only on Slave
            if ($name === 'AllowKeyTransport') {
                $element['visible'] = $isSlave;
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



    public function SaveAuthToken(string $token): void
    {
        $token = trim($token);
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


    public function ApplyChanges(): void {
        parent::ApplyChanges();

        // 1. Variable im Baum verstecken
        $vaultID = @$this->GetIDForIdent("Vault");
        if ($vaultID) {
            IPS_SetHidden($vaultID, true);
        }

        // 2. Aktuelle Rolle prüfen
        $mode = $this->ReadPropertyInteger("OperationMode");

        // Nur Slave registriert Hook
        if ($mode === 0) {
            @$this->RegisterHook("secrets_" . $this->InstanceID);
        }

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
    public function UpdateUI(): void {
        $this->UpdateFormLayout("");
    }

    /**
     * Internal helper to update static UI elements like Error Headers
     */
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
    // CONFIGURATION ACTIONS (Called by Buttons)
    // =========================================================================

    public function CheckDirectory(): void {
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


    public function ShowToken(): void {
        $token = $this->ReadPropertyString("AuthToken");
        echo ($token === "") ? "No token set." : "YOUR SYNC TOKEN:\n\n" . $token . "\n\n(Select text and Ctrl+C to copy)";
    }

    // =========================================================================
    // EDITOR ACTIONS (Load / Save / Wipe)
    // =========================================================================

    public function LoadVault(): void {
        $cache = $this->_decryptVault();
        
        if ($cache === false) {
            $json = ($this->GetValue("Vault") === "") ? "{}" : "";
            if ($json === "") {
                echo "❌ Fehler: Entschlüsselung fehlgeschlagen.";
                return;
            }
        } else {
            $json = json_encode($cache, JSON_PRETTY_PRINT);
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
    public function EncryptAndSave(string $jsonInput): void {
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

    public function ClearVault(): void {
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
            $k = (string)$k;
            return (strpos($k, "__") !== 0);
        }));

        return json_encode($keys);
    }



    public function GetSecret(string $ident): string {
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
        return (is_array($val) || is_object($val)) ? (json_encode($val) ?: "") : (string)$val;
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

        $token = $this->getAuthToken();
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

        $sys = $this->loadSystemSecrets();
        $slavePassMap = (isset($sys['slaves']) && is_array($sys['slaves'])) ? $sys['slaves'] : [];

        $successCount = 0;
        $totalSlaves  = 0;

        foreach ($slaves as $slave) {
            $url = trim((string)($slave['Url'] ?? ''));
            if ($url === '') continue;
            $totalSlaves++;

            $tlsMode      = (string)($slave['TlsMode'] ?? 'strict');        // http | strict | pinned
            $fpExp        = (string)($slave['Fingerprint'] ?? '');
            $keyTransport = (string)($slave['KeyTransport'] ?? 'manual');   // manual | sync

            if ($tlsMode === 'http' && $keyTransport === 'sync') {
                $this->LogMessage("❌ Sync blocked: KeyTransport=sync not allowed with HTTP for $url", KL_ERROR);
                continue;
            }

            $payloadArr = [
                'auth'  => $token,
                'vault' => $vault
            ];
            if ($keyTransport === 'sync') {
                $payloadArr['key'] = $keyHex;
            }
            $payload = json_encode($payloadArr);

            $headers = ['Content-Type: application/json'];

            // Optional Basic Auth (per slave): User from list, Pass from system.vault
            $user = trim((string)($slave['User'] ?? ''));
            if ($user !== '') {
                $pass = (string)($slavePassMap[$url] ?? '');
                if ($pass === '') {
                    $this->LogMessage("❌ Sync blocked: BasicAuth user set but no password stored for $url", KL_ERROR);
                    continue;
                }
                $headers[] = 'Authorization: Basic ' . base64_encode($user . ':' . $pass);
            }

            try {
                if ($tlsMode === 'http') {
                    $result = $this->httpPostJson($url, $payload, $headers);
                } elseif ($tlsMode === 'strict') {
                    $result = $this->httpsPostJsonStrict($url, $payload, $headers);
                } elseif ($tlsMode === 'pinned') {
                    if (trim($fpExp) === '') throw new Exception("Pinned mode requires Fingerprint.");
                    $result = $this->httpsPostJsonPinned($url, $payload, $headers, $fpExp);
                } else {
                    throw new Exception("Unknown TLS mode: " . $tlsMode);
                }

                $statusLine = (string)($result['status'] ?? 'Unknown Status');
                $body = trim((string)($result['body'] ?? ''));

                $ok = (strpos($statusLine, '200') !== false && $body === 'OK');
                $kt = ($keyTransport === 'sync') ? "key=sent" : "key=manual";

                if ($ok) {
                    $successCount++;
                    $this->LogMessage("✅ Sync OK [$tlsMode, $kt] $url", KL_MESSAGE);
                } else {
                    $respShort = $body;
                    if (strlen($respShort) > 180) $respShort = substr($respShort, 0, 180) . "...";
                    $this->LogMessage("❌ Sync FAIL [$tlsMode, $kt] $url | $statusLine | " . ($respShort ?: '(no body)'), KL_ERROR);
                }

            } catch (Throwable $e) {
                $kt = ($keyTransport === 'sync') ? "key=sent" : "key=manual";
                $this->LogMessage("❌ Sync EXC  [$tlsMode, $kt] $url | " . $e->getMessage(), KL_ERROR);
            }
        }

        if ($totalSlaves === 0) {
            $this->LogMessage("Sync aborted: No valid slave URLs found.", KL_WARNING);
            return;
        }

        $level = ($successCount === $totalSlaves) ? KL_MESSAGE : KL_WARNING;
        $this->LogMessage("Sync summary: $successCount / $totalSlaves successful.", $level);
    }
    



    private function httpPostJson(string $url, string $payload, array $headers): array {
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
    private function httpsPostJsonStrict(string $url, string $payload, array $headers): array {
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

    private function httpsPostJsonPinned(string $url, string $payload, array $headers, string $expectedFingerprint): array {
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


    private function normalizeFingerprint(string $fp): string {
    $fp = strtolower($fp);
    // erlaubt Eingaben mit ":" oder Leerzeichen – wir nehmen nur hex
    $fp = preg_replace('/[^0-9a-f]/', '', $fp) ?? '';
    return $fp;
}

    private function certSha256Fingerprint($x509Cert): string {
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

/**
     * WEBHOOK DATA PROCESSING
     * This is called by IP-Symcon when data is posted to /hook/secrets_ID
     */
    protected function ProcessHookData(): void
    {
        if ($this->ReadPropertyInteger("OperationMode") !== 0) {
            header("HTTP/1.1 403 Forbidden");
            echo "Access Denied: This instance is not configured as a Slave.";
            $this->LogMessage("Unauthorized WebHook access attempt: Instance is not a Slave.", KL_WARNING);
            return;
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header("HTTP/1.1 405 Method Not Allowed");
            echo "Only POST requests are allowed.";
            return;
        }

        $expectedToken = $this->getAuthToken();
        if ($expectedToken === "") {
            header("HTTP/1.1 500 Internal Server Error");
            echo "Slave not configured: missing auth token";
            $this->LogMessage("WebHook Error: Slave has no AuthToken in encrypted system file.", KL_ERROR);
            return;
        }

        // Optional Basic Auth: HookUser from property, HookPass from system.vault
        $hookUser = trim($this->ReadPropertyString("HookUser"));
        $hookPass = $this->getHookPass(); // from encrypted system file

        if ($hookUser !== "" && $hookPass !== "") {
            if (!isset($_SERVER['PHP_AUTH_USER']) ||
                $_SERVER['PHP_AUTH_USER'] !== $hookUser ||
                ($_SERVER['PHP_AUTH_PW'] ?? '') !== $hookPass)
            {
                header('WWW-Authenticate: Basic realm="SecretsManager"');
                header('HTTP/1.0 401 Unauthorized');
                echo 'Authentication Required';
                return;
            }
        } elseif ($hookUser !== "" && $hookPass === "") {
            // Misconfig warning: user set but pass missing -> BasicAuth effectively OFF
            $this->LogMessage("Warning: HookUser set but HookPass missing in system file. BasicAuth not enforced.", KL_WARNING);
        }

        $data = json_decode(file_get_contents("php://input"), true);

        if (!isset($data['auth']) || $data['auth'] !== $expectedToken) {
            header("HTTP/1.1 403 Forbidden");
            echo "Invalid Sync Token";
            $this->LogMessage("WebHook Error: Received an invalid or missing Sync Token.", KL_ERROR);
            return;
        }

        if (isset($data['key'])) {
            $allow = $this->ReadPropertyBoolean("AllowKeyTransport");
            if ($allow) {
                $this->_writeKey((string)$data['key']);
                $this->LogMessage("Key received via sync and written (AllowKeyTransport=true).", KL_MESSAGE);
            } else {
                $this->LogMessage("Key received via sync but ignored (AllowKeyTransport=false).", KL_WARNING);
            }
        }

        if (isset($data['vault'])) {
            $this->SetValue("Vault", (string)$data['vault']);
        }

        echo "OK";
    }
 


    // =========================================================================
    // INTERNAL CRYPTO HELPERS
    // =========================================================================

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
            'iv'     => bin2hex($iv),
            'tag'    => bin2hex($tag),
            'data'   => $cipherText
        ]);

        $this->SetValue("Vault", $vaultData);

        // (ENTFÄLLT) Disk-clean: kein Klartext-Cache
        // $this->_setCache($dataArray);

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

    private function _readKey() {
        return $this->_loadOrGenerateKey();
    }

    private function _writeKey(string $hexKey): void {
        $path = $this->_getFullPath();
        if ($path !== "") {
            file_put_contents($path, $hexKey);
        }
    }
}
?>