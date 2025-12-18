# SymconSecrets
A secure credential manager for IP-Symcon that encrypts secrets using AES-128-GCM with external key storage and automated Master-Slave replication.

SymconSecrets is a security module designed to protect sensitive data (API keys, passwords, user credentials) within IP-Symcon. Unlike standard variables, secrets are stored as encrypted blobs using AES-128-GCM, with the decryption key isolated on the OS file system (or USB stick). It features a Master-Slave architecture, allowing you to manage secrets centrally and automatically push updates to multiple IP-Symcon installations without exposing credentials in cleartext backups or the management console.
Key Features List (Optional add-on)
Zero-Knowledge Storage: Passwords are never stored in settings.json in cleartext.
Hardware Separation: Master encryption keys are stored outside the IP-Symcon environment.
Automated Sync: Push updates from a Master server to multiple Slave instances via secure WebHooks.
In-Memory Caching: High-performance decryption for scripts with RAM buffering.
Flexible Input: Supports arbitrary JSON structures for complex credentials.

# SymconSecrets

A secure credential manager for IP-Symcon that encrypts secrets using AES-128-GCM. It features a Master-Slave architecture to distribute secrets automatically to multiple IP-Symcon installations without exposing them in cleartext.

## Features
*   **Zero-Knowledge Storage:** Passwords are stored as encrypted blobs (AES-128-GCM).
*   **Hardware Separation:** The Master Key is stored on the OS file system (e.g., USB stick), not in the database.
*   **Auto-Sync:** Master instance pushes updates to Slave instances via WebHooks.
*   **In-Memory Caching:** High performance decryption for scripts.

## Requirements
*   IP-Symcon 6.0 or higher
*   PHP 7.4 or higher with OpenSSL extension

## Setup

### 1. Master Configuration
1.  Create an instance of **SecretsManager**.
2.  Set Role to **Master**.
3.  Enter a local path for the Key File (e.g., `/var/lib/symcon_keys/` on Linux or Docker mount).
4.  Generate a **Sync Token**.
5.  Paste your secrets as a JSON object into the input field and click **Encrypt**.

### 2. Slave Configuration
1.  Create an instance on the remote system.
2.  Set Role to **Slave**.
3.  Enter a local path for the Key File (must be writable).
4.  Paste the **same Sync Token** as the Master.
5.  Copy the **WebHook URL** displayed in the configuration.

### 3. Connection
1.  Go back to the Master.
2.  Add the Slave's WebHook URL to the "Slave WebHooks" list.
3.  Click **Manually Sync to Slaves**.

## PHP Usage

To retrieve a password in your scripts:

```php
$instanceID = 12345; // Your SecretsManager Instance ID
Returns a String : $password = SEC_GetSecret($instanceID, $key);

Returns a Array : $password = json_decode(SEC_GetSecret($instanceID, $key), true);

Return all keys : $keys = SEC_GetKeys($instanceID); // Returns JSON string


