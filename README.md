# SymconSecrets
A secure credential manager for IP-Symcon that encrypts secrets using AES-128-GCM with external key storage and automated Master-Slave replication.

SymconSecrets is a security module designed to protect sensitive data (API keys, passwords, user credentials) within IP-Symcon. Unlike standard variables, secrets are stored as encrypted blobs using AES-128-GCM, with the decryption key isolated on the OS file system (or USB stick). It features a Master-Slave architecture, allowing you to manage secrets centrally and automatically push updates to multiple IP-Symcon installations without exposing credentials in cleartext backups or the management console.
Key Features List (Optional add-on)
Zero-Knowledge Storage: Passwords are never stored in settings.json in cleartext.
Hardware Separation: Master encryption keys are stored outside the IP-Symcon environment.
Automated Sync: Push updates from a Master server to multiple Slave instances via secure WebHooks.
In-Memory Caching: High-performance decryption for scripts with RAM buffering.
Flexible Input: Supports arbitrary JSON structures for complex credentials.
