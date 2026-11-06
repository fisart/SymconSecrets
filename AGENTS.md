# Standing development requirements

All new modules and relevant configuration changes must follow the configuration backup requirements agreed with Artur Fischer on 6 November 2026: [configuration-backup-requirements.md](.docs/configuration-backup-requirements.md).

Provide versioned native configuration export and read-only importer validation through `ExportConfigurationBackup` and `ValidateConfigurationBackup`. Keep the format version separate from code versions, share validation with the real importer, include required configuration attributes, exclude vault contents and private keys, and retain all provisioning/security protections. Compatible software updates must not require a change in the backup module. Source fingerprints alone are informational.

Test read-only behavior, export/import format parity, required-field rejection, safe import behavior and secret exclusion. Use isolated test instances; never test by restoring a live installation. Keep the native-only replacement branch synchronized for shared module API changes, preserving its SEC replacement and original module identity.
