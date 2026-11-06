# Standing requirements for IP-Symcon module configuration backups

Decision owner: Artur Fischer. Agreed 6 November 2026. Applies to future module development and relevant updates to existing modules.

## User requirement

Warn only when there is a specific, reasonable doubt that the captured configuration can be restored. A changed commit, software version, source fingerprint, or an unfamiliar implementation is not by itself a restore warning. Compatible module updates must not require changes to the configuration backup module.

## Module responsibilities

1. Provide public `ExportConfigurationBackup(): string` and `ValidateConfigurationBackup(string $JSON): string` functions through the normal Symcon module prefix. Discovery uses `IPS_GetModule(ModuleID)['Prefix']`; no central source whitelist or per-version registration is required.
2. Own the complete configuration export, including required configuration attributes, drafts and mappings. The export must be the same native format accepted by the module's ordinary configuration importer. Do not duplicate the export definition in the backup module.
3. Version the configuration format independently from software releases. Keep existing formats importable when practical; perform explicit, validated migrations when a format changes. Additions that the exporter and importer already understand must require no backup-module update.
4. Keep export and validation read-only: no property/attribute writes, ApplyChanges, UI changes, timers, filesystem writes, network calls, device commands, vault unlock, or import execution. Validation must use the same parser and validation logic as the real importer.
5. Include every setting required for configuration restoration. Explicitly identify intentional exclusions and restore behavior. Secrets configuration excludes vault records, private key bytes, credentials, sessions and runtime state. The encrypted vault backup is a separate recovery artifact; its intentional exclusion is informational.
6. Reject missing mandatory fields, invalid types or unsupported formats. Never silently discard new required settings or falsely report complete coverage. Validation replies and report metadata must not contain configuration values, credentials or raw exception text.
7. Respect security controls during real import: restore with automation disabled where appropriate; retain provisioning and trust protections. Configuration validation is not permission to bypass them.
8. At restore time, check target dependencies, object mappings, provisioning restrictions and relevant storage paths. A format check at backup time does not establish readiness of a future replacement installation.

## Wire format v1

`ExportConfigurationBackup` returns a JSON object with exactly these fields:

| Field | Meaning |
|---|---|
| `schema` | `Symcon.ConfigurationBackup.v1` |
| `moduleID` | Uppercase module GUID |
| `format` | Native configuration format identifier; independent of code version |
| `payload` | Native configuration JSON object, directly usable with the ordinary native importer |
| `sourceHash` | SHA-256 of canonical JSON of `{properties: raw IPS_GetConfiguration object, attributes: declared configuration attribute values}` |
| `attributeNames` | Names of configuration attributes included in sourceHash; absent saved attributes are treated as empty strings |
| `restoreMode` | `manual-native-import` in this implementation; the backup service never invokes an unfamiliar importer automatically |
| `exclusions` | List of intentional excluded data categories |
| `notes` | Short operational notes without configuration values |

Canonical JSON recursively sorts object keys, preserves array order and zero fractions, and uses unescaped Unicode and slashes. Source identity here means captured configuration identity, not a code fingerprint. It binds the module export to the saved settings generation.

`ValidateConfigurationBackup` receives the native payload JSON, not the export envelope. It returns `schema: Symcon.ConfigurationBackupValidation.v1`, Boolean `valid`, `scope: format`, `payloadHash` (SHA-256 of canonical native payload), and string lists `issues`, `checks`, `notes`. A valid result has no issues. Bind the answer to the exact payload, so a response for another backup cannot establish compatibility.

## Backup module responsibilities

- Prefer module-owned export and validation when available, including modules absent from the legacy registry. Validate the envelope, module identity, configuration-generation binding, size limits and validator response.
- Keep useful exported data when format validation fails, and report the specific restore risk. Report omitted configurations separately from properties-only captures.
- For modules awaiting the new interface, retain legacy extraction and safe configuration schemas. Label the verification level honestly. Source fingerprint changes are information; actual missing data, incompatible value types, rejected formats or missing restore mechanisms are actionable risks.
- Retain file-integrity checks, authenticated encryption, private GitHub destinations, retention, recovery copies and restore concurrency guards. A source change after an approved restore preview invalidates that preview; this is a concurrency safeguard, not a daily backup warning.
- Distinguish configuration coverage/validation, an actual isolated restore test, and backup delivery. Never label schema validation as a successful restore test. GitHub upload failure must be shown separately from restore coverage.
- Never restore production modules automatically just to test a backup. Use an isolated fixture or explicitly selected test installation.

## Warning and failure criteria

Warnings require evidence: missing required configuration; known importer/schema incompatibility; a failed validation or isolated restore test; a missing required dependency on the intended target; or an incomplete export. Include the instance, consequence and remedy without leaking values. An export or storage failure must be explicit and must not overwrite an earlier good generation with a falsely successful result.

An unfamiliar source fingerprint, no full restore test yet, documented safe disable-on-import behavior, intentional vault-content exclusion, or a cosmetic/code update alone is not a restore warning. Information may explain the verification limits without raising an alert.

## Required development verification

- Export equals native configuration export and includes declared configuration attributes.
- Export and validation leave module properties, attributes, UI, timers, files and vault state unchanged.
- Normal updates and supported new configuration fields work without backup-module changes.
- Missing fields, incompatible types, unsupported formats and validator rejection produce specific failures/risks.
- Source-hash mismatch waits for current saved settings; wrong module IDs, wrong payload hashes and malformed metadata fail safely.
- Secret canaries never appear in reports or intentionally excluded data.
- Test real import on isolated instances where possible, including documented safe normalization such as Enabled=false. Record format checks separately from actual restore evidence.

## Adoption in this change

The configuration backup module supports automatic protocol discovery and legacy fallback. Secrets frontend and backend implement the read-only interface using their existing native parsers. Other legacy modules retain structural/schema validation until they adopt the interface. This is not a claim that every legacy importer has been independently tested against every future software release.
