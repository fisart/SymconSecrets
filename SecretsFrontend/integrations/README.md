# Integration handoff — no existing module files changed

The owner explicitly requested the new modules and integrations while prohibiting changes to other modules and the existing password module. Portal exposes an existing `AdditionalPages` configuration mechanism, so the new frontend provides `AddToPortal` without changing Portal code.

The reviewed Dokumentation and ConfigurationBackup versions have **fixed** catalogs/registries. There is no dynamic provider-registration API that a new module can safely call. These files make the remaining changes reviewable without violating the instruction:

- `dokumentation.catalog-entry.json`: proposed page entry for `SystemDocumentation/catalog.json`; copy the module guide to `SystemDocumentation/manuals/secrets-frontend.md` when that content change is authorized.
- `configuration-backup.contract.json`: both module IDs, prefixes, configuration schemas, field inventories, export/import APIs, exclusions and disabled-on-import behavior. The current central backup module needs reviewed native adapters plus registry/source-contract entries. A property-only restore is not equivalent to these guarded importers.

Until those explicit registration/adapter changes are authorized and tested, central documentation/backup activation is **pending**, not silently reported as complete. The new modules' own import/export and bundled guide already work. There are no startup scripts that edit another module's source or registry on disk.
