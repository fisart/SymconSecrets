# Original-manager comparison branch

Select `diagnostics/old-secret-manager` for the SymconSecrets library to test the previous setup. This branch is based on `feature/secrets-frontend` at d612e52c772beea3c39f7994a2f354169e451ac1. Its original SecretsManager implementation, GUID, prefix, original libraries and all 33 baseline files are unchanged. The sole runtime-file change from that source branch is a test-path reference, not the original manager or native implementation. Migration tooling is moved into `.migration` so Module Control ignores it; test/workflow/documentation paths follow that move.

The original SEC implementation reads the saved old Vault/key files and uses the saved original properties. The separate native backend/frontend modules remain installed with their prior development implementation. Do not delete or recreate instances or import/reset any vault as part of the comparison. If retained original storage/configuration is unavailable, use the saved backup and stop the test until it is restored correctly.

Keep Remote Mirror on `fix/secrets-read-retry-storm` throughout the comparison. Keep secret updates and old replication paused so the two data sets do not diverge. Original administrative and synchronization methods exist again on this diagnostic branch; do not invoke them during the observation window. New writes are never copied back into old storage by changing branches.

Record `IPS_GetKernelStartTime()` before/after any console reconnection. A service uptime over nine days already excludes the reported frequent console reloads being repeated Symcon service restarts. Ignore the one-off console refresh during a module update; compare behavior after the update has settled for several ordinary recurrence intervals. A repeatable difference implicates the changed Secrets setup, without by itself identifying the component responsible.

To return to the native-only implementation, select `migration/legacy-sec-replacement`. Preserve the native vault, keys and original rollback data during both switches. No installation is changed by creating this branch.
