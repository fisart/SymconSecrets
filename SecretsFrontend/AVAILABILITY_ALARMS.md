# Boolean availability alarms

The native replacement branch exposes read-only Boolean variables with the Symcon `~Alert` profile. `true` means unavailable/not ready; `false` means the corresponding check passed. No variable action is enabled and the module sends no notification itself.

| Instance | Display name | Ident | Meaning when true |
|---|---|---|---|
| SecretsBackend | Vault error | `VaultError` | The native vault has not been validated as ready: startup/recovery pending, disabled, uninitialized, pending settings, failed recovery or failed validation. |
| SecretsFrontend | Backend error | `BackendError` | The selected backend cannot be confirmed ready: missing instance/API, non-ready instance status, failed response, unknown/stale heartbeat or reported vault unavailability. |
| SecretsFrontend | Frontend error | `FrontendError` | The frontend is starting, disabled, has pending settings, or its own configuration/setup status is not 102. This does not duplicate backend failure. |

The backend updates VaultError on apply/recovery and its 30-second watchdog. The frontend updates BackendError on its independent 30-second observer. A backend heartbeat older than 90 seconds is rejected at the next observer tick (normally within roughly 120 seconds of the last successful check). FrontendError updates on apply, configuration refresh and observer ticks. Enabled monitoring timers must be running.

All indicators begin as true until validated; disabled instances deliberately remain unavailable. Normal restart/update can briefly assert an alarm. In the alarm system, use a startup grace period or a sustained-true condition, for example two minutes, to avoid messages for an expected short restart. Trigger notifications on transitions into the sustained error state and optionally on recovery. Configure intentional maintenance exclusions in the alarm system.

VaultError is a local last-check result: if its own watchdog stalls, it cannot change itself. Use the independently maintained BackendError to detect a stale backend heartbeat. FrontendError reports local module/configuration readiness, not external HTTPS, DNS, certificates, browser execution or passkey success. A process-wide Symcon outage or a stopped frontend observer needs monitoring from another installation; no Boolean inside a stopped process can update itself.

After updating SymconSecrets on `migration/legacy-sec-replacement`, wait for the next checks and locate these variables below the respective instances. IDs are assigned by Symcon; integrations should discover them by ident with `IPS_GetObjectIDByIdent`. For production121 the backend parent is 18655 and the frontend parent is 29568. All three should be false after healthy startup. This feature does not enable remote-vault secret fallback.

Regression coverage includes startup alarms, successful automatic recovery, vault validation/configuration failures, stale and restored heartbeat, failed backend instance status, missing backend, frontend invalid configuration and repair, pending settings, and disabled/re-enabled frontend.

Additional backend indicators for explicitly configured fallback are FallbackActive, SecretsUnavailable, SynchronizationProblem and ActiveSource. See [Emergency Global access](EMERGENCY_GLOBAL_ACCESS.md) for setup, degraded-service alarm interpretation and node-count behavior.
