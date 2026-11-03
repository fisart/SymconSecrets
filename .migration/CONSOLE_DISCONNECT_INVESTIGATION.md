# Console disconnect investigation

The test installation's console repeatedly lost its connection on
`migration/legacy-sec-replacement`, while Symcon's kernel uptime continued.
After the corrected `diagnostics/old-secret-manager` branch actually loaded,
the user reported that the console stayed connected. This implicates the
replacement workload; it does not establish a kernel restart or prove the
particular connection timeout mechanism.

## Reproduced regression

At commit `5685e15547182b363098c4543fb47a3f99f11826`, a bound `SEC_GetSecret`
call invoked the full `SECB_GetNativeInfo` diagnostic before its real data
operation. Native store construction, metadata, application validation and
authorization each performed separate locked journal reads. Each journal load
decrypts and verifies the complete snapshot. Every successful application read
also records an authorization audit by publishing an encrypted snapshot.

A disposable synthetic native vault, with 160,000 bytes of application padding
plus normal identity/policy/journal state, produced these counts for 100 reads:

| Measurement | Before | Corrected |
| --- | ---: | ---: |
| Full snapshot loads | 2,600 | 400 |
| Audited snapshot writes | 100 | 100 |
| First measured wall time | 11.52 s | 2.49 s |
| PHP peak allocation | 16 MiB | 12 MiB |

A second run reproduced the counts (14.44 s versus 2.53 s). Wall time depends
on hardware and competing work; tests assert counts instead of timing. These
measurements do not reproduce the live browser disconnection itself. Repeated
vault work and exclusive lock contention are a plausible cause under frequent
RemoteSync/application reads. Audited writes still have a cost.

## Correction

The adapter keeps its automatic backend/vault binding, but checks the expected
vault identity inside the actual backend operation. It no longer calls the
full metadata diagnostic for every bound data call. One store object and one
active snapshot serve application validation, permissions, data access and
auditing within that operation. Storage path and handoff metadata are read
together. No decrypted-value or permission cache persists between calls.

The retry timer also no longer calls the parent ApplyChanges lifecycle. Failed
binding retries back off from 5 to 60 seconds; successful binding stops the
timer. This removes a secondary source of repeated lifecycle work, although the
reported BOUND status does not establish that this timer was active during the
disconnects.

The old implementation remains disabled. Existing SEC IDs/signatures and the
native APIs remain available. Revocation, frozen writes, backend enabled state,
pending settings, pinned identity and runtime fencing are still checked.

## Reproduction and verification

These commands create only disposable test vaults; they never contact a live
Symcon installation or read its secrets:

```sh
python .migration/tests/read-load.py --ref 5685e15547182b363098c4543fb47a3f99f11826
python .migration/tests/read-load.py
python SecretsBackend/tests/native-runtime.py
```

The benchmark instruments load/write counters only in its temporary source
copy. CI checks at most four loads and exactly one audited write per successful
bound read. Actual-module tests cover immediate revocation, changed vault pins,
pending settings, runtime fencing, unchanged calls/IDs, pure JSON failure
responses, startup recovery, retry backoff and absence of lifecycle calls from
reads/retries.

For the live comparison, keep the Remote Mirror version, browser route and
traffic comparable. Update the existing replacement branch and verify it
loaded successfully. Observe for several of the previously reported disconnect
intervals. If the console still disconnects, capture the disconnect timestamp,
kernel start/uptime, ScriptEngine workload and console connection error; do not
classify the issue as resolved based solely on these local tests. The old-manager
diagnostic branch remains available for comparison.
