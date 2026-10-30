# SecretsBackend

Separate development backend for [SecretsFrontend](../SecretsFrontend/README.md). Module ID `{52165EDD-B2C0-40EC-8A59-42A97319B6E2}`, prefix `SECB`. It creates its own encrypted vault, administrator credentials and external-anchor identity. It never uses the old SecretsManager instance or imports its storage automatically.

Read the [installation and wizard guide](../SecretsFrontend/README.md) and [release gates](../SecretsFrontend/RELEASE_STATUS.md) before enabling it on a test installation.

The `Debug` string variable and `DebugEnabled` switch are registered below every instance. `ExportConfiguration` / `ImportConfiguration` handle only `SECB.Config.v1` settings; private key bytes, vault contents, credentials, sessions and setup/enrollment codes are excluded. Import leaves `Enabled=false`.

`BeginStorageSetup` and `BeginAdminEnrollment` are privileged local console/recovery operations. Only their one-use credentials are entered in the browser. `HandleFrontendRequest` is restricted to the configured new frontend module ID, reciprocal instance binding and protected origin. There is no generic function-name, RPC, PHP or RequestAction forwarding route.

Each protected core contains encrypted vault, identity, policy, pairing, stream, operations and outbox objects. The manifest binds their exact encrypted bytes. An active state plus at most one pending successor is stored in SQLite. The external anchor decides a prepared head; local publication conditionally checks runtime ownership and exact predecessor. A newer runtime fences old workers. Already authorized actions follow the explicit v1.3 completion boundary.

Run local tests from the repository root:

```sh
php SecretsBackend/tests/run.php
php SecretsBackend/tests/interoperability.php
php SecretsFrontend/tests/modules.php
python3 SecretsBackend/tests/anchor_test.py
cd SecretsFrontend/tests
npm ci --ignore-scripts
npm test
```

Python interoperability/service tests require `cryptography` (tested with 50.0.2). Those tests inject a local transport; the production client always uses verified mutual-TLS HTTPS plus a pinned Ed25519 response key. The test-only DELETE journal is not configurable in the installed module.
