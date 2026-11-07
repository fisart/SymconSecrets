"""Development-only runner: supplied crypto, no database drivers, bounded PHP memory."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--php', default='php')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
extension_dir = subprocess.check_output([args.php, '-r', "echo ini_get('extension_dir');"], text=True).strip()
command = [args.php, '-n', '-d', 'extension_dir=' + extension_dir, '-d', 'memory_limit=32M']
probe = json.loads(subprocess.check_output(command + ['-r', "echo json_encode(['openssl'=>function_exists('openssl_encrypt'),'sodium'=>function_exists('sodium_crypto_sign_keypair')]);"], text=True))
for extension, present in probe.items():
    if not present:
        command += ['-d', 'extension=' + extension]
# Windows PHP can compile PDO's core into the executable; it cannot be unloaded.
# Prohibit every database driver, and record whether that inert core is present.
subprocess.run(command + ['-r', "$pdo=class_exists('PDO',false); $drivers=$pdo?PDO::getAvailableDrivers():[]; echo json_encode(['pdoCore'=>$pdo,'databaseDrivers'=>$drivers,'openssl'=>function_exists('openssl_encrypt'),'sodium'=>function_exists('sodium_crypto_sign_keypair')]).PHP_EOL; if(extension_loaded('pdo_sqlite')||$drivers||!function_exists('openssl_encrypt')||!function_exists('sodium_crypto_sign_keypair'))exit(1); echo 'PASS native test runtime: no database drivers, supplied OpenSSL/sodium, 32 MiB limit'.PHP_EOL;"], check=True)
subprocess.run([sys.executable, str(root / 'SecretsBackend/tests/trust-cleanup.py'), args.php], cwd=root, check=True, timeout=30)
for name in ['SecretsFrontend/tests/native-http.php', 'SecretsBackend/tests/audit-remediation.php', 'SecretsBackend/tests/audit-oauth.php', 'SecretsBackend/tests/monitoring-freshness.php', 'SecretsFrontend/tests/configuration-backup.php', 'SecretsBackend/tests/availability.php', '.migration/tests/preflight.php', 'SecretsBackend/tests/legacy-api.php', 'SecretsBackend/tests/legacy-peers.php', 'SecretsFrontend/tests/bootstrap-security.php', 'SecretsFrontend/tests/setup-address-console.php', 'SecretsFrontend/tests/setup-purpose.php', 'SecretsFrontend/tests/form-call-arguments.php', 'SecretsFrontend/tests/connect-discovery.php', 'SecretsFrontend/tests/connect-transport.php', 'SecretsFrontend/tests/connect-lifecycle.php', 'SecretsFrontend/tests/full-connect.php', 'SecretsFrontend/tests/full-connect-upgrade-console.php', 'SecretsFrontend/tests/full-connect-upgrade-passkey.php', 'SecretsFrontend/tests/magic-initial-setup.php', 'SecretsFrontend/tests/legacy-import.php', 'SecretsBackend/tests/backup-origin-policy.php', 'SecretsBackend/tests/native-store.php', 'SecretsBackend/tests/native-trust.php', 'SecretsBackend/tests/native-issuers.php', 'SecretsBackend/tests/native-legacy-https.php', 'SecretsFrontend/tests/native-lifecycle.php', 'SecretsFrontend/tests/request-diagnostics.php', 'SecretsFrontend/tests/automatic-setup.php', 'SecretsBackend/tests/peer-work.php', 'SecretsBackend/tests/automatic-setup.php', 'SecretsBackend/tests/automatic-mesh.php', 'SecretsFrontend/tests/folder-editor.php', 'SecretsFrontend/tests/pairing-wizard.php', 'SecretsBackend/tests/native-peers.php', 'SecretsBackend/tests/shared-global.php', 'SecretsBackend/tests/shared-global-peers.php', 'SecretsBackend/tests/full-peer-routes.php', 'SecretsBackend/tests/native-health.php', 'SecretsBackend/tests/mesh-status.php', 'SecretsBackend/tests/mailbox.php', 'SecretsBackend/tests/peer-names.php', 'SecretsBackend/tests/support-report.php', 'SecretsBackend/tests/mesh-consistency.php', 'SecretsBackend/tests/emergency-access.php', 'SecretsFrontend/tests/emergency-runtime.php', 'SecretsBackend/tests/native-effects.php']:
    if name in ['SecretsBackend/tests/native-legacy-https.php']:
        print('SKIP retired-manager integration: ' + name + '; native-only replacement rejects old TLS discovery',flush=True)
        continue
    # The four-vault fixture publishes many fsynced encrypted journals; Windows
    # runner storage needs more time than the ordinary single-vault checks.
    timeout = 300 if name in ['SecretsBackend/tests/automatic-setup.php','SecretsBackend/tests/automatic-mesh.php'] else 90
    subprocess.run(command + [str(root / name)], cwd=root, check=True, timeout=timeout)

subprocess.run([sys.executable, str(root / '.migration/tests/build.py')], cwd=root, check=True, timeout=30)
subprocess.run([sys.executable, str(root / '.migration/tests/read-load.py'), '--php', args.php, '--reads', '30'], cwd=root, check=True, timeout=120)

subprocess.run([sys.executable, str(root / 'SecretsBackend/tests/peer-status-load.py'), '--php', args.php], cwd=root, check=True, timeout=120)
