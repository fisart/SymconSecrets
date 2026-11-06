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
for name in ['SecretsFrontend/tests/configuration-backup.php', 'SecretsBackend/tests/legacy-api.php', 'SecretsBackend/tests/legacy-peers.php', 'SecretsFrontend/tests/bootstrap-security.php', 'SecretsFrontend/tests/setup-address-console.php', 'SecretsFrontend/tests/setup-purpose.php', 'SecretsFrontend/tests/form-call-arguments.php', 'SecretsFrontend/tests/connect-discovery.php', 'SecretsFrontend/tests/connect-transport.php', 'SecretsFrontend/tests/connect-lifecycle.php', 'SecretsFrontend/tests/full-connect.php', 'SecretsFrontend/tests/full-connect-upgrade-console.php', 'SecretsFrontend/tests/full-connect-upgrade-passkey.php', 'SecretsFrontend/tests/magic-initial-setup.php', 'SecretsFrontend/tests/legacy-import.php', 'SecretsBackend/tests/backup-origin-policy.php', 'SecretsBackend/tests/native-store.php', 'SecretsBackend/tests/native-trust.php', 'SecretsBackend/tests/native-issuers.php', 'SecretsBackend/tests/native-legacy-https.php', 'SecretsFrontend/tests/native-lifecycle.php', 'SecretsFrontend/tests/folder-editor.php', 'SecretsFrontend/tests/pairing-wizard.php', 'SecretsBackend/tests/native-peers.php', 'SecretsBackend/tests/shared-global.php', 'SecretsBackend/tests/shared-global-peers.php', 'SecretsBackend/tests/full-peer-routes.php', 'SecretsBackend/tests/native-health.php', 'SecretsBackend/tests/native-effects.php']:
    subprocess.run(command + [str(root / name)], cwd=root, check=True, timeout=90)

subprocess.run([sys.executable, str(root / '.migration/tests/build.py')], cwd=root, check=True, timeout=30)
