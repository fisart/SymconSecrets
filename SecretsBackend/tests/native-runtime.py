"""Development-only runner: supplied crypto, no PDO, bounded PHP memory."""
import argparse
import json
from pathlib import Path
import subprocess

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
subprocess.run(command + ['-r', "if(class_exists('PDO',false)||!function_exists('openssl_encrypt')||!function_exists('sodium_crypto_sign_keypair'))exit(1); echo 'PASS native test runtime: no PDO, supplied OpenSSL/sodium, 32 MiB limit'.PHP_EOL;"], check=True)
for name in ['SecretsBackend/tests/native-store.php', 'SecretsFrontend/tests/native-lifecycle.php', 'SecretsBackend/tests/native-peers.php', 'SecretsBackend/tests/native-effects.php']:
    subprocess.run(command + [str(root / name)], cwd=root, check=True, timeout=90)
