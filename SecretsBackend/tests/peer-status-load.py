"""Count full-vault I/O for signed status requests in an isolated source copy."""
import argparse
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--php', default='php')
parser.add_argument('--ref')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
# -n disables DLL extensions on Windows. Load only the supplied crypto, just
# like the main database-free native runner; never inherit a PDO driver.
extension_dir = subprocess.check_output([args.php, '-r', "echo ini_get('extension_dir');"], text=True).strip()
command = [args.php, '-n', '-d', 'extension_dir=' + extension_dir, '-d', 'memory_limit=32M']
probe = json.loads(subprocess.check_output(command + ['-r', "echo json_encode(['openssl'=>function_exists('openssl_encrypt'),'sodium'=>function_exists('sodium_crypto_sign_keypair')]);"], text=True))
for extension, present in probe.items():
    if not present:
        command += ['-d', 'extension=' + extension]
subprocess.run(command + ['-r', "if(!function_exists('openssl_encrypt')||!function_exists('sodium_crypto_sign_keypair')||(class_exists('PDO',false)&&PDO::getAvailableDrivers()))exit(1);"], check=True)

with tempfile.TemporaryDirectory(prefix='sec-peer-status-') as directory:
    fixture = Path(directory)
    if args.ref:
        archive = subprocess.check_output(['git', 'archive', args.ref], cwd=root)
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(fixture, filter='data')
    else:
        for folder in ['SecretsBackend', 'SecretsFrontend', 'SecretsManager']:
            shutil.copytree(root / folder, fixture / folder,
                            ignore=shutil.ignore_patterns('node_modules', '__pycache__', 'quorum'))
    shutil.copyfile(root / 'SecretsBackend/tests/peer-status-load.php', fixture / 'SecretsBackend/tests/peer-status-load.php')
    store = fixture / 'SecretsBackend/NativeStore.php'
    source = store.read_text(encoding='utf-8')
    for method, counter, signature in [('load', 'loadProbe', 'bool $allowEmpty'), ('save', 'saveProbe', '')]:
        needle = f'private function {method}({signature}): void\n    {{'
        assert source.count(needle) == 1
        source = source.replace(needle, needle + f" $GLOBALS['{counter}']=($GLOBALS['{counter}']??0)+1;")
    store.write_text(source, encoding='utf-8')
    result = subprocess.run(command + [str(fixture / 'SecretsBackend/tests/peer-status-load.php')],
                            cwd=fixture, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    measurement = json.loads(result.stdout)
    if not args.ref:
        for request in measurement['requests']:
            assert request['loads'] <= 2, request
            assert request['writes'] <= (1 if request['kind'] == 'SETUP_HELLO' else 0), request
    print(json.dumps({'implementation': args.ref or 'working-tree', **measurement}))
