"""Build an explicit replacement checkout. Does not contact any Symcon installation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('checkout', type=Path, help='Disposable checkout of this exact development commit')
args = parser.parse_args()
root = args.checkout.resolve()
metadata = json.loads((root/'SecretsManager/module.json').read_text(encoding='utf-8'))
if metadata['id'] != '{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}' or metadata['prefix'] != 'SEC':
    raise SystemExit('Unexpected legacy module identity.')
if subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True).strip():
    raise SystemExit('Use a clean disposable checkout of the reviewed commit.')
original = root/'SecretsManager/module.php'
if 'NativeBackendInstanceID' in original.read_text(encoding='utf-8'):
    raise SystemExit('Already a replacement checkout.')
source = subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
manifest = {'format':'NativeSECReplacement.1','adapterSHA256':hashlib.sha256((root/'migration/templates/SecretsManager.php.txt').read_bytes()).hexdigest(),'oldImplementationEnabled':False,'oldStorageUsed':False,'oldSyncEnabled':False,'sourceCommit':source, 'originalModuleSHA256':hashlib.sha256(original.read_bytes()).hexdigest(), 'guid':metadata['id'], 'prefix':metadata['prefix'], 'activation':'Not activated: a unique ready native backend will be selected and pinned; otherwise select it by name. No old manager fallback exists.', 'rollback':'Restore previous branch AND saved instance configuration; old Vault/key files are retained. New writes do not update old storage.'}
original.write_bytes((root/'migration/templates/SecretsManager.php.txt').read_bytes())
(root/'migration/replacement-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
print('Replacement checkout prepared. No installation, storage, configuration or instance ID was changed.')
