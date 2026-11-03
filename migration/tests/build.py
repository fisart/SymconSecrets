"""Exercise replacement preparation and rollback using only disposable code fixtures."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parents[2]
builder = source/'migration/build-replacement.py'
with tempfile.TemporaryDirectory(prefix='secrets-replacement-test-') as directory:
    root = Path(directory)
    for relative in ['SecretsManager/module.json','SecretsManager/module.php','migration/templates/SecretsManager.php.txt']:
        path = root/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((source/relative).read_bytes())
    def git(*args):
        return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
    git('init','-q')
    git('config','user.name','Replacement fixture')
    git('config','user.email','fixture@example.invalid')
    git('config','core.autocrlf','false')
    git('add','.')
    git('commit','-qm','Immutable fixture')
    commit = git('rev-parse','HEAD')
    original = (root/'SecretsManager/module.php').read_bytes()
    metadata = (root/'SecretsManager/module.json').read_bytes()
    subprocess.run([sys.executable,str(builder),str(root)],check=True,capture_output=True)
    manifest = json.loads((root/'migration/replacement-manifest.json').read_text())
    assert manifest['sourceCommit'] == commit
    assert manifest['originalModuleSHA256'] == hashlib.sha256(original).hexdigest()
    assert manifest['prefix'] == 'SEC'
    assert (root/'SecretsManager/module.json').read_bytes() == metadata
    assert (root/'SecretsManager/module.php').read_bytes() == (source/'migration/templates/SecretsManager.php.txt').read_bytes()
    assert git('diff','--name-only') == 'SecretsManager/module.php'
    assert git('ls-files','--others','--exclude-standard') == 'migration/replacement-manifest.json'
    assert subprocess.run([sys.executable,str(builder),str(root)],capture_output=True).returncode != 0
    git('restore','SecretsManager/module.php')
    (root/'migration/replacement-manifest.json').unlink()
    assert (root/'SecretsManager/module.php').read_bytes() == original
    assert git('status','--porcelain') == ''
    (root/'SecretsManager/module.php').write_text('dirty checkout')
    assert subprocess.run([sys.executable,str(builder),str(root)],capture_output=True).returncode != 0
print('PASS replacement builder: exact commit/hash, unchanged GUID/prefix, isolated code-only diff, dirty/repeat refusal and byte-identical code rollback')
