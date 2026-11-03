"""Build/test support only. Never imported or executed by Symcon modules."""
import hashlib
import json
from pathlib import Path
import re
import subprocess


def manifest(root):
    return json.loads((Path(root)/'.migration/replacement-manifest.json').read_text(encoding='utf-8'))


def original_source(root):
    root = Path(root)
    m = manifest(root)
    ref = m['sourceCommit']
    if not re.fullmatch(r'[a-f0-9]{40}', ref):
        raise RuntimeError('Invalid pinned reference commit')
    original = subprocess.check_output(['git','-C',str(root),'show',ref+':SecretsManager/module.php'])
    if hashlib.sha256(original).hexdigest() != m['originalModuleSHA256']:
        raise RuntimeError('Original reference hash mismatch')
    return original


def verify_replacement(root):
    root = Path(root)
    m = manifest(root)
    metadata = json.loads((root/'SecretsManager/module.json').read_text(encoding='utf-8'))
    assert metadata['id'] == m['guid'] == '{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}'
    assert metadata['prefix'] == m['prefix'] == 'SEC'
    actual = (root/'SecretsManager/module.php').read_bytes()
    assert actual == (root/'.migration/templates/SecretsManager.php.txt').read_bytes()
    assert hashlib.sha256(actual).hexdigest() == m['adapterSHA256']
    assert m['oldImplementationEnabled'] is False and m['oldStorageUsed'] is False and m['oldSyncEnabled'] is False
    original_source(root)
    return actual
