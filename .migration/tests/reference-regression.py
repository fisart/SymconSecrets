"""Test the pinned old implementation in an isolated CI fixture, then restore the replacement.
The old implementation is never used by the installed module or native backend.
"""
from pathlib import Path
import subprocess
import sys
from replacement_support import original_source, verify_replacement

root = Path(__file__).resolve().parents[2]
entry = root/'SecretsManager/module.php'
replacement = verify_replacement(root)
try:
    entry.write_bytes(original_source(root))
    for name in ['PortalSecurityTest','WebAuthnAssertionTest','ModuleSecurityRegressionTest','ModuleStateTest']:
        subprocess.run(['php',str(root/'tests'/f'{name}.php')],cwd=root,check=True)
finally:
    entry.write_bytes(replacement)
    verify_replacement(root)
print('PASS pinned original security regressions in a temporary test fixture; native-only registered module restored')
