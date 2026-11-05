"""Measure full snapshot work in disposable copies; no live vault or network access.

Use --ref 5685e15547182b363098c4543fb47a3f99f11826 to reproduce the regression.
Wall time is informational; assertions use operation counts, not machine speed.
"""
import argparse
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--php', default='php')
parser.add_argument('--ref')
parser.add_argument('--reads', type=int, default=100)
args = parser.parse_args()
assert 1 <= args.reads <= 1000
root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='sec-read-load-') as directory:
    fixture = Path(directory)
    if args.ref:
        commit = subprocess.check_output(['git', 'rev-parse', '--verify', args.ref + '^{commit}'], cwd=root, text=True).strip()
        archive = subprocess.check_output(['git', 'archive', commit], cwd=root)
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(fixture, filter='data')
    else:
        files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
        for name in files:
            if name and (root / name).is_file():
                target = fixture / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / name, target)
    # The same harness tests either implementation; instrumentation exists only in this copy.
    target = fixture / '.migration/tests/read-load.php'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / '.migration/tests/read-load.php', target)
    store = fixture / 'SecretsBackend/NativeStore.php'
    source = store.read_text(encoding='utf-8')
    for method, counter, signature in [('load', 'loadProbe', 'bool $allowEmpty'), ('save', 'saveProbe', '')]:
        needle = f'private function {method}({signature}): void\n    {{'
        assert source.count(needle) == 1
        source = source.replace(needle, needle + f" $GLOBALS['{counter}']=($GLOBALS['{counter}']??0)+1;")
    store.write_text(source, encoding='utf-8')
    result = subprocess.run([args.php, '-d', 'memory_limit=32M', str(target)], cwd=fixture,
                            env={**os.environ, 'SEC_BENCH_READS': str(args.reads)},
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    measurement = json.loads(result.stdout)
    if not args.ref:
        assert measurement['snapshotLoads'] <= 4 * args.reads, measurement
        assert measurement['snapshotWrites'] == 0, 'Successful local application reads must not publish vault snapshots'
    print(json.dumps({'implementation': args.ref or 'working-tree', **measurement}))
