import hashlib
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
# Module Control ignores dot folders and these documented support directories.
# Any other top-level folder is a module and must contain module.json.
def missing_module_metadata(directory):
    support = {"libs", "docs", "imgs", "tests", "actions"}
    return sorted(p.name for p in directory.iterdir()
                  if p.is_dir() and not p.name.startswith(".")
                  and p.name not in support and not (p / "module.json").is_file())

assert not missing_module_metadata(root), "Symcon module.json missing in: " + ", ".join(missing_module_metadata(root))
# Reproduce the reported packaging failure, and verify the corrected dot folder.
import tempfile
with tempfile.TemporaryDirectory(prefix="symcon-layout-") as temporary:
    fixture = Path(temporary)
    (fixture / "migration").mkdir()
    assert missing_module_metadata(fixture) == ["migration"]
    (fixture / "migration").rename(fixture / ".migration")
    for support in ["libs", "docs", "imgs", "tests", "actions"]:
        (fixture / support).mkdir()
    assert missing_module_metadata(fixture) == []
print("PASS Symcon library layout: every module folder has module.json; dot/support folders ignored")
baseline = json.loads((Path(__file__).parent / "baseline-files.json").read_text())
sys.path.insert(0,str(root/'.migration/tests'))
from replacement_support import verify_replacement, original_source, manifest
import subprocess
replacement_files=manifest(root).get("replacementBaselineFiles",{})
assert set(replacement_files).issubset({".github/workflows/portal-navigation.yml"})
verify_replacement(root)
for name, expected in baseline.items():
    if name in replacement_files:
        assert hashlib.sha256((root/name).read_bytes()).hexdigest()==replacement_files[name]
        content=subprocess.check_output(['git','-C',str(root),'show',manifest(root)['sourceCommit']+':'+name])
    else:
        content = original_source(root) if name == 'SecretsManager/module.php' else (root / name).read_bytes()
    actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    assert actual == expected, f"Existing repository file changed: {name}"
for directory in [root / "SecretsFrontend", root / "SecretsBackend"]:
    for file in directory.rglob("*.json"):
        json.loads(file.read_text())
    metadata = json.loads((directory / "module.json").read_text())
    assert metadata["type"] == 3 and metadata["prefix"] in ["SECF", "SECB"]
assert json.loads((root / "SecretsManager/module.json").read_text())["id"] not in [json.loads((root / folder / "module.json").read_text())["id"] for folder in ["SecretsFrontend", "SecretsBackend"]]
for file in [root / "SecretsFrontend/page.html", root / "SecretsFrontend/module.php"]:
    text = file.read_text()
    assert "localStorage" not in text and "sessionStorage" not in text
    assert "SEC_GetSecret" not in text and "SEC_EncryptAndSave" not in text
print(f"PASS {len(baseline)-1-len(replacement_files)} original repository blobs unchanged and exact native-only SEC replacement verified; distinct new module IDs, valid JSON and no legacy secret forwarding/browser storage")
