import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2]
support = {"libs", "docs", "imgs", "tests", "actions"}
invalid = sorted(p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith(".") and p.name not in support and not (p/"module.json").is_file())
assert not invalid, "Symcon module.json missing: " + ", ".join(invalid)
print("PASS Symcon top-level module/support folder layout")
baseline = json.loads((Path(__file__).parent / "baseline-files.json").read_text())
for name, expected in baseline.items():
    content = (root / name).read_bytes()
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
print(f"PASS {len(baseline)} original repository blobs unchanged; distinct new module IDs, valid JSON and no legacy secret forwarding/browser storage")

# Visible helper directories are treated as modules by Symcon.
assert not (root / "migration").exists(), "Migration helpers must not appear as a module without module.json"
assert (root / ".migration/build-replacement.py").is_file()
