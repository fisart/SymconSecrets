"""IR-02: narrow Go build overlays; production files never gain fault switches."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import re

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
source = root / "durable/directory.go"
before = source.read_bytes()
text = before.decode()
hooks = {
    "func (d *Directory) Sync() error {": """func (d *Directory) Sync() error {
 IRDirCalls++
 if IRFailDir && IRDirCalls >= IRDirAfter { return syscall.EIO }
""",
    "func (d *Directory) syncFile(f *os.File) error {": """func (d *Directory) syncFile(f *os.File) error {
 IRFileCalls++
 if IRFailFile && IRFileCalls >= IRFileAfter { return syscall.EIO }
""",
    "func (d *Directory) rename(from, to string) error {": """func (d *Directory) rename(from, to string) error {
 if IRFailRename { return syscall.EIO }
""",
}
for needle, replacement in hooks.items():
    expression = re.escape(needle).replace(r"\ ", r"\s+")
    pattern = re.compile(expression)
    assert len(pattern.findall(text)) == 1, needle
    text = pattern.sub(lambda _: replacement, text, count=1)
text += """
var IRFailDir, IRFailFile, IRFailRename bool
var IRDirCalls, IRFileCalls int
var IRDirAfter, IRFileAfter int
func IRReset(){IRFailDir=false;IRFailFile=false;IRFailRename=false;IRDirCalls=0;IRFileCalls=0;IRDirAfter=0;IRFileAfter=0}
"""
with tempfile.TemporaryDirectory(prefix="symcon-ir02-") as folder:
    folder = Path(folder)
    overlay_source = folder / "directory.go"
    overlay_source.write_text(text)
    replacements = {str(source): str(overlay_source)}
    for package in ["trust", "durable", "core"]:
        replacements[str(root / package / "ir_io_overlay_test.go")] = str(root / "tests" / f"io_faults_{package}.go.txt")
    overlay = folder / "overlay.json"
    overlay.write_text(json.dumps({"Replace": replacements}))
    output = Path(args.output).resolve()
    with output.open("w") as log:
        result = subprocess.run(["go", "test", "-race", "-count=1", "-timeout=3m", "-json", "-overlay", str(overlay), "-run", "^TestIR", "./trust", "./durable", "./core"], cwd=root, stdout=log, stderr=subprocess.STDOUT)
assert source.read_bytes() == before, "Fault overlay changed tracked source"
rows = [json.loads(line) for line in output.read_text().splitlines() if line.startswith("{")]
failures = [row for row in rows if row.get("Action") == "fail"]
print(json.dumps({"result": "PASS" if result.returncode == 0 else "FAIL", "passingTestEvents": sum(row.get("Action") == "pass" and "Test" in row for row in rows), "sourceSha256": hashlib.sha256(before).hexdigest(), "productionSourcesUnchangedByOverlay": True}))
if result.returncode:
    for row in rows:
        if row.get("Action") == "output": print(row.get("Output", ""), end="")
raise SystemExit(result.returncode)
