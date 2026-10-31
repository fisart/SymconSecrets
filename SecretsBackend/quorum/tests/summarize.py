"""Record component evidence without promoting it to end-to-end acceptance."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
source = Path(sys.argv[1])
destination = Path(sys.argv[2])
rows = [json.loads(line) for line in source.read_text().splitlines()] if source.exists() else []
fault_source = Path(sys.argv[3]) if len(sys.argv) > 3 else None
fault_rows = [json.loads(line) for line in fault_source.read_text().splitlines() if line.startswith('{')] if fault_source and fault_source.exists() else []
tests = []
packages = []
for row in rows:
    if row.get("Action") not in ["pass", "fail", "skip"]:
        continue
    record = {key: row[key] for key in ["Package", "Test", "Action", "Elapsed"] if key in row}
    (tests if "Test" in row else packages).append(record)
passed = bool(packages) and all(p["Action"] != "fail" for p in packages)
fault_packages = [row for row in fault_rows if row.get('Action') in ['pass','fail'] and 'Test' not in row]
fault_passed = bool(fault_packages) and all(row['Action'] == 'pass' for row in fault_packages)
passed = passed and fault_passed
try:
    version = subprocess.check_output(["go", "version"], text=True).strip()
except (OSError, subprocess.CalledProcessError):
    version = "NOT_RECORDED"
files = {}
for path in sorted(root.rglob("*")):
    if path.is_file() and path.suffix in [".go", ".mod", ".sum", ".json", ".py", ".txt"]:
        files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
report = {
    "evidenceClass": "COMPONENT_AND_LOOPBACK_PROCESS_FAILURE_TESTS_ONLY",
    "implementationCommit": os.environ.get("SOURCE_IMPLEMENTATION_COMMIT", os.environ.get("GITHUB_SHA", "LOCAL_WORKTREE_SEE_FILE_HASHES")),
    "testedCheckoutCommit": os.environ.get("GITHUB_SHA", "LOCAL_WORKTREE_SEE_FILE_HASHES"),
    "profileSha256": hashlib.sha256((root / "protocol/profile.json").read_bytes()).hexdigest(),
    "goVersion": version,
    "etcdVersion": "v3.7.3",
    "transport": "Loopback plaintext in test harness; not production TLS/proxy evidence",
    "result": "PASS" if passed else "FAILED_OR_INCOMPLETE",
    "packages": packages,
    "testResults": tests,
    "injectedIOFailures": {"result": "PASS" if fault_passed else "FAILED_OR_INCOMPLETE", "packages": fault_packages, "testResults": [row for row in fault_rows if row.get('Action') in ['pass','fail','skip'] and 'Test' in row]},
    "formalAcceptance": {f"Q{i:02}": "NOT_RUN_END_TO_END" for i in range(1, 49)},
    "limitations": [
        "No Symcon quorum runtime or browser end-to-end execution",
        "No real hardware-key, TLS/proxy or independent host-guard qualification",
        "No end-to-end core lifecycle/authorization/GC, sync, OAuth or migration acceptance",
        "SIGKILL and fsync fault hooks do not emulate storage-controller power loss",
        "Authority host trust/admission and fencing remain deployment prerequisites",
    ],
    "codeSha256": files,
}
destination.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"result": report["result"], "testResults": len(tests), "packages": len(packages), "commit": report["implementationCommit"]}))
if not passed:
    raise SystemExit(1)
