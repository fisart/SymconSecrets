#!/usr/bin/env python3
"""Test-only stdio transport for the real witness; production always uses mTLS HTTPS."""
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("witness_service", Path(__file__).parents[1] / "anchor" / "service.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
directory = sys.argv[1]
if len(sys.argv) == 3:
    result = module.Witness.initialize(directory)
    module.Witness(directory).provision(json.loads(Path(sys.argv[2]).read_text()), "a" * 64)
    print(json.dumps(result))
else:
    sys.stdout.buffer.write(module.Witness(directory).execute(sys.stdin.buffer.read(), "a" * 64))
