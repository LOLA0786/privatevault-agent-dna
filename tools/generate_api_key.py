#!/usr/bin/env python3
"""Generate a pilot API key. Prints the key ONCE; stores only its hash.

Usage: python3 tools/generate_api_key.py <name> [keys_file]
Appends the hash to keys_file (default: data/api_keys.json).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent_dna.apikeys import generate_key  # noqa: E402

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(2)

name = sys.argv[1]
path = Path(sys.argv[2] if len(sys.argv) > 2 else "data/api_keys.json")
path.parent.mkdir(parents=True, exist_ok=True)

entry = generate_key(name)
existing = json.loads(path.read_text()) if path.exists() else {}
existing[entry["hash"]] = name
path.write_text(json.dumps(existing, indent=2))

print(f"API key for {name!r} (shown ONCE, store it now):\n\n  {entry['key']}\n")
print(f"hash appended to {path}")
