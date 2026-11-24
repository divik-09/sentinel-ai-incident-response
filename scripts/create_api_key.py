"""Generate an API key and the matching SENTINEL_API_KEYS entry.

    python scripts/create_api_key.py alice approver

Prints the raw key ONCE (give it to the user) and the 'name:role:sha256' entry to put in SENTINEL_API_KEYS.
Only the hash is ever configured on the server.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.config import ROLES, hash_api_key


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in ROLES:
        print(f"usage: create_api_key.py <name> <{'|'.join(ROLES)}>", file=sys.stderr)
        return 2
    name, role = sys.argv[1], sys.argv[2]
    if not name.replace("-", "").replace("_", "").isalnum():
        print("name must be alphanumeric (dashes/underscores allowed)", file=sys.stderr)
        return 2
    raw = "snt_" + secrets.token_urlsafe(32)
    print(f"API key (shown once, store it in a secret manager):\n  {raw}\n")
    print("Add this entry to SENTINEL_API_KEYS (comma-separated):\n  " + f"{name}:{role}:{hash_api_key(raw)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
