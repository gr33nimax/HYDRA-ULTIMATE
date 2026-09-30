"""SSH-only bounded cookie import; no paths, shell commands or pool mutations."""
from __future__ import annotations

import json
import os
import sys

from hydra.bootstrap import production_node_cookie_import
from hydra.core.node_identity import load_node_identity
from hydra.services.nodes.cookies import MAX_NODE_COOKIE_BYTES, cookie_request


def main() -> int:
    if os.name != "nt" and os.geteuid() != 0:
        print("Node cookie import requires root", file=sys.stderr)
        return 2
    try:
        identity = load_node_identity()
        if identity is None:
            raise ValueError("node identity is missing")
        raw = sys.stdin.read(MAX_NODE_COOKIE_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_NODE_COOKIE_BYTES:
            raise ValueError("cookie request exceeds the supported size")
        node_id, cookies = cookie_request(json.loads(raw))
        if node_id != identity.node_id:
            raise ValueError("cookie import node identity does not match")
        production_node_cookie_import(cookies)
    except Exception:
        # Neither JSON content nor SDK error text may expose VK credentials.
        print("Node VK cookie import failed", file=sys.stderr)
        return 2
    print("Node VK cookies imported; call pool unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
