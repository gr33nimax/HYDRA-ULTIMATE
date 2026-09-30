"""Production entrypoint for the managed-node mTLS control API."""

from __future__ import annotations

import os
import sys

from hydra.bootstrap import production_node_reconciler
from hydra.core.host import HOST
from hydra.core.node_identity import load_node_identity
from hydra.services.nodes.firewall import apply_control_firewall
from hydra.services.nodes.transport import create_control_server


def main() -> int:
    if os.name != "nt" and os.geteuid() != 0:
        print("Node control API requires root", file=sys.stderr)
        return 2
    identity = load_node_identity()
    if identity is None:
        print("Node control API requires a provisioned identity", file=sys.stderr)
        return 2

    try:
        apply_control_firewall(identity, host=HOST)
    except Exception:
        print("Node control firewall could not be applied", file=sys.stderr)
        return 2

    operations = production_node_reconciler(identity.node_id)
    server = create_control_server(identity, operations, port=identity.control_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
