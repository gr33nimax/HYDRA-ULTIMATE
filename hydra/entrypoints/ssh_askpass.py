"""OpenSSH askpass entrypoint: hand one password to ssh, then exit."""

from __future__ import annotations

import sys

from hydra.services.nodes.ssh_auth import run_askpass


def main() -> int:
    return run_askpass()


if __name__ == "__main__":
    sys.exit(main())
