"""Shared AntiDPI filesystem locations without facade dependencies."""
from pathlib import Path


NAIVE_ACCESS_LOG = Path("/var/log/caddy-naive/access.log")


__all__ = ["NAIVE_ACCESS_LOG"]
