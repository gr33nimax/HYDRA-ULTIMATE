"""Runtime locations and protocol defaults for the NaiveProxy plugin."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


BIN_PATH = Path("/usr/local/bin/caddy-naive")
CFG_DIR = Path("/etc/caddy-naive")
CADDYFILE = CFG_DIR / "Caddyfile"
LOG_DIR = Path("/var/log/caddy-naive")
FAKE_SITE_DIR = Path("/var/www/naive-fake")
SERVICE_FILE = Path("/etc/systemd/system/caddy-naive.service")
SERVICE_NAME = "caddy-naive"

DEFAULT_PORT = 443
GITHUB_REPO = "Michaol/caddy-naive"
DATA_DIR = Path("/var/lib/caddy-naive")
DOWNLOAD_DIR = Path("/tmp/caddy-naive-install")


@dataclass(frozen=True)
class NaiveRuntimeLayout:
    """Patchable filesystem and process settings resolved by the facade."""

    binary: Path
    config_dir: Path
    caddyfile: Path
    log_dir: Path
    fake_site_dir: Path
    service_file: Path
    service_name: str
    default_port: int
    github_repo: str
