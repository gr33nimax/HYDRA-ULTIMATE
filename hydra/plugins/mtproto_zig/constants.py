"""Hydra-owned runtime locations for mtproto.zig."""

from pathlib import Path

NAME = "mtproto_zig"
SERVICE_NAME = "mtproto-zig"
SERVICE_USER = "mtproto-zig"
BIN_PATH = Path("/usr/local/bin/mtproto-zig")
CONFIG_DIR = Path("/etc/hydra-mtproto-zig")
CONFIG_FILE = CONFIG_DIR / "config.toml"
WORK_DIR = Path("/var/lib/hydra/mtproto-zig")
TOTALS_FILE = WORK_DIR / "traffic-totals.json"
SERVICE_FILE = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
GITHUB_REPO = "sleep3r/mtproto.zig"
INTERNAL_PORT = 20449
PUBLIC_PORT = 443
METRICS_PORT = 9400
ROUTE_KEY = "_tls_passthrough_route"
WEB_ROUTE_KEY = "_tls_terminated_route"
WEB_RELAY_PORT = 8081
WEB_SERVICE_NAME = "mtproto-zig-web"
WEB_SERVICE_FILE = Path(f"/etc/systemd/system/{WEB_SERVICE_NAME}.service")
WEB_MODES = ("off", "hybrid", "web-only")
WEB_WS_PATH = "/api/v1/socket"
