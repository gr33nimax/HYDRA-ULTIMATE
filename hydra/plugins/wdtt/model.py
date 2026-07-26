"""Constants and dependency environment for the WDTT plugin."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


BIN_PATH = Path("/usr/local/bin/wdtt-server")
CONFIG_DIR = Path("/etc/wdtt")
CONFIG_FILE = CONFIG_DIR / "config.json"
PASSWORDS_FILE = CONFIG_DIR / "passwords.json"
SERVICE_FILE = Path("/etc/systemd/system/wdtt.service")
SERVICE_NAME = "wdtt"

DEFAULT_DTLS_PORT = 56000
DEFAULT_WG_PORT = 56001
DEFAULT_WG_SUBNET = "10.66.66.0/16"
WG_INTERFACE = "wdtt0"
WG_STATS_DIR = Path(f"/sys/class/net/{WG_INTERFACE}/statistics")
LOCAL_TUN_PORT = 9000
SYSTEM_PASSWORD = "hydra-system-wdtt"

GITHUB_REPO = "SpaceNeuroX/proxy-turn-vk-android"
SOURCE_URL = (
    f"https://github.com/{GITHUB_REPO}/archive/refs/heads/master.tar.gz"
)
GO_DL_URL = "https://go.dev/dl/"

SOURCE_EXTRACT_TIMEOUT = 120
GO_MODULE_TIMEOUT = 600
GO_BUILD_TIMEOUT = 900


@dataclass(frozen=True)
class WdttRuntimeObservation:
    """Immutable facts read from the WDTT host runtime."""

    installed: bool
    running: bool
    dtls_port: int = DEFAULT_DTLS_PORT
    wg_port: int = DEFAULT_WG_PORT
    main_password: str = SYSTEM_PASSWORD
    admin_id: str = ""
    bot_token: str = ""


@dataclass(frozen=True)
class WdttEnvironment:
    """Late-bound plugin infrastructure used to preserve facade patch seams."""

    host: Any
    bin_path: Path
    config_dir: Path
    config_file: Path
    passwords_file: Path
    service_file: Path
    service_name: str
    default_dtls_port: int
    default_wg_port: int
    default_wg_subnet: str
    wg_interface: str
    wg_stats_dir: Path
    local_tun_port: int
    system_password: str
    github_repo: str
    source_url: str
    go_dl_url: str
    source_extract_timeout: int
    go_module_timeout: int
    go_build_timeout: int
    json_module: Any
    os_module: Any
    platform_module: Any
    re_module: Any
    shutil_module: Any
    tempfile_module: Any
    time_module: Any
    urllib_module: Any
    firewall_module: Any
    local_ip: Callable[[], str]
    public_ip: Callable[[], str]
