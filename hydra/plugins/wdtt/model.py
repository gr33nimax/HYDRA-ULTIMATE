"""Constants and dependency environment for the WDTT plugin."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


BIN_PATH = Path("/usr/local/bin/wdtt-server")
CONFIG_DIR = Path("/etc/wdtt")
CONFIG_FILE = CONFIG_DIR / "config.json"
PASSWORDS_FILE = CONFIG_DIR / "passwords.json"
ACCESS_FILE = CONFIG_DIR / "hydra-access.json"
HEADLESS_DIR = CONFIG_DIR / "headless"
HEADLESS_COOKIES_DIR = Path("/etc/hydra/cookiesvk")
HEADLESS_COOKIES_FILE = HEADLESS_COOKIES_DIR / "cookies-vk.json"
HEADLESS_LINK_FILE = CONFIG_DIR / "qwdtt_link.txt"
HEADLESS_STATE_FILE = HEADLESS_DIR / "state.json"
HEADLESS_BIN_PATH = Path("/usr/local/bin/headless-vk-creator")
SERVICE_FILE = Path("/etc/systemd/system/wdtt.service")
HEADLESS_SERVICE_FILE = Path(
    "/etc/systemd/system/wdtt-headless-creator@.service"
)
SERVICE_NAME = "wdtt"
HEADLESS_CALL_COUNT = 4
HEADLESS_GITHUB_REPO = "kulikov0/whitelist-bypass"

DEFAULT_DTLS_PORT = 56000
DEFAULT_WG_PORT = 56001
DEFAULT_WG_SUBNET = "10.66.66.0/16"
WG_INTERFACE = "wdtt0"
WG_STATS_DIR = Path(f"/sys/class/net/{WG_INTERFACE}/statistics")
LOCAL_TUN_PORT = 9000
SYSTEM_PASSWORD = "hydra-system-wdtt"

GITHUB_REPO = "gr33nimax/hydra-wdtt"
SOURCE_REVISION = "ecea643c2c14fcb9328fbe8836c6f711d3af6147"
SOURCE_URL = f"https://github.com/{GITHUB_REPO}/archive/{SOURCE_REVISION}.tar.gz"
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
    access_file: Path
    headless_dir: Path
    headless_cookies_file: Path
    headless_link_file: Path
    headless_state_file: Path
    headless_bin_path: Path
    headless_service_file: Path
    headless_call_count: int
    headless_github_repo: str
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
    source_revision: str = SOURCE_REVISION
