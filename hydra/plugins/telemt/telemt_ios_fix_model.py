"""State model for the Telemt iOS MSS/redirect feature."""
from dataclasses import dataclass
from pathlib import Path

CONFIG_FILE = Path("/etc/telemt/telemt.toml")
STATE_FILE = Path("/var/lib/hydra/telemt_ios_fix.json")
SERVICE_NAME = "telemt"
COMMENT_TAG = "telemt-ios-mss-fix"


@dataclass
class IosFixConfig:
    enabled: bool = False
    ext_port: int = 0
    target_port: int = 0
    mss: int = 92
