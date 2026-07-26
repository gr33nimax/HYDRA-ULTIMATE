"""State model and policy presets for the Telemt SYN limiter."""
from dataclasses import dataclass
from pathlib import Path

CONFIG_FILE = Path("/etc/telemt/telemt.toml")
STATE_FILE = Path("/var/lib/hydra/telemt_syn_limiter.json")
COMMENT_TAG = "telemt-syn-limit"
HASHLIMIT_NAME = "telemt_syn"


@dataclass
class SynLimiterConfig:
    enabled: bool = False
    port: int = 0
    rate_per_sec: int = 1
    burst: int = 1
    htable_expire_ms: int = 60000
    preset_name: str = "hard"


PRESETS = {
    "1": ("hard", 1, 1, "Жёсткий", "1/sec burst 1", True),
    "2": ("medium", 1, 3, "Средний", "1/sec burst 3", False),
    "3": ("soft", 2, 5, "Мягкий", "2/sec burst 5", False),
}
