"""Filesystem and runtime constants for the Telemt plugin."""
from pathlib import Path

BIN_PATH = Path("/usr/local/bin/telemt")
CONFIG_DIR = Path("/etc/telemt")
CONFIG_FILE = CONFIG_DIR / "telemt.toml"
WORK_DIR = Path("/var/lib/telemt")
SERVICE_FILE = Path("/etc/systemd/system/telemt.service")
SERVICE_NAME = "telemt"
LOG_FILE = Path("/var/log/telemt_install.log")
STATS_CRON_FILE = Path("/etc/cron.d/telemt-stats")
PERFORMANCE_SYSCTL_FILE = Path("/etc/sysctl.d/99-telemt-performance.conf")
PERFORMANCE_LIMITS_FILE = Path("/etc/security/limits.d/99-telemt-limits.conf")

DEFAULT_PORT = 8443
GITHUB_REPO = "telemt/telemt"
