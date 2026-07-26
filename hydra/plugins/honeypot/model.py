"""Constants and late-bound infrastructure for Honeypot."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


HONEYPOT_SCRIPT = Path('/usr/local/bin/hydra-honeypot.py')
HONEYPOT_SERVICE = Path('/etc/systemd/system/hydra-honeypot.service')
HONEYPOT_STATE = Path('/var/lib/hydra/honeypot.json')
HONEYPOT_LOG = Path('/var/log/hydra-honeypot.log')
HONEYPOT_LOGROTATE = Path('/etc/logrotate.d/hydra-honeypot')
HONEYPOT_PORT = 9999
_FW_COMMENT = 'hydra-honeypot-ban'
_PORT_COMMENT = 'hydra-honeypot-port'


@dataclass(frozen=True)
class HoneypotEnvironment:
    host: Any
    honeypot_script: Path
    honeypot_service: Path
    honeypot_state: Path
    honeypot_log: Path
    honeypot_logrotate: Path
    honeypot_port: int
    fw_comment: str
    port_comment: str
    copy_module: Any
    ipaddress_module: Any
    json_module: Any
    os_module: Any
    shutil_module: Any
    subprocess_module: Any
    textwrap_module: Any
    time_module: Any
    host_ip_addresses: Callable[[], tuple[str, ...]]
    run: Callable
