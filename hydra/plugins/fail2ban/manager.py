"""Compatibility alias for :mod:`hydra.ui.plugin_managers.fail2ban`."""
from __future__ import annotations

import sys

from hydra.ui.plugin_managers import fail2ban as _implementation


sys.modules[__name__] = _implementation
