"""Compatibility alias for :mod:`hydra.ui.plugin_managers.dnscrypt`."""
from __future__ import annotations

import sys

from hydra.ui.plugin_managers import dnscrypt as _implementation


sys.modules[__name__] = _implementation
