"""Compatibility alias for :mod:`hydra.ui.plugin_managers.ipban`."""
from __future__ import annotations

import sys

from hydra.ui.plugin_managers import ipban as _implementation


sys.modules[__name__] = _implementation
