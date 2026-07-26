"""Compatibility alias for :mod:`hydra.ui.plugin_managers.wdtt`."""
from __future__ import annotations

import sys

from hydra.ui.plugin_managers import wdtt as _implementation


sys.modules[__name__] = _implementation
