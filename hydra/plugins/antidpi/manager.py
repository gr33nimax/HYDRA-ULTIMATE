"""Compatibility alias for :mod:`hydra.ui.plugin_managers.antidpi`."""
from __future__ import annotations

import sys

from hydra.ui.plugin_managers import antidpi as _implementation


sys.modules[__name__] = _implementation
