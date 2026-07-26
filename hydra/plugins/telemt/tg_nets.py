"""Compatibility facade for modular Telegram network discovery."""
import sys

from . import tg_nets_console as _implementation

sys.modules[__name__] = _implementation
