"""Compatibility facade for the modular Telemt iOS endpoint."""
import sys

from . import telemt_ios_fix_console as _implementation

sys.modules[__name__] = _implementation
