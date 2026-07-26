"""Compatibility facade for the modular Telemt SYN limiter."""
import sys

from . import telemt_syn_limiter_console as _implementation

sys.modules[__name__] = _implementation
