"""Compatibility facade for modular Telemt statistics."""
import sys

from . import mtproto_stats_console as _implementation

sys.modules[__name__] = _implementation
