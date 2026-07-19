"""Typed errors crossing HYDRA's host, configuration and plugin boundaries."""
from __future__ import annotations


class HydraError(RuntimeError):
    """Base class for expected HYDRA operational failures."""


class HostOperationError(HydraError):
    """A bounded command or privileged host operation failed."""


class ConfigurationError(HydraError):
    """Configuration could not be generated, validated or applied."""


class PluginError(ConfigurationError):
    """A plugin lifecycle operation failed."""


class RestoreError(HydraError):
    """A backup could not be validated or restored safely."""
