"""Dependency-neutral errors shared across HYDRA layers."""
from __future__ import annotations


class HydraError(RuntimeError):
    """Base class for expected HYDRA operational failures."""


class ConfigurationError(HydraError):
    """Configuration could not be generated, validated or applied."""
