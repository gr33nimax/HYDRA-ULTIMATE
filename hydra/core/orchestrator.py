"""Deprecated alias for the legacy function-based orchestration facade.

Production composition uses the instance-scoped
``hydra.services.orchestration_service.OrchestrationService``.  This alias is
retained only for integrations that still import the historic functions.
"""
from __future__ import annotations

import sys

from hydra.services import orchestration as _implementation


sys.modules[__name__] = _implementation
