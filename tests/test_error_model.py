from types import SimpleNamespace

from hydra.core.errors import (
    ConfigurationError,
    ErrorCode,
    HostOperationError,
    ServiceResult,
    normalize_error,
)
from hydra.core.state import AppState
from hydra.services.application import ApplicationService
from hydra.services.protocols import ProtocolService


def test_normalize_error_maps_domain_types_to_stable_codes():
    assert normalize_error(ValueError("bad input")).code is ErrorCode.INVALID_INPUT
    assert normalize_error(HostOperationError("systemd failed")).code is ErrorCode.HOST_OPERATION
    assert normalize_error(ConfigurationError("invalid config")).code is ErrorCode.CONFIGURATION


def test_service_result_keeps_bool_compatibility_and_serializes_error():
    result = ServiceResult(False, error=normalize_error(ValueError("bad")))
    assert not result
    assert result.as_dict()["error"]["code"] == "invalid_input"


def test_application_apply_result_normalizes_legacy_false():
    app = ApplicationService(
        users=SimpleNamespace(), protocols=SimpleNamespace(),
        apply_config=lambda state: False,
        last_apply_error=lambda: "sing-box rejected configuration",
    )
    result = app.apply_result(AppState())
    assert not result
    assert result.error.code is ErrorCode.OPERATION_FAILED
    assert result.error.message == "sing-box rejected configuration"


def test_protocol_lifecycle_result_normalizes_exception_and_false():
    operations = SimpleNamespace(
        install_plugin=lambda state, name: False,
        reinstall_plugin=lambda state, name: True,
        uninstall_plugin=lambda state, name: True,
        enable=lambda state, name: (_ for _ in ()).throw(ConfigurationError("missing domain")),
        disable=lambda state, name: True,
    )
    catalog = SimpleNamespace()
    service = ProtocolService(operations, catalog)

    failed = service.lifecycle_result(AppState(), "install", "naive")
    raised = service.lifecycle_result(AppState(), "enable", "naive")
    assert failed.error.code is ErrorCode.OPERATION_FAILED
    assert raised.error.code is ErrorCode.CONFIGURATION
