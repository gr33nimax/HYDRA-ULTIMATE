from unittest.mock import Mock

from hydra.core.state_models import AppState
from hydra.services.system import SystemService


def test_system_service_owns_checks_and_atomic_migration():
    state = AppState(revision=7)
    validate = Mock()
    doctor = Mock(return_value={"ok": True})
    upgrade = Mock(return_value={"ready": True})
    migrate = Mock(return_value={"from": 3, "to": 4, "changed": True})
    service = SystemService(
        validate_state=validate,
        doctor_check=doctor,
        upgrade_readiness=upgrade,
        migrate_persisted_state=migrate,
    )

    assert service.validate(state) == {
        "valid": True,
        "schema_version": state.version,
        "revision": 7,
    }
    assert service.doctor(state) == {"ok": True}
    assert service.upgrade_check(state) == {"ready": True}
    assert service.migrate_state()["changed"] is True

    validate.assert_called_once_with(state)
    doctor.assert_called_once_with(state)
    upgrade.assert_called_once_with(state)
    migrate.assert_called_once_with()


def test_system_validation_does_not_hide_failure():
    validate = Mock(side_effect=ValueError("bad state"))
    service = SystemService(
        validate_state=validate,
        doctor_check=Mock(),
        upgrade_readiness=Mock(),
        migrate_persisted_state=Mock(),
    )

    try:
        service.validate(AppState())
    except ValueError as exc:
        assert str(exc) == "bad state"
    else:
        raise AssertionError("validation failure must cross the application port")
