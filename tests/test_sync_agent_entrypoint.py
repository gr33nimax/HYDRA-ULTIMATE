from unittest.mock import MagicMock, patch

from hydra.entrypoints import sync_agent


def test_main_composes_every_sync_dependency():
    application = MagicMock()
    operations = MagicMock()

    with patch.object(
        sync_agent,
        "production_application",
        return_value=application,
    ), patch.object(
        sync_agent,
        "default_sync_operations",
        return_value=operations,
    ) as compose, patch.object(
        sync_agent,
        "run_sync",
        return_value=(True, "ok"),
    ) as run:
        assert sync_agent.main() == 0

    arguments = compose.call_args.kwargs
    assert arguments["protocols"] is application.protocols
    assert arguments["plugin_actions"] is application.plugin_actions
    assert arguments["plugin_queries"] is application.plugin_queries
    assert arguments["apply_config"] is application.apply
    assert arguments["check_traffic_limits"] is application.traffic.check_limits
    assert arguments["inspect_certificates"] is application.certificates.inspect
    assert callable(arguments["renew_subscription_certificate"])
    run.assert_called_once_with(operations=operations)


def test_subscription_renewal_reaches_the_admin_adapter():
    from hydra.services.sync_ports import subscription_certificate_renewal

    admin = MagicMock()
    admin.obtain_subscription_certificate.return_value = MagicMock(
        ok=True,
        message="",
    )
    admin.unit_active.return_value = True

    ok, _message = subscription_certificate_renewal(admin)("sub.example.com")

    assert ok is True
    admin.obtain_subscription_certificate.assert_called_once_with(
        "sub.example.com",
    )
    admin.restart_unit.assert_called_once_with("hydra-sub")
