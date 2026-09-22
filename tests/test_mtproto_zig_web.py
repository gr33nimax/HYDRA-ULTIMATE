"""Selectable Telegram WEB mode for mtproto.zig: route, links, relay and staging.

Every case is host-free: the loopback relay, the HTTPS bridge probe and the
frontend are injected fakes, so no network, systemd unit, certificate or
Telegram client is required.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, patch

import pytest

from hydra.core import sni_router
from hydra.core.sni_router_planning import collect_backends
from hydra.core.state import AppState, PluginState, User
from hydra.plugins.mtproto_zig import bridge_probe, configuration, installation, web_runtime
from hydra.plugins.mtproto_zig.credentials import bridge_capability, derive_secret
from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin
from hydra.services.application import ApplicationService
from hydra.services.protocol_setup import ProtocolSetupService

COVER_DOMAIN = "cover.example"
WEB_DOMAIN = "relay.example"


def _state(mode: str | None = None, *, enabled: bool = True, domain: str = WEB_DOMAIN) -> AppState:
    """Desired state for one mode; ``web-only`` carries no passthrough route."""
    state = AppState(users=[User(email="a@example", uuid="user-a")])
    state.network.server_ip = "203.0.113.10"
    config: dict = {"domain": COVER_DOMAIN}
    if mode == "web-only":
        config["web_mode"] = mode
        config["web_domain"] = domain
        config[configuration.WEB_ROUTE_KEY] = configuration.web_route_metadata()
    else:
        config[configuration.ROUTE_KEY] = configuration.route_metadata()
        if mode is not None:
            config["web_mode"] = mode
            config["web_domain"] = domain
            config[configuration.WEB_ROUTE_KEY] = configuration.web_route_metadata()
    state.protocols["mtproto_zig"] = PluginState(enabled=enabled, installed=True, config=config)
    return state


def _toml_lines(config: str) -> list[str]:
    """Exact rendered lines: `fake_tls_only = true` must not satisfy an `only` check."""
    return [line.strip() for line in config.splitlines()]


def _string_literals(source: str) -> list[str]:
    """String values the module can actually pass on, excluding docstrings."""
    tree = ast.parse(source)
    docstrings = {
        id(statement.value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        for statement in node.body[:1]
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
    ]


def _backends(state: AppState) -> list[dict]:
    return collect_backends(state, sni_router._INTERNAL_PORTS)


def _config(state: AppState) -> dict[str, Any]:
    return state.protocols["mtproto_zig"].config


def _web_route(state: AppState) -> dict[str, Any]:
    return cast(dict[str, Any], _config(state)[configuration.WEB_ROUTE_KEY])


class _Certificates:
    """Certificate provider double that records which names were requested."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def ensure(self, domain: str, config: dict) -> tuple[str, str]:
        del config
        self.calls.append(domain)
        return (f"/cert/{domain}.pem", f"/key/{domain}.pem")


class _Host:
    """Host double that records argv and fails only the commands a test names."""

    def __init__(self, fail=None, stdout: str = "active\n", code: int = 0) -> None:
        self.commands: list[list[str]] = []
        self._fail = fail
        self._stdout = stdout
        self._code = code

    def run(self, args, **_kwargs):
        self.commands.append(list(args))
        failed = bool(self._fail and self._fail(list(args)))
        return CompletedProcess(args, 1 if failed else self._code, self._stdout if not failed else "inactive\n", "")

    def atomic_write(self, path: Path, content, **_kwargs) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else bytes(content).decode(), encoding="utf-8")

    def ensure_directory(self, path: Path, **_kwargs) -> None:
        path.mkdir(parents=True, exist_ok=True)


# ── TSK-012: generic plugin-owned TLS-terminating route ──────────────────────


def test_web_route_is_a_second_plugin_owned_backend():
    backends = _backends(_state("hybrid"))

    passed = next(item for item in backends if item["name"] == "mtproto_zig")
    web = next(item for item in backends if item["name"] == "mtproto_zig:web")

    assert passed["route_kind"] == "tls_passthrough"
    assert passed["port"] == configuration.INTERNAL_PORT
    assert web["route_kind"] == "http_reverse_proxy"
    assert web["domain"] == WEB_DOMAIN
    assert web["port"] == configuration.WEB_RELAY_PORT
    assert web["cert_file"] == ""


def test_web_route_forces_the_multiplexer_even_alone():
    assert sni_router.needs_mux(_state("hybrid")) is True


def test_web_route_is_absent_when_the_feature_is_off():
    backends = _backends(_state())

    assert [item["name"] for item in backends] == ["mtproto_zig"]
    assert sni_router.needs_mux(_state()) is False


def test_duplicate_web_and_cover_domain_names_both_owners():
    state = _state("hybrid", domain=COVER_DOMAIN)

    with pytest.raises(ValueError, match=f"{COVER_DOMAIN}"):
        _backends(state)


def test_web_route_rejects_a_port_owned_by_another_route():
    state = _state("hybrid")
    route = _web_route(state)
    route["internal_port"] = configuration.INTERNAL_PORT

    with pytest.raises(ValueError, match=f"port {configuration.INTERNAL_PORT}"):
        _backends(state)


def test_rendered_web_route_terminates_tls_and_forwards_the_plain_stream(tmp_path):
    state = _state("hybrid")
    cert = tmp_path / "web-cert.pem"
    key = tmp_path / "web-key.pem"
    cert.write_text("cert")
    key.write_text("key")
    state.protocols["mtproto_zig"].config.update(
        web_cert_file=str(cert),
        web_key_file=str(key),
    )

    rendered = sni_router._generate_config(_backends(state), state)
    routes = rendered["apps"]["layer4"]["servers"]["tls_mux"]["routes"]
    web = next(route for route in routes if route["match"][0]["tls"]["sni"] == [WEB_DOMAIN])

    assert web["handle"][0] == {
        "handler": "tls",
        "connection_policies": [{"alpn": ["http/1.1"]}],
    }
    assert web["handle"][1] == {
        "handler": "proxy",
        "upstreams": [{"dial": [f"127.0.0.1:{configuration.WEB_RELAY_PORT}"]}],
    }
    assert "proxy_protocol" not in web["handle"][1]
    loaded = rendered["apps"]["tls"]["certificates"]["load_files"]
    assert {"certificate": str(cert), "key": str(key)} in loaded
    passthrough = next(route for route in routes if route["match"][0]["tls"]["sni"] == [COVER_DOMAIN])
    assert "handler" not in passthrough["handle"][0] or passthrough["handle"][0]["handler"] == "proxy"


def test_web_route_without_a_certificate_is_rejected():
    state = _state("hybrid")

    with pytest.raises(ValueError, match="TLS material is missing"):
        sni_router._generate_config(_backends(state), state)


def test_audit_reports_a_web_certificate_that_is_not_loaded(tmp_path):
    state = _state("hybrid")
    state.protocols["mtproto_zig"].config.update(
        web_cert_file="/missing/cert.pem",
        web_key_file="/missing/key.pem",
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"apps": {"layer4": {"servers": {"tls_mux": {"routes": []}}}}}))

    with (
        patch.object(sni_router, "CADDY_CFG", config_path),
        patch.object(sni_router, "is_active", return_value=True),
    ):
        report = sni_router.audit_routes(state)

    assert report.ok is False
    assert any(WEB_DOMAIN in error for error in report.certificate_errors)


# ── TSK-014: desired state, TOML, certificate and links ──────────────────────


def test_configuration_has_no_web_section_when_the_feature_is_off():
    _config, _fragment = configuration.plan_configuration(_state())

    assert "[web]" not in _config
    assert _config.count("[server]") == 1


@pytest.mark.parametrize(("mode", "expected_only"), [("hybrid", "false"), ("web-only", "false")])
def test_web_modes_render_the_relay_section_without_only(mode, expected_only):
    rendered, _fragment = configuration.plan_configuration(_state(mode))

    assert "[web]" in rendered
    assert "enabled = true" in rendered
    assert f"only = {expected_only}" in rendered
    assert f'domain = "{WEB_DOMAIN}"' in rendered
    assert f"port = {configuration.WEB_RELAY_PORT}" in rendered
    assert f'backend = "127.0.0.1:{configuration.INTERNAL_PORT}"' in rendered
    assert "trust_forwarded_for = false" in rendered


def test_only_web_only_commits_the_exclusive_mode():
    rendered, _fragment = configuration.plan_configuration(_state("web-only"), web_only=True)

    assert "only = true" in rendered


def test_hybrid_never_commits_the_exclusive_mode():
    rendered, _fragment = configuration.plan_configuration(_state("hybrid"), web_only=True)

    assert "only = false" in rendered


def test_web_mode_without_its_route_fails_closed():
    state = _state("hybrid")
    del state.protocols["mtproto_zig"].config[configuration.WEB_ROUTE_KEY]

    with pytest.raises(ValueError, match="Маршрут WEB"):
        configuration.plan_configuration(state)


def test_web_mode_without_a_dedicated_domain_fails_closed():
    state = _state("hybrid")
    state.protocols["mtproto_zig"].config["web_domain"] = ""

    with pytest.raises(ValueError, match="домен релея"):
        configuration.plan_configuration(state)


def test_off_mode_publishes_only_the_fake_tls_link():
    state = _state()

    links = MtprotoZigPlugin().client_links(state.users[0], state)

    assert len(links) == 1
    assert links[0].startswith("tg://proxy?") and "&port=443&secret=ee" in links[0]


def test_hybrid_publishes_both_links_without_a_port_in_the_web_link():
    state = _state("hybrid")

    links = MtprotoZigPlugin().client_links(state.users[0], state)

    assert len(links) == 2
    assert links[0].startswith("tg://proxy?")
    secret = state.users[0].uuid
    assert links[1] == f"tg://webproxy?server={WEB_DOMAIN}&secret=dd{configuration.derive_secret(secret)}"
    assert "port=" not in links[1]


def test_web_only_publishes_only_the_web_link():
    state = _state("web-only")

    links = MtprotoZigPlugin().client_links(state.users[0], state)

    assert len(links) == 1
    assert links[0].startswith("tg://webproxy?")


def test_set_web_settings_requires_a_real_hostname():
    plugin = MtprotoZigPlugin()
    state = _state()

    with pytest.raises(ValueError, match="Домен WEB-релея"):
        plugin.set_web_settings(state, mode="hybrid", domain="10.0.0.1")
    with pytest.raises(ValueError, match="Домен WEB-релея"):
        plugin.set_web_settings(state, mode="hybrid", domain="relay")


def test_set_web_settings_adds_and_removes_the_route():
    plugin = MtprotoZigPlugin()
    state = _state()

    assert plugin.set_web_settings(state, mode="HYBRID", domain="Relay.Example.") is True
    config = _config(state)
    assert config["web_mode"] == "hybrid"
    assert config["web_domain"] == WEB_DOMAIN
    assert _web_route(state)["kind"] == "http_reverse_proxy"

    assert plugin.set_web_settings(state, mode="off") is True
    assert configuration.WEB_ROUTE_KEY not in config
    assert "web_domain" not in config
    assert config["web_mode"] == "off"


def test_fake_tls_domain_never_requests_a_certificate_but_the_web_domain_does():
    certificates = _Certificates()
    plugin = MtprotoZigPlugin()
    setup = ProtocolSetupService(certificates, lambda name: plugin if name == "mtproto_zig" else None)

    off_state = _state()
    setup.prepare_enable(off_state, "mtproto_zig")
    assert certificates.calls == []
    assert _config(off_state).get("cert_file") in (None, "")

    web_state = _state("hybrid")
    setup.prepare_enable(web_state, "mtproto_zig")
    assert certificates.calls == [WEB_DOMAIN]
    config = _config(web_state)
    assert config["web_cert_file"] == f"/cert/{WEB_DOMAIN}.pem"
    assert config["web_key_file"] == f"/key/{WEB_DOMAIN}.pem"
    assert config.get("cert_file") in (None, "")


# ── TSK-015: Hydra-owned relay unit and staged activation ────────────────────


def test_web_unit_runs_the_relay_mode_without_capabilities(tmp_path):
    host = _Host()
    service = tmp_path / "mtproto-zig-web.service"

    assert installation.write_web_service(
        host=host,
        service_file=service,
        binary=tmp_path / "mtproto-zig",
        config=tmp_path / "config.toml",
        work_dir=tmp_path / "work",
        service="mtproto-zig-web",
        proxy_service="mtproto-zig",
    )

    unit = service.read_text(encoding="utf-8")
    assert "ExecStart=" in unit and " web-relay " in unit
    assert "User=mtproto-zig" in unit
    assert "PartOf=mtproto-zig.service" in unit
    assert "CapabilityBoundingSet=" in [line.strip() for line in unit.splitlines()]
    assert "AmbientCapabilities" not in unit
    assert "CAP_NET_ADMIN" not in unit
    assert ["systemctl", "daemon-reload"] in host.commands


def test_web_unit_reports_a_rejected_unit(tmp_path):
    stages: list[str] = []
    host = _Host(fail=lambda command: command[:2] == ["systemctl", "daemon-reload"])

    assert (
        installation.write_web_service(
            host=host,
            service_file=tmp_path / "unit.service",
            binary=tmp_path / "bin",
            config=tmp_path / "config.toml",
            work_dir=tmp_path / "work",
            service="mtproto-zig-web",
            proxy_service="mtproto-zig",
            on_failure=stages.append,
        )
        is False
    )
    assert stages and stages[0].startswith("systemd не принял юнит WEB-релея")


def test_relay_staging_starts_and_probes_the_loopback_listener(tmp_path):
    host = _Host()
    stages: list[str] = []

    with patch.object(web_runtime, "probe_local", return_value=(True, "")) as probe:
        applied = web_runtime.apply(
            host=host,
            binary=tmp_path / "mtproto-zig",
            config_file=tmp_path / "config.toml",
            work_dir=tmp_path / "work",
            service="mtproto-zig-web",
            service_file=tmp_path / "unit.service",
            proxy_service="mtproto-zig",
            on_failure=stages.append,
        )

    assert applied is True
    assert stages == []
    assert ["systemctl", "enable", "mtproto-zig-web"] in host.commands
    assert ["systemctl", "restart", "mtproto-zig-web"] in host.commands
    probe.assert_called_once_with()


def test_relay_staging_reports_an_unreachable_listener(tmp_path):
    host = _Host()
    stages: list[str] = []

    with patch.object(web_runtime, "probe_local", return_value=(False, "connection refused")):
        applied = web_runtime.apply(
            host=host,
            binary=tmp_path / "mtproto-zig",
            config_file=tmp_path / "config.toml",
            work_dir=tmp_path / "work",
            service="mtproto-zig-web",
            service_file=tmp_path / "unit.service",
            proxy_service="mtproto-zig",
            on_failure=stages.append,
        )

    assert applied is False
    assert stages == [
        f"WEB-релей не отвечает на 127.0.0.1:{configuration.WEB_RELAY_PORT}: connection refused",
    ]


def test_relay_staging_reports_an_inactive_unit(tmp_path):
    host = _Host(stdout="failed\n")
    stages: list[str] = []

    applied = web_runtime.apply(
        host=host,
        binary=tmp_path / "mtproto-zig",
        config_file=tmp_path / "config.toml",
        work_dir=tmp_path / "work",
        service="mtproto-zig-web",
        service_file=tmp_path / "unit.service",
        proxy_service="mtproto-zig",
        on_failure=stages.append,
    )

    assert applied is False
    assert stages and stages[0].startswith("служба mtproto-zig-web не запустилась (state=failed)")


def test_relay_snapshot_and_rollback_restore_the_previous_unit(tmp_path):
    service = tmp_path / "unit.service"
    service.write_text("old unit", encoding="utf-8")
    snapshot = web_runtime.snapshot(service_file=service, running=True)
    service.write_text("new unit", encoding="utf-8")
    host = _Host()

    assert web_runtime.rollback(snapshot, host=host, service="mtproto-zig-web", service_file=service) is True

    assert service.read_text(encoding="utf-8") == "old unit"
    assert ["systemctl", "restart", "mtproto-zig-web"] in host.commands


def test_relay_snapshot_rollback_removes_a_unit_that_did_not_exist(tmp_path):
    service = tmp_path / "unit.service"
    snapshot = web_runtime.snapshot(service_file=service, running=False)
    service.write_text("new unit", encoding="utf-8")
    host = _Host()

    assert web_runtime.rollback(snapshot, host=host, service="mtproto-zig-web", service_file=service) is True

    assert not service.exists()
    assert ["systemctl", "disable", "--now", "mtproto-zig-web"] in host.commands


def test_stopping_the_relay_disables_removes_and_reloads(tmp_path):
    service = tmp_path / "unit.service"
    service.write_text("unit", encoding="utf-8")
    host = _Host()

    assert web_runtime.stop(host=host, service="mtproto-zig-web", service_file=service) is True

    assert not service.exists()
    assert ["systemctl", "disable", "--now", "mtproto-zig-web"] in host.commands
    assert ["systemctl", "daemon-reload"] in host.commands


def test_stopping_the_relay_clears_an_enable_link_left_by_a_removed_unit(tmp_path):
    """A surviving multi-user.target.wants link can still pull the unit in at boot."""
    service = tmp_path / "mtproto-zig-web.service"
    link = tmp_path / "multi-user.target.wants" / "mtproto-zig-web.service"
    link.parent.mkdir()
    try:
        link.symlink_to(service)
    except OSError:
        # Windows without symlink privileges: a plain entry at the same path
        # still stands in for the surviving dangling enable link.
        link.write_text("", encoding="utf-8")
    host = _Host(fail=lambda command: command[:2] == ["systemctl", "disable"])
    stages: list[str] = []

    assert (
        web_runtime.stop(
            host=host,
            service="mtproto-zig-web",
            service_file=service,
            on_failure=stages.append,
        )
        is False
    )

    assert ["systemctl", "disable", "--now", "mtproto-zig-web"] in host.commands, "disable runs without the unit file"
    assert ["systemctl", "daemon-reload"] in host.commands
    assert stages and stages[0].startswith("WEB-релей mtproto-zig-web остался включён")


def test_stopping_a_relay_that_was_never_installed_is_not_a_failure(tmp_path):
    """systemd reports a missing unit as non-zero; a fresh host has nothing to stop."""
    host = _Host(fail=lambda command: command[:2] == ["systemctl", "disable"])

    assert web_runtime.stop(host=host, service="mtproto-zig-web", service_file=tmp_path / "unit.service") is True

    assert ["systemctl", "disable", "--now", "mtproto-zig-web"] in host.commands, "disable must not be skipped"


def test_stopping_the_relay_reports_a_failed_disable_of_an_installed_unit(tmp_path):
    service = tmp_path / "unit.service"
    service.write_text("unit", encoding="utf-8")
    host = _Host(fail=lambda command: command[:2] == ["systemctl", "disable"])
    stages: list[str] = []

    assert (
        web_runtime.stop(host=host, service="mtproto-zig-web", service_file=service, on_failure=stages.append) is False
    )

    assert stages and stages[0].startswith("systemctl disable --now не выполнился для mtproto-zig-web")


def test_staging_never_commits_web_only_before_the_bridge_is_proven(tmp_path):
    plugin = MtprotoZigPlugin()
    state = _state("web-only")
    plugin.configure(state)
    applied_configs: list[str] = []

    def fake_apply(config, **_kwargs):
        applied_configs.append(config)
        return True

    with (
        patch("hydra.core.decoy.ensure_decoy_site", return_value=Path("/var/www/decoy-zig")),
        patch("hydra.plugins.mtproto_zig.plugin.runtime.apply", side_effect=fake_apply),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.apply", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.running", return_value=False),
        patch("hydra.plugins.mtproto_zig.plugin.bridge_probe.probe_bridge", return_value=(False, "no route")),
    ):
        assert plugin.apply(state) is True
        assert "only = false" in _toml_lines(applied_configs[0])
        assert plugin.finalize_apply(state) is False

    assert applied_configs == [applied_configs[0]], "an unproven bridge must not commit only=true"
    assert "only = true" not in _toml_lines(applied_configs[0])
    assert plugin.apply_failure() == "WEB-мост не подтверждён: no route"


def test_web_only_is_committed_after_a_successful_bridge_probe():
    plugin = MtprotoZigPlugin()
    state = _state("web-only")
    plugin.configure(state)
    applied_configs: list[str] = []

    def fake_apply(config, **_kwargs):
        applied_configs.append(config)
        return True

    with (
        patch("hydra.core.decoy.ensure_decoy_site", return_value=Path("/var/www/decoy-zig")),
        patch("hydra.plugins.mtproto_zig.plugin.runtime.apply", side_effect=fake_apply),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.apply", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.running", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.bridge_probe.probe_bridge", return_value=(True, "")) as probe,
    ):
        assert plugin.apply(state) is True
        assert plugin.finalize_apply(state) is True

    assert len(applied_configs) == 2
    assert "only = false" in _toml_lines(applied_configs[0])
    assert "only = true" not in _toml_lines(applied_configs[0])
    assert "only = true" in _toml_lines(applied_configs[1])
    probe.assert_called_once_with(WEB_DOMAIN, capability=bridge_capability(derive_secret("user-a"), WEB_DOMAIN))


def test_web_only_without_an_active_user_refuses_to_close_the_direct_path():
    """Without a real user secret the bridge cannot be authenticated, so no commit."""
    plugin = MtprotoZigPlugin()
    state = _state("web-only")
    state.users = []

    with patch("hydra.plugins.mtproto_zig.plugin.bridge_probe.probe_bridge") as probe:
        assert plugin.finalize_apply(state) is False

    probe.assert_not_called()
    assert plugin.apply_failure() == "WEB-мост нельзя проверить: нет ни одного активного пользователя"


def test_hybrid_without_an_active_user_keeps_the_direct_path():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")
    state.users = []

    assert plugin.finalize_apply(state) is True


def test_hybrid_finalization_only_probes_the_bridge():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")

    with (
        patch("hydra.plugins.mtproto_zig.plugin.runtime.apply") as apply,
        patch("hydra.plugins.mtproto_zig.plugin.bridge_probe.probe_bridge", return_value=(True, "")),
    ):
        assert plugin.finalize_apply(state) is True

    apply.assert_not_called()


def test_off_mode_finalization_is_a_no_op():
    plugin = MtprotoZigPlugin()

    with patch("hydra.plugins.mtproto_zig.plugin.bridge_probe.probe_bridge") as probe:
        assert plugin.finalize_apply(_state()) is True

    probe.assert_not_called()


def test_apply_removes_the_relay_when_the_mode_is_off():
    plugin = MtprotoZigPlugin()
    state = _state()
    plugin.configure(state)

    with (
        patch("hydra.plugins.mtproto_zig.plugin.runtime.apply", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.stop", return_value=True) as stop,
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.apply") as web_apply,
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.running", return_value=False),
    ):
        assert plugin.apply(state) is True

    stop.assert_called_once()
    web_apply.assert_not_called()


def test_status_requires_the_relay_unit_in_web_mode():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")

    with (
        patch.object(MtprotoZigPlugin, "_installed", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.HOST.run") as run,
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.service_state", return_value="failed"),
    ):
        run.return_value = CompletedProcess(["systemctl"], 0, "active\n", "")
        status = plugin.status(state)
        health = plugin.healthcheck_for_state(state)

    assert status.running is False
    assert status.info["web_mode"] == "hybrid"
    assert status.info["web_state"] == "failed"
    assert status.info["link_mode"] == "FakeTLS + WEB bridge"
    assert health.healthy is False
    assert "mtproto-zig-web" in health.detail


def test_web_only_status_names_the_exclusive_link_mode():
    plugin = MtprotoZigPlugin()

    with (
        patch.object(MtprotoZigPlugin, "_installed", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.HOST.run") as run,
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.service_state", return_value="active"),
    ):
        run.return_value = CompletedProcess(["systemctl"], 0, "active\n", "")
        status = plugin.status(_state("web-only"))

    assert status.running is True
    assert status.info["link_mode"] == "WEB bridge only"
    assert status.info["web_domain"] == WEB_DOMAIN


# ── TSK-016: TUI adapter and the WEB-only safety gate ────────────────────────


def test_settings_row_names_both_values_behind_one_entry():
    from hydra.ui._menus import mtproto_zig_settings

    rows = {
        mode: mtproto_zig_settings.option(_state(mode).protocols["mtproto_zig"])
        for mode in ("off", "hybrid", "web-only")
    }

    assert {row[0] for row in rows.values()} == {"⚙️ Настройки MTProto Zig"}
    assert "выключен · только FakeTLS" in rows["off"][1]
    assert "FakeTLS + WEB" in rows["hybrid"][1]
    assert "только WEB" in rows["web-only"][1]
    assert all(COVER_DOMAIN in row[1] for row in rows.values())


def test_cancelling_the_web_only_confirmation_changes_nothing():
    from hydra.ui._menus import mtproto_zig_settings

    state = _state("hybrid")
    command = Mock(return_value=True)
    app = cast(
        ApplicationService,
        SimpleNamespace(
            admin=SimpleNamespace(load_state=lambda: state),
            plugin_command=command,
        ),
    )

    with (
        patch.object(mtproto_zig_settings, "menu", side_effect=["1", "3"]),
        patch.object(mtproto_zig_settings, "prompt", return_value=WEB_DOMAIN),
        patch.object(mtproto_zig_settings, "confirm", return_value=False) as confirm,
    ):
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    confirm.assert_called_once()
    command.assert_not_called()


def test_confirming_web_only_goes_through_the_plugin_command():
    from hydra.ui._menus import mtproto_zig_settings

    state = _state("hybrid")
    command = Mock(return_value=True)
    app = cast(
        ApplicationService,
        SimpleNamespace(
            admin=SimpleNamespace(load_state=lambda: state),
            plugin_command=command,
        ),
    )

    with (
        patch.object(mtproto_zig_settings, "menu", side_effect=["1", "3"]),
        patch.object(mtproto_zig_settings, "prompt", return_value=WEB_DOMAIN),
        patch.object(mtproto_zig_settings, "confirm", return_value=True),
        patch.object(mtproto_zig_settings, "_report_change"),
    ):
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    command.assert_called_once_with(
        state,
        "mtproto_zig",
        "set_web_settings",
        mode="web-only",
        domain=WEB_DOMAIN,
        confirm_host_change=True,
    )


def test_reselecting_the_same_mode_is_reported_as_a_no_op():
    from hydra.ui._menus import mtproto_zig_settings

    state = _state("hybrid")
    command = Mock(return_value=True)
    app = cast(
        ApplicationService,
        SimpleNamespace(
            admin=SimpleNamespace(load_state=lambda: state),
            plugin_command=command,
        ),
    )
    messages: list[str] = []

    with (
        patch.object(mtproto_zig_settings, "menu", side_effect=["1", "2"]),
        patch.object(mtproto_zig_settings, "prompt", return_value="Relay.Example."),
        patch.object(mtproto_zig_settings, "info", messages.append),
        patch.object(mtproto_zig_settings, "error", messages.append),
    ):
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    command.assert_not_called()
    assert messages and "уже выбран" in messages[0]


def test_settings_row_opens_the_mode_chooser_directly():
    """One settings menu, then the chooser: no menu repeats the pressed row."""
    from hydra.ui._menus import mtproto_zig_settings

    state = _state("hybrid")
    app = cast(
        ApplicationService,
        SimpleNamespace(
            admin=SimpleNamespace(load_state=lambda: state),
            plugin_command=Mock(),
        ),
    )

    with patch.object(mtproto_zig_settings, "menu", side_effect=["1", "0"]) as drawn:
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    assert drawn.call_count == 2
    settings_items = drawn.call_args_list[0][0][0]
    assert [item[1] for item in settings_items[:2]] == ["🌐 Режим WEB", "🔒 Домен FakeTLS"]
    assert "РЕЖИМ WEB" in drawn.call_args_list[1][0][1]
    assert "НАСТРОЙКИ MTPROTO ZIG" not in drawn.call_args_list[1][0][1]


def test_cancelling_the_mode_chooser_draws_no_second_menu():
    from hydra.ui._menus import mtproto_zig_settings

    state = _state("hybrid")
    app = cast(ApplicationService, SimpleNamespace(plugin_command=Mock()))

    with (
        patch.object(mtproto_zig_settings, "menu", side_effect=["1", "0"]) as drawn,
        patch.object(mtproto_zig_settings, "prompt") as wait,
    ):
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    assert drawn.call_count == 2, "the settings menu and one chooser, nothing more"
    wait.assert_not_called()


# ── TSK-021: the FakeTLS cover domain is its own settings row (R16) ─────────


def test_cover_domain_change_leaves_the_web_domain_untouched():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")

    assert plugin.set_domain(state, "new-cover.example", confirm_change=True) is True

    config = _config(state)
    assert config["domain"] == "new-cover.example"
    assert config["web_domain"] == WEB_DOMAIN
    assert config[configuration.WEB_ROUTE_KEY]["kind"] == "http_reverse_proxy"


def test_web_domain_change_leaves_the_cover_domain_untouched():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")

    assert plugin.set_web_settings(state, mode="hybrid", domain="other.example", confirm_host_change=True) is True

    assert _config(state)["domain"] == COVER_DOMAIN
    assert _config(state)["web_domain"] == "other.example"


def test_cover_domain_equal_to_the_web_domain_is_refused_before_mutation():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")

    with pytest.raises(ValueError, match=WEB_DOMAIN) as refused:
        plugin.set_domain(state, WEB_DOMAIN)

    assert "WEB-релея" in str(refused.value), "the message must name the conflict"
    assert _config(state)["domain"] == COVER_DOMAIN


@pytest.mark.parametrize("domain", ["", "cover", "10.0.0.1", "0177.0.0.1", "0x7f.1"])
def test_cover_domain_rejects_empty_ip_literal_and_single_label_before_mutation(domain):
    plugin = MtprotoZigPlugin()
    state = _state()

    with pytest.raises(ValueError):
        plugin.set_domain(state, domain)

    assert _config(state)["domain"] == COVER_DOMAIN


def test_changing_an_issued_cover_domain_needs_explicit_confirmation():
    """A headless caller must not invalidate issued FakeTLS links by accident."""
    plugin = MtprotoZigPlugin()
    state = _state()

    with pytest.raises(ValueError, match="confirm_change"):
        plugin.set_domain(state, "other.example")
    assert _config(state)["domain"] == COVER_DOMAIN

    assert plugin.set_domain(state, "other.example", confirm_change="true") is True
    assert _config(state)["domain"] == "other.example"


def test_cover_domain_change_requests_no_certificate_and_no_decoy_site():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")
    certificates = _Certificates()
    setup = ProtocolSetupService(certificates, lambda name: plugin if name == "mtproto_zig" else None)

    assert plugin.set_domain(state, "new-cover.example", confirm_change=True) is True

    assert plugin.certificate_requirements(state) == ((WEB_DOMAIN, "web_cert_file", "web_key_file"),)
    setup.prepare_enable(state, "mtproto_zig")
    assert certificates.calls == [WEB_DOMAIN], "the cover domain never requests a certificate"
    assert _config(state).get("cert_file") in (None, "")
    rendered, _fragment = configuration.plan_configuration(state)
    assert 'tls_domain = "new-cover.example"' in rendered
    assert "public_dir" not in rendered


def test_cover_domain_change_runs_through_the_transactional_command_service():
    from hydra.services.plugin_commands import PluginCommandService

    plugin = MtprotoZigPlugin()
    state = _state()
    applied: list[str] = []
    service = PluginCommandService(
        get_plugin=lambda name: plugin if name == "mtproto_zig" else None,
        apply_config=lambda current: applied.append("apply") or True,
        save_state=lambda current: None,
    )

    with patch.object(MtprotoZigPlugin, "snapshot", return_value={}):
        assert service.execute(
            state,
            "mtproto_zig",
            "set_domain",
            domain="new-cover.example",
            confirm_change=True,
        )

    assert _config(state)["domain"] == "new-cover.example"
    assert applied == ["apply"], "an enabled protocol applies the new cover domain"


def test_settings_menu_shows_both_rows_without_repeating_the_pressed_row():
    from hydra.ui._menus import mtproto_zig_settings

    state = _state("hybrid")
    app = cast(ApplicationService, SimpleNamespace(plugin_command=Mock()))

    with patch.object(mtproto_zig_settings, "menu", side_effect=["0"]) as drawn:
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    items = drawn.call_args[0][0]
    assert [item[1] for item in items[:2]] == ["🌐 Режим WEB", "🔒 Домен FakeTLS"]
    assert items[1][2] == COVER_DOMAIN, "the FakeTLS row shows the current cover domain"
    assert drawn.call_args[0][1] == "НАСТРОЙКИ MTPROTO ZIG"
    entry, _value = mtproto_zig_settings.option(state.protocols["mtproto_zig"])
    assert entry not in [item[1] for item in items]


def test_cover_domain_change_needs_confirmation():
    from hydra.ui._menus import mtproto_zig_settings

    state = _state()
    command = Mock(return_value=True)
    app = cast(ApplicationService, SimpleNamespace(plugin_command=command))

    with (
        patch.object(mtproto_zig_settings, "menu", side_effect=["2"]),
        patch.object(mtproto_zig_settings, "prompt", return_value="new-cover.example"),
        patch.object(mtproto_zig_settings, "confirm", return_value=False) as confirm,
    ):
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    confirm.assert_called_once()
    assert "ссылк" in confirm.call_args[0][0]
    assert "секрет" in confirm.call_args[0][0]
    command.assert_not_called()


def test_confirmed_cover_domain_change_goes_through_the_plugin_command():
    from hydra.ui._menus import mtproto_zig_settings

    state = _state()
    command = Mock(return_value=True)
    app = cast(ApplicationService, SimpleNamespace(plugin_command=command))

    with (
        patch.object(mtproto_zig_settings, "menu", side_effect=["2"]),
        patch.object(mtproto_zig_settings, "prompt", return_value="New-Cover.Example."),
        patch.object(mtproto_zig_settings, "confirm", return_value=True),
        patch.object(mtproto_zig_settings, "_report_change"),
    ):
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    command.assert_called_once_with(
        state,
        "mtproto_zig",
        "set_domain",
        domain="new-cover.example",
        confirm_change=True,
    )


def test_an_ip_literal_cover_domain_is_refused_before_confirmation_and_command():
    from hydra.ui._menus import mtproto_zig_settings

    state = _state()
    command = Mock(return_value=True)
    app = cast(ApplicationService, SimpleNamespace(plugin_command=command))
    messages: list[str] = []

    with (
        patch.object(mtproto_zig_settings, "menu", side_effect=["2"]),
        patch.object(mtproto_zig_settings, "prompt", return_value="10.0.0.1"),
        patch.object(mtproto_zig_settings, "confirm") as confirm,
        patch.object(mtproto_zig_settings, "error", messages.append),
    ):
        mtproto_zig_settings.open_menu(state, SimpleNamespace(), app)

    confirm.assert_not_called()
    command.assert_not_called()
    assert messages and "IP-адресом" in messages[0]


# ── TSK-020: cover site on the WEB domain (R15) ─────────────────────────────


def test_cover_site_is_referenced_only_while_web_mode_is_active():
    plugin = MtprotoZigPlugin()
    site = Path("/var/www/decoy-zig")
    applied: list[str] = []

    def fake_apply(config, **_kwargs):
        applied.append(config)
        return True

    active = _state("hybrid")
    plugin.configure(active)
    with (
        patch("hydra.core.decoy.ensure_decoy_site", return_value=site) as ensure,
        patch("hydra.plugins.mtproto_zig.plugin.runtime.apply", side_effect=fake_apply),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.apply", return_value=True),
    ):
        assert plugin.apply(active) is True

    ensure.assert_called_once_with("mtproto_zig", "landing", domain=WEB_DOMAIN)
    assert f'public_dir = "{site}"' in applied[0]

    off = _state()
    plugin.configure(off)
    with (
        patch("hydra.core.decoy.ensure_decoy_site") as ensure_off,
        patch("hydra.plugins.mtproto_zig.plugin.runtime.apply", side_effect=fake_apply),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.stop", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.running", return_value=False),
    ):
        assert plugin.apply(off) is True

    ensure_off.assert_not_called()
    assert "public_dir" not in applied[1]


def test_cover_site_generation_failure_leaves_no_public_dir():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")
    plugin.configure(state)
    applied: list[str] = []

    def fake_apply(config, **_kwargs):
        applied.append(config)
        return True

    with (
        patch("hydra.core.decoy.ensure_decoy_site", side_effect=OSError("диск недоступен")),
        patch("hydra.plugins.mtproto_zig.plugin.runtime.apply", side_effect=fake_apply),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.apply", return_value=True),
        patch.object(MtprotoZigPlugin, "_installed", return_value=True),
        patch("hydra.plugins.mtproto_zig.plugin.HOST.run") as run,
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.service_state", return_value="active"),
    ):
        run.return_value = CompletedProcess(["systemctl"], 0, "active\n", "")
        assert plugin.apply(state) is True
        status = plugin.status(state)
        health = plugin.healthcheck_for_state(state)

    assert "public_dir" not in applied[0], "a failed generation must not be referenced"
    assert "диск недоступен" in status.info["decoy_site"]
    assert health.healthy is True, "a cover-site failure must not fail the transport"
    assert health.severity == "warning"
    assert "диск недоступен" in health.detail


def test_cover_theme_is_selectable_through_the_shared_decoy_command():
    from hydra.plugins.decoy_support import supports_decoy_theme
    from hydra.ui._menus import decoy_theme

    plugin = MtprotoZigPlugin()
    state = _state("hybrid")
    desired = state.protocols["mtproto_zig"]

    assert supports_decoy_theme(plugin)
    assert decoy_theme.decoy_option(plugin, desired) == (
        "🎭 Сайт-заглушка",
        decoy_theme.theme_label("landing"),
    )
    assert plugin.set_decoy_theme(state, "blog")
    assert desired.config["decoy_theme"] == "blog"


def test_changing_the_cover_theme_regenerates_the_site(tmp_path):
    from hydra.core.decoy import DECOY_DIRS
    from hydra.core.decoy_sites import builder
    from hydra.core.decoy_sites.identity import build_identity
    from hydra.core.decoy_sites.registry import get_theme

    plugin = MtprotoZigPlugin()
    state = _state("hybrid")
    site = tmp_path / "decoy-zig"
    generated: list[str] = []
    published: list[Path] = []

    def publish(site_dir, theme, *, domain=""):
        published.append(Path(site_dir))
        selected = get_theme(theme)
        identity = build_identity(domain or site.name)
        if not builder.is_current(site, selected.name, identity):
            builder.build(site, selected.name, selected.render, identity)
        generated.append(selected.name)
        return site

    def render_apply() -> str:
        plugin.configure(state)
        captured: list[str] = []

        def fake_apply(config, **_kwargs):
            captured.append(config)
            return True

        with (
            patch("hydra.core.decoy.ensure_site", side_effect=publish),
            patch("hydra.plugins.mtproto_zig.plugin.runtime.apply", side_effect=fake_apply),
            patch("hydra.plugins.mtproto_zig.plugin.web_runtime.apply", return_value=True),
        ):
            assert plugin.apply(state) is True
        return captured[0]

    first = render_apply()
    first_index = (site / "index.html").read_text(encoding="utf-8")
    assert plugin.set_decoy_theme(state, "blog")
    second = render_apply()

    assert published == [DECOY_DIRS["mtproto_zig"], DECOY_DIRS["mtproto_zig"]]
    assert generated == ["landing", "blog"]
    assert f'public_dir = "{site}"' in first
    assert f'public_dir = "{site}"' in second
    assert builder.is_current(site, "blog", build_identity(WEB_DOMAIN))
    assert (site / "index.html").read_text(encoding="utf-8") != first_index


def test_cover_site_stays_inside_the_upstream_loader_bounds(tmp_path):
    from hydra.core.decoy import DECOY_DIRS
    from hydra.core.decoy_sites import builder
    from hydra.core.decoy_sites.identity import build_identity
    from hydra.core.decoy_sites.registry import get_theme

    registered = DECOY_DIRS["mtproto_zig"]
    assert registered.as_posix().startswith("/var/www/decoy-")
    assert not registered.is_symlink()

    site = tmp_path / "decoy-zig"
    theme = get_theme("landing")
    builder.build(site, theme.name, theme.render, build_identity(WEB_DOMAIN))
    files = [path for path in site.rglob("*") if path.is_file()]

    assert len(files) <= 256
    assert max(path.stat().st_size for path in files) <= 2 * 1024 * 1024
    assert sum(path.stat().st_size for path in files) <= 16 * 1024 * 1024
    assert max(len(path.relative_to(site).parts) for path in files) <= 8
    assert not any(path.is_symlink() for path in site.rglob("*"))
    # The marker is the only dotfile; the upstream loader never publishes it.
    assert {path.name for path in site.rglob("*") if path.name.startswith(".")} == {builder.MARKER_NAME}


# ── TSK-017: no upstream manager, no second host owner ───────────────────────


def test_lone_terminated_route_forces_the_multiplexer():
    """A WEB-only state has no passthrough route; the frontend must still be used."""
    state = _state("web-only")
    assert configuration.ROUTE_KEY not in state.protocols["mtproto_zig"].config

    assert sni_router.needs_mux(state) is True
    backends = _backends(state)
    assert [item["name"] for item in backends] == ["mtproto_zig:web"]


def test_web_only_route_set_drops_the_direct_passthrough_route():
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")

    assert plugin.set_web_settings(state, mode="web-only", domain=WEB_DOMAIN) is True

    config = _config(state)
    assert configuration.ROUTE_KEY not in config
    assert config[configuration.WEB_ROUTE_KEY]["kind"] == "http_reverse_proxy"
    # The rendered Caddy document keeps the WEB route and no direct SNI route.
    assert [item["name"] for item in _backends(state)] == ["mtproto_zig:web"]


def test_leaving_web_only_restores_the_passthrough_route():
    plugin = MtprotoZigPlugin()
    state = _state("web-only")

    assert plugin.set_web_settings(state, mode="hybrid", domain=WEB_DOMAIN) is True

    assert _config(state)[configuration.ROUTE_KEY]["kind"] == "tls_passthrough"
    assert sni_router.needs_mux(state) is True


def test_web_only_with_a_stale_passthrough_route_fails_closed():
    state = _state("web-only")
    state.protocols["mtproto_zig"].config[configuration.ROUTE_KEY] = configuration.route_metadata()

    with pytest.raises(ValueError, match="снятого маршрута FakeTLS"):
        configuration.plan_configuration(state)


@pytest.mark.parametrize("host", ["127.1", "1.2.3", "0177.0.0.1", "0x7f.1", "relay.0x7f", "10.0.0.1"])
def test_web_domain_rejects_tdesktop_incompatible_numeric_hosts(host):
    plugin = MtprotoZigPlugin()
    state = _state()

    with pytest.raises(ValueError):
        plugin.set_web_settings(state, mode="hybrid", domain=host)


def test_web_domain_still_accepts_a_hex_looking_non_final_label():
    plugin = MtprotoZigPlugin()
    state = _state()

    assert plugin.set_web_settings(state, mode="hybrid", domain="0xrelay.example") is True
    assert _config(state)["web_domain"] == "0xrelay.example"


def test_changing_an_issued_web_domain_needs_explicit_confirmation():
    """Headless callers must not invalidate issued links by accident."""
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")

    with pytest.raises(ValueError, match="confirm_host_change"):
        plugin.set_web_settings(state, mode="hybrid", domain="other.example")
    assert _config(state)["web_domain"] == WEB_DOMAIN

    assert (
        plugin.set_web_settings(
            state,
            mode="hybrid",
            domain="other.example",
            confirm_host_change="true",
        )
        is True
    )
    assert _config(state)["web_domain"] == "other.example"


def test_apply_takes_a_fresh_relay_snapshot_every_time():
    """A stale capture must never delete a relay that is currently healthy."""
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")
    plugin.configure(state)
    snapshots: list[dict] = []

    def snapshot(**kwargs):
        snapshots.append(kwargs)
        return {"unit": None, "running": kwargs["running"]}

    with (
        patch("hydra.core.decoy.ensure_decoy_site", return_value=Path("/var/www/decoy-zig")),
        patch("hydra.plugins.mtproto_zig.plugin.runtime.apply", return_value=False),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.running", return_value=True) as running,
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.service_state", return_value="active"),
        patch("hydra.plugins.mtproto_zig.plugin.web_runtime.snapshot", side_effect=snapshot),
    ):
        assert plugin.apply(state) is False
        assert plugin.apply(state) is False
        assert running.call_count == 0, "an apply that fails on the main unit must not capture the relay"
        first = plugin.snapshot(state)
        running.return_value = False
        second = plugin.snapshot(state)

    assert first["web"] == {"unit": None, "running": True}
    assert second["web"] == {"unit": None, "running": False}, "a cached capture would keep claiming the relay is up"
    assert [item["running"] for item in snapshots] == [True, False]
    assert running.call_count == 2, "every contract snapshot must ask the host for the current state"


def test_disabling_the_proxy_disables_and_removes_the_relay_unit(tmp_path):
    plugin = MtprotoZigPlugin()
    state = _state("hybrid")
    unit = tmp_path / "mtproto-zig-web.service"
    unit.write_text("unit", encoding="utf-8")
    commands: list[list[str]] = []

    class _Host:
        def run(self, args, **_kwargs):
            commands.append(list(args))
            return CompletedProcess(args, 0, "", "")

    with (
        patch("hydra.plugins.mtproto_zig.plugin.HOST", _Host()),
        patch("hydra.plugins.mtproto_zig.plugin.WEB_SERVICE_FILE", unit),
    ):
        plugin.on_disable(state)

    assert ["systemctl", "disable", "--now", "mtproto-zig"] in commands
    assert ["systemctl", "disable", "--now", "mtproto-zig-web"] in commands
    assert not unit.exists(), "the relay unit must not survive a disable"


@pytest.mark.parametrize("stage", ["page", "upgrade"])
def test_probe_respects_the_absolute_deadline(stage):
    """One deadline covers page and upgrade; an expired budget fails closed."""
    token = "A" * 43
    relay = _Relay()
    pages = _ScriptedTls(lambda _request: _bridge_page(token))
    upgrade = _ScriptedTls(relay.respond)
    connections = {"count": 0}

    def connect(*_args):
        connections["count"] += 1
        return pages if connections["count"] == 1 else upgrade

    def clock():
        if stage == "upgrade":
            return 0.0 if connections["count"] < 2 else 100.0
        return 0.0 if connections["count"] == 0 else 100.0

    with (
        patch.object(bridge_probe, "_tls_connection", side_effect=connect),
        patch.object(bridge_probe, "_now", side_effect=clock),
    ):
        healthy, detail = bridge_probe.probe_bridge(
            WEB_DOMAIN,
            capability=bridge_capability("00" * 16, WEB_DOMAIN),
            timeout=1.0,
        )

    assert healthy is False
    assert "время" in detail, f"the {stage} stage must consume the shared deadline"
    if stage == "upgrade":
        assert pages.requests and upgrade.requests, "the page must complete before the upgrade expires"


@pytest.mark.parametrize(
    "forbidden",
    ["mtbuddy", "bootstrap.sh", "nginx", "/opt/mtproto-proxy"],
)
def test_zig_package_never_executes_an_upstream_manager(forbidden):
    """Only real argv/URL literals count: prose may name what we refuse to run."""
    package = Path(configuration.__file__).parent

    for path in package.glob("*.py"):
        literals = _string_literals(path.read_text(encoding="utf-8"))
        offenders = [value for value in literals if forbidden in value]
        assert offenders == [], f"{path.name}: {offenders}"


def test_zig_package_never_spawns_a_process_itself():
    package = Path(configuration.__file__).parent

    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
        } | {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        assert {"subprocess", "os", "shlex"}.isdisjoint(imported), path.name


def test_bridge_capability_matches_the_upstream_wire_format():
    """Golden vector: key 0xDD + 16 secret bytes, context prefix + canonical host."""
    capability = bridge_capability("00" * 16, "relay.example")

    assert capability == "Qi4XNwN_VfbcZtgrhGFEsI-sLnSxfO4fQoQo42WehHg"
    assert len(capability) == 43
    assert "=" not in capability
    assert bridge_capability("00" * 16, "other.example") != capability
    assert bridge_capability("11" + "00" * 15, "relay.example") != capability


class _ScriptedTls:
    """TLS socket double that answers each request through one responder."""

    def __init__(self, responder) -> None:
        self._responder = responder
        self._buffer = bytearray()
        self.requests: list[bytes] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def sendall(self, payload: bytes) -> None:
        self.requests.append(payload)
        self._buffer.extend(self._responder(payload))

    def recv(self, size: int) -> bytes:
        chunk = bytes(self._buffer[:size])
        del self._buffer[:size]
        return chunk

    def settimeout(self, _timeout: float) -> None:
        return None


def _bridge_page(token: str, ws_path: str = bridge_probe.WEB_WS_PATH) -> bytes:
    body = (
        '<html><head><meta name="tproxy-token" content="'
        + token
        + '"><meta name="tproxy-ws-path" content="'
        + ws_path
        + '"></head></html>'
    ).encode()
    return b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def _request_header(request: bytes, name: str) -> str:
    """Read one header from a captured request, refusing to guess."""
    prefix = f"{name}: ".encode()
    for line in request.split(b"\r\n"):
        if line.startswith(prefix):
            return line[len(prefix) :].decode()
    raise AssertionError(f"missing header {name}")


def _ws_frame(payload: bytes, *, opcode: int = bridge_probe.OPCODE_BINARY) -> bytes:
    """Wrap a bridge frame in one unmasked server WebSocket frame."""
    return bytes([0x80 | opcode, len(payload)]) + payload


def _unmask_ws_frame(frame: bytes) -> bytes:
    """Decode one masked client WebSocket frame into its bridge payload."""
    assert frame[0] == 0x80 | bridge_probe.OPCODE_BINARY, f"unexpected opcode {frame[0]:#x}"
    length = frame[1] & 0x7F
    mask = frame[2:6]
    payload = frame[6 : 6 + length]
    return bytes(value ^ mask[index % 4] for index, value in enumerate(payload))


class _Relay:
    """Relay double that only welcoms a client which greeted it with HELLO."""

    # Frozen at import: patching the probe's HELLO must never patch the
    # expected greeting too, or the refusal branch would become dead code.
    HELLO = bridge_probe.hello_frame()

    def __init__(
        self,
        *,
        status: int = 101,
        accept: str | None = None,
        welcome: bytes | None = None,
    ) -> None:
        self.status = status
        self.accept = accept
        self.welcome = welcome if welcome is not None else _ws_frame(bridge_probe.welcome_frame())
        self.hello: bytes | None = None

    def respond(self, request: bytes) -> bytes:
        if request.startswith(b"GET "):
            return self._handshake(request)
        self.hello = _unmask_ws_frame(request)
        if self.hello != self.HELLO:
            # A relay refuses a missing or malformed HELLO and never welcoms.
            return b""
        return self.welcome

    def _handshake(self, request: bytes) -> bytes:
        if self.status != 101:
            return f"HTTP/1.1 {self.status} Forbidden\r\nContent-Length: 0\r\n\r\n".encode()
        key = _request_header(request, "Sec-WebSocket-Key")
        protocol = _request_header(request, "Sec-WebSocket-Protocol")
        expected = base64.b64encode(hashlib.new("sha1", f"{key}{bridge_probe.WEBSOCKET_GUID}".encode()).digest())
        return (
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {(self.accept or expected.decode())}\r\n"
            f"Sec-WebSocket-Protocol: {protocol}\r\n\r\n"
        ).encode()


def _probe_with(pages, upgrades):
    """Run the bridge probe against scripted page and upgrade sockets."""
    queue = [(_ScriptedTls(responder)) for responder in (pages, upgrades)]

    def connect(_domain, _address, _port, _timeout):
        return queue.pop(0)

    with patch.object(bridge_probe, "_tls_connection", side_effect=connect):
        return bridge_probe.probe_bridge(WEB_DOMAIN, capability=bridge_capability("00" * 16, WEB_DOMAIN))


def test_bridge_probe_sends_hello_and_requires_the_relay_welcome():
    token = "A" * 43
    relay = _Relay()
    pages = _ScriptedTls(lambda _request: _bridge_page(token))
    upgrade = _ScriptedTls(relay.respond)
    queue = [pages, upgrade]

    with patch.object(bridge_probe, "_tls_connection", side_effect=lambda *_args: queue.pop(0)):
        healthy, detail = bridge_probe.probe_bridge(WEB_DOMAIN, capability=bridge_capability("00" * 16, WEB_DOMAIN))

    assert (healthy, detail) == (True, "")
    # HELLO must arrive before WELCOME is read, with the upstream wire bytes.
    assert relay.hello == bridge_probe.hello_frame()
    assert relay.hello == b"\x10\x00\x00\x00\x00\x00\x00\x01\x01"
    assert pages.requests[0].startswith(b"GET /?bridge="), "the page needs the capability"
    request = upgrade.requests[0]
    assert b"Upgrade: websocket\r\n" in request
    assert b"Sec-WebSocket-Version: 13\r\n" in request
    assert f"Origin: https://{WEB_DOMAIN}\r\n".encode() in request
    assert f"Sec-WebSocket-Protocol: tproxy-v1.{token}\r\n".encode() in request
    assert f"Host: {WEB_DOMAIN}\r\n".encode() in request


def test_bridge_probe_fails_when_the_relay_withholds_welcome():
    token = "A" * 43
    relay = _Relay(welcome=b"")

    healthy, detail = _probe_with(lambda _request: _bridge_page(token), relay.respond)

    assert relay.hello == bridge_probe.hello_frame(), "the probe must still greet the relay"
    assert healthy is False
    assert detail


def test_bridge_probe_fails_when_its_hello_is_malformed():
    """A wrong HELLO must hit the relay refusal, not a permissive double."""
    token = "A" * 43
    relay = _Relay()
    malformed = b"\x10\x00\x00\x00\x00\x00\x00\x01\x02"

    with patch.object(bridge_probe, "hello_frame", return_value=malformed):
        healthy, detail = _probe_with(lambda _request: _bridge_page(token), relay.respond)

    assert relay.hello == malformed, "the relay double must have seen the bad greeting"
    assert healthy is False
    assert detail


def test_bridge_probe_fails_when_no_hello_frame_is_sent():
    """Regression guard: a client that never greets is refused, never welcomed."""
    token = "A" * 43
    relay = _Relay()

    with patch.object(bridge_probe, "_send_ws_frame") as send:
        healthy, detail = _probe_with(lambda _request: _bridge_page(token), relay.respond)

    send.assert_called_once()
    assert relay.hello is None, "no greeting reached the relay, so no WELCOME can arrive"
    assert healthy is False
    assert detail


def test_bridge_probe_rejects_a_wrong_welcome_frame():
    token = "A" * 43
    relay = _Relay(welcome=_ws_frame(b"\x12\x00\x00\x00\x00\x00\x00\x00"))

    healthy, detail = _probe_with(lambda _request: _bridge_page(token), relay.respond)

    assert healthy is False
    assert "WELCOME" in detail


def test_bridge_probe_rejects_a_page_without_authenticated_metadata():
    healthy, detail = _probe_with(
        lambda _request: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        _Relay().respond,
    )

    assert healthy is False
    assert "авторизованные метаданные" in detail


def test_bridge_probe_rejects_a_page_that_is_not_served():
    healthy, detail = _probe_with(
        lambda _request: b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        _Relay().respond,
    )

    assert healthy is False
    assert "HTTP 404" in detail


def test_bridge_probe_rejects_a_non_upgrade_answer():
    token = "B" * 43
    healthy, detail = _probe_with(
        lambda _request: _bridge_page(token),
        _Relay(status=403).respond,
    )

    assert healthy is False
    assert "HTTP 403" in detail


def test_bridge_probe_rejects_a_wrong_accept_token():
    token = "C" * 43
    healthy, detail = _probe_with(
        lambda _request: _bridge_page(token),
        _Relay(accept="not-the-accept").respond,
    )

    assert healthy is False
    assert "Sec-WebSocket-Accept" in detail


def test_bridge_probe_requires_a_capability():
    healthy, detail = bridge_probe.probe_bridge(WEB_DOMAIN, capability="too-short")

    assert healthy is False
    assert "capability" in detail


def test_cover_site_is_never_accepted_as_the_bridge_page(tmp_path):
    """R15.2: publishing a site must not make the readiness proof accept it."""
    from hydra.core.decoy_sites import builder
    from hydra.core.decoy_sites.identity import build_identity
    from hydra.core.decoy_sites.registry import get_theme

    site = tmp_path / "decoy-zig"
    theme = get_theme("landing")
    builder.build(site, theme.name, theme.render, build_identity(WEB_DOMAIN))
    index = (site / "index.html").read_bytes()
    page = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(index)).encode() + b"\r\n\r\n" + index

    healthy, detail = _probe_with(lambda _request: page, _Relay().respond)

    assert healthy is False
    assert "авторизованные метаданные" in detail


def test_malformed_navigation_with_a_capability_stays_refused():
    """Upstream answers 404 for a malformed navigation carrying a real capability.

    The probe always sends a well-formed navigation, so this pins the relay
    answer it must keep refusing once a public site is configured.
    """
    healthy, detail = _probe_with(
        lambda _request: b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found",
        _Relay().respond,
    )

    assert healthy is False
    assert "HTTP 404" in detail
