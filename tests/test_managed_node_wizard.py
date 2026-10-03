from __future__ import annotations

from types import SimpleNamespace

from hydra.contracts.managed_node_installation import InstallPlan
from hydra.contracts.managed_node_models import NodeDefinition, Operation, ProtocolAssignment
from hydra.ui._menus import nodes_setup
from hydra.ui._menus.node_protocol_fields import collect_protocol_config, preflight_protocol

_FINGERPRINT = "SHA256:" + "A" * 43
_SHA = "a" * 40


def _fake_fields(monkeypatch, calls):
    fields = {
        "ID ноды": "de-1",
        "Имя ноды": "Germany",
        "IP-адрес ноды": "203.0.113.4",
        "Пользователь SSH": "operator",
        "SSH-порт": "2222",
        "TCP-порт управления (1024–65535)": "24443",
    }

    def required(label, default=""):
        del default
        calls.append(label)
        return fields.get(label)

    monkeypatch.setattr(nodes_setup, "_required", required)
    monkeypatch.setattr(nodes_setup, "ask_secret", lambda _label: calls.append("password") or "")
    monkeypatch.setattr(
        nodes_setup,
        "_collect_protocols",
        lambda _app: calls.append("protocols") or [ProtocolAssignment("vless", {"port": 443})],
    )
    monkeypatch.setattr(nodes_setup, "_confirm_plan", lambda _plan, _count: True)
    monkeypatch.setattr(nodes_setup, "confirm", lambda _message, default=False: True)


def test_install_wizard_uses_identity_branch_port_protocol_order_and_preserves_choices(monkeypatch):
    calls = []
    _fake_fields(monkeypatch, calls)
    menu_choices = iter(("2", "2"))
    monkeypatch.setattr(nodes_setup, "menu", lambda _items, title: calls.append(title) or next(menu_choices))
    captured = {}

    class Nodes:
        def discover_host_key(self, address, port):
            calls.append("host_key")
            assert (address, port) == ("203.0.113.4", 2222)
            return _FINGERPRINT

        def plan(self, request, auth):
            del auth
            calls.append("plan")
            captured["request"] = request
            definition = NodeDefinition(
                request.id,
                request.name,
                request.address,
                request.ssh_user,
                request.branch,
                _SHA,
                request.control_port,
                request.protocols,
                "managed-node/de-1",
                request.ssh_port,
            )
            return InstallPlan(
                definition,
                False,
                ["bootstrap"],
                host_key_fingerprint=_FINGERPRINT,
                source_address="198.51.100.8",
                use_sudo=True,
            )

        def install(self, plan, auth, confirmed, reinstall_confirmed, progress):
            del auth, confirmed, reinstall_confirmed, progress
            calls.append("install")
            return Operation("install-1", "install", plan.definition.id, "b" * 64, "succeeded")

    result = nodes_setup.install_node(SimpleNamespace(users=[]), SimpleNamespace(nodes=Nodes()))
    request = captured["request"]

    assert result is not None and result.state == "succeeded"
    assert request.branch == "dev" and request.control_port == 24443 and request.ssh_port == 2222
    assert calls.index("Пользователь SSH") < calls.index("SSH-порт") < calls.index("password")
    assert calls.index("password") < calls.index("ВЕТКА ДО НАСТРОЙКИ ПРОТОКОЛОВ")
    assert calls.index("ВЕТКА ДО НАСТРОЙКИ ПРОТОКОЛОВ") < calls.index("ПОРТ УПРАВЛЕНИЯ") < calls.index("protocols")
    assert calls.index("protocols") < calls.index("host_key") < calls.index("plan") < calls.index("install")


def test_protocol_parameter_form_rejects_missing_transport_requirements_and_secrets(monkeypatch):
    from hydra.contracts.managed_node_models import ProtocolAssignment
    from hydra.ui._menus import node_protocol_fields

    monkeypatch.setattr(node_protocol_fields, "prompt", lambda _label, _default="": "node.example.com")
    monkeypatch.setattr(node_protocol_fields, "menu", lambda _items, _title: "0")
    parameters = collect_protocol_config("anytls", {})

    assert parameters is not None
    assert parameters == {"domain": "node.example.com"}
    assert not preflight_protocol("anytls", parameters)
    assert preflight_protocol("vless", {"security": "tls"})
    assert not preflight_protocol("vless", {"security": "reality"})
    try:
        ProtocolAssignment("vless", {"port": 443, "private_key": "never-export"}).validate()
    except ValueError as exc:
        assert "secret" in str(exc)
    else:
        raise AssertionError("node-local key material must not cross the managed-node boundary")


def test_cancelled_branch_stops_before_protocol_input_or_mutation(monkeypatch):
    calls = []
    _fake_fields(monkeypatch, calls)
    monkeypatch.setattr(nodes_setup, "menu", lambda _items, title: calls.append(title) or "0")

    result = nodes_setup.install_node(SimpleNamespace(users=[]), SimpleNamespace(nodes=object()))

    assert result is None
    assert "protocols" not in calls
    assert "host_key" not in calls
