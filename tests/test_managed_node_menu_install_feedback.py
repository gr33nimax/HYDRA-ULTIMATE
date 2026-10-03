from types import SimpleNamespace

import pytest

from hydra.ui._menus import managed_nodes


@pytest.mark.parametrize("failure", ["reported", "raised"])
def test_install_error_remains_until_acknowledged_before_menu_redraw(monkeypatch, failure):
    events = []
    choices = iter(("1", "0"))
    state = object()
    app = SimpleNamespace(
        nodes=SimpleNamespace(list=lambda: [], list_cascades=lambda: []),
        admin=SimpleNamespace(load_state=lambda: state),
    )

    def error(message):
        events.append(("error", message))

    def install(active, application):
        assert active is state and application is app
        if failure == "raised":
            raise RuntimeError("source revision lookup failed")
        error("Этап bootstrap: remote bootstrap failed")
        return None

    monkeypatch.setattr(managed_nodes, "install_node", install)
    monkeypatch.setattr(managed_nodes, "clear", lambda: events.append(("clear", "")))
    monkeypatch.setattr(managed_nodes, "menu", lambda *_args: next(choices))
    monkeypatch.setattr(managed_nodes, "error", error)
    monkeypatch.setattr(managed_nodes, "prompt", lambda text: events.append(("acknowledge", text)))

    managed_nodes.menu_nodes(state, app)

    kinds = [kind for kind, _ in events]
    assert kinds == ["clear", "error", "acknowledge", "clear"]
    assert events[1][1].endswith("failed")
    assert "Enter" in events[2][1]
