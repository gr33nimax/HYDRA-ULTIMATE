from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra.ui import tui
from hydra.ui.plugin_managers import telemt as telemt_facade
from hydra.ui.plugin_managers import wdtt as wdtt_facade
from hydra.ui.plugin_managers import _wdtt_headless
from hydra.ui.plugin_managers._facade_bridge import bind_facade


def test_wrapped_panel_line_preserves_long_colored_uri() -> None:
    link = (
        "qwdtt://config?name=qWDTT-test&peer=203.0.113.10:56000"
        "&hashes=" + ",".join(f"hash-{index}-" + "x" * 30 for index in range(4))
        + "&password=" + "secret" * 12
    )
    colored = f"\033[1;33m{link}\033[0m"

    wrapped = tui._wrap_line(colored, 24)

    assert "".join(tui._strip(chunk) for chunk, _width in wrapped) == link
    assert all(width <= 24 for _chunk, width in wrapped)
    assert len(wrapped) > 1


def test_panel_wrap_renders_the_uri_tail_instead_of_ellipsis(capsys) -> None:
    link = "tg://proxy?server=203.0.113.10&secret=" + "abcdef" * 30

    tui.panel("LINK", [link], wrap=True)

    output = tui._strip(capsys.readouterr().out)
    assert "..." not in output
    assert link[:40] in output
    assert link[-40:] in output


def test_qwdtt_master_link_panel_enables_lossless_wrapping() -> None:
    link = "qwdtt://config?" + "hashes=" + "x" * 240
    app = SimpleNamespace()

    with (
        patch.object(wdtt_facade, "panel") as panel,
        patch.object(wdtt_facade, "_save_link_to_file"),
        bind_facade(wdtt_facade),
    ):
        _wdtt_headless._show_master_link(link, app, save=False)

    assert panel.call_args.args[1][-1] == link
    assert panel.call_args.kwargs == {"wrap": True}


def test_telemt_links_panel_enables_lossless_wrapping() -> None:
    link = "tg://proxy?server=203.0.113.10&port=443&secret=" + "a" * 96
    state = SimpleNamespace(
        users=[SimpleNamespace(email="user@example.com", blocked=False)],
    )
    app = SimpleNamespace(
        protocols=SimpleNamespace(client_links=MagicMock(return_value=[link])),
    )

    with (
        patch.object(telemt_facade, "clear"),
        patch.object(telemt_facade, "panel") as panel,
        patch.object(telemt_facade, "_pause"),
    ):
        telemt_facade._view_links(state, app)

    assert link in panel.call_args.args[1][1]
    assert panel.call_args.kwargs == {"wrap": True}
