from types import SimpleNamespace
from typing import cast

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService
from hydra.ui._menus import root


def test_root_menu_shows_core_identity_without_truncating(monkeypatch):
    version = "sing-box version v1.14.0-extended-2.7.1-hydracore.123456789"
    captured = {}
    state = SimpleNamespace(users=[])
    runtime = SimpleNamespace(installed=True, running=True, version=version)
    app = SimpleNamespace(
        admin=SimpleNamespace(
            load_state=lambda: state,
            system_overview=lambda _: SimpleNamespace(
                cpu_percent=None,
                load_averages=None,
                memory_percent=None,
                memory_used=0,
                memory_total=0,
                disk_percent=None,
                disk_used=0,
                disk_total=0,
                uptime_seconds=None,
                country_flag=None,
                public_ip="127.0.0.1",
                local_ip="127.0.0.1",
                dns="system",
                dnscrypt_active=False,
                dnscrypt_servers=(),
            ),
        ),
        kernel=SimpleNamespace(status=lambda _: SimpleNamespace(runtime=runtime)),
        protocols=SimpleNamespace(statuses=lambda _: {}, list=lambda _: []),
        users=SimpleNamespace(list=lambda _: [], access_status=lambda _: (False, "")),
    )
    deps = root.RootMenuDependencies(*([lambda *_: None] * 8))

    monkeypatch.setattr(root, "clear", lambda: None)
    monkeypatch.setattr(root, "menu", lambda *_: "0")
    monkeypatch.setattr(
        root, "panel", lambda title, lines, **kwargs: captured.update(title=title, lines=lines, **kwargs)
    )

    root.run_main_menu(
        cast(AppState, state),
        cast(ApplicationService, app),
        deps,
    )

    assert captured["title"] == "Состояние"
    assert captured["wrap"]
    assert any("Ядро:" in line and version in line for line in captured["lines"])
