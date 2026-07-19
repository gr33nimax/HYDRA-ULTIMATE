from hydra.ui.protocol_ui import (
    protocol_label,
    protocol_menu_title,
    protocol_state,
    protocol_status_panel,
    status_badge,
)


def test_protocol_names_are_product_facing():
    assert protocol_label("amneziawg") == "AmneziaWG"
    assert protocol_label("naive") == "NaiveProxy"
    assert protocol_menu_title("wdtt") == "QWDTT · УПРАВЛЕНИЕ"


def test_protocol_state_distinguishes_disabled_and_failed():
    assert "Отключён" in protocol_state(True, False, False)
    assert "Не работает" in protocol_state(True, True, False)
    assert "Не установлен" in protocol_state(False, False, False)


def test_status_badges_are_explicit_without_relying_on_colour():
    assert "✓ РАБОТАЕТ" in status_badge({"running": True})
    assert "○ ОТКЛЮЧЁН" in status_badge({"installed": True})
    assert "✕ СБОЙ" in status_badge({"installed": True, "enabled": True})
    assert "— НЕ УСТАНОВЛЕН" in status_badge({})
    assert "! ОШИБКА СТАТУСА" in status_badge({"error": "boom"})
    assert "! ЛИШНИЙ ПРОЦЕСС" in status_badge({"running": True, "drift": "unexpectedly_running"})
    assert "! НЕИЗВЕСТНО" in status_badge({"drift": "unknown"})


def test_protocol_panel_has_canonical_field_order(capsys):
    protocol_status_panel(
        "anytls",
        installed=True,
        enabled=True,
        running=True,
        port=443,
        details=[("Домен", "vpn.example")],
    )
    output = capsys.readouterr().out
    assert output.index("Состояние") < output.index("Установлен")
    assert output.index("Установлен") < output.index("Включён")
    assert output.index("Включён") < output.index("Порт")
    assert "AnyTLS" in output
    assert "vpn.example" in output
