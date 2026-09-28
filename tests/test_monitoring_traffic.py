"""Monitoring traffic view: honest availability, labels, status and geometry."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.mtproto_zig.plugin import MtprotoZigPlugin
from hydra.services.protocols import ProtocolService
from hydra.services.traffic import TrafficService, protocol_totals
from hydra.ui._menus.monitoring_support import (
    ACCOUNTING_WIDTH,
    PROTOCOL_WIDTH,
    SHARE_WIDTH,
    STATUS_WIDTH,
    TABLE_WIDTH,
    TRAFFIC_WIDTH,
    _cell,
    _share_bar,
    _status_text,
)
from hydra.ui._menus.monitoring_traffic import (
    _TrafficView,
    _load_traffic_view,
    _protocol_row,
    _render_protocol_traffic,
)
from hydra.ui.tui import _strip, visible_width

PREFIX = 2
TRAFFIC_START = PREFIX + PROTOCOL_WIDTH + 1
SHARE_START = TRAFFIC_START + TRAFFIC_WIDTH + 2
ACCOUNTING_START = SHARE_START + SHARE_WIDTH + 1
STATUS_START = ACCOUNTING_START + ACCOUNTING_WIDTH + 1


class _FakeProtocols:
    """Traffic port with injectable snapshots, reasons and enabled names."""

    def __init__(self, *, names=("demo",), snapshots=None, reasons=None):
        self.names = set(names)
        self.snapshots = dict(snapshots or {})
        self.reasons = dict(reasons or {})

    def enabled_names(self, state):
        return set(self.names)

    def traffic(self, state, name):
        return dict(self.snapshots.get(name) or {})

    def traffic_snapshot(self, state, name):
        return self.snapshots.get(name)

    def traffic_source_reason(self, state, name):
        return self.reasons.get(name, "")

    def aggregate_traffic_snapshot(self, state, name):
        return None

    def ingest_traffic(self, state, name, cursors):
        return None


def _plugin(name):
    return SimpleNamespace(meta=SimpleNamespace(name=name, display_name=""))


def _app(service, state, plugins):
    app = MagicMock()
    app.traffic.refresh_state.return_value = state
    app.traffic.protocol_totals.side_effect = service.protocol_totals
    app.traffic.source_availability.side_effect = service.source_availability
    app.protocols.enabled_names.return_value = set(service.protocols.names)
    app.protocols.list.return_value = plugins
    app.protocols.display_name.side_effect = lambda name: ""
    app.protocols.status.side_effect = lambda name, s=None: SimpleNamespace(
        installed=True,
        running=True,
        enabled=True,
    )
    return app


def _view(
    names,
    *,
    by_protocol=None,
    enabled=None,
    runtime=None,
    reasons=None,
    labels=None,
    aggregate=None,
):
    by_protocol = dict(by_protocol or {})
    return _TrafficView(
        state=AppState(),
        by_protocol=by_protocol,
        enabled_names=set(enabled if enabled is not None else names),
        names=list(names),
        labels=dict(labels or {}),
        aggregate_totals=dict(aggregate or {}),
        legacy_unattributed=0,
        total_traffic=sum(by_protocol.values()),
        runtime=dict(runtime or {name: (True, True) for name in names}),
        source_reasons=dict(reasons or {}),
    )


def test_table_width_matches_the_design_layout():
    assert TABLE_WIDTH == 77
    assert PROTOCOL_WIDTH == 16
    assert TRAFFIC_WIDTH == 12
    assert SHARE_WIDTH == 23
    assert ACCOUNTING_WIDTH == 13
    assert STATUS_WIDTH == 8


def test_snapshot_reaches_the_monitoring_view_through_credentials_and_report_totals():
    user = User(email="a@example.com", uuid="u1")
    state = AppState(users=[user], protocols={"demo": PluginState(enabled=True)})
    protocols = _FakeProtocols(snapshots={"demo": {user.email: 500}})
    service = TrafficService(protocols=protocols)

    service.refresh(state)

    assert user.credentials["demo"]["traffic_used_bytes"] == 500
    assert service.protocol_totals(state) == {"demo": 500}

    view = _load_traffic_view(_app(service, state, [_plugin("demo")]))

    assert view.by_protocol == {"demo": 500}
    assert view.names == ["demo"]
    assert view.source_reasons == {"demo": ""}
    assert view.runtime == {"demo": (True, True)}
    assert view.total_traffic == 500


def test_protocol_service_exposes_the_plugin_source_reason():
    """The production boundary: ProtocolService -> PluginInvoker -> plugin."""
    plugin = MtprotoZigPlugin()
    plugin._traffic_reason = "control API недоступен (URLError)"
    catalog = MagicMock()
    catalog.get.side_effect = lambda name: plugin if name == "mtproto_zig" else None
    catalog.transports.return_value = [plugin]
    catalog.enhancements.return_value = []
    catalog.security.return_value = []
    protocol_service = ProtocolService(operations=MagicMock(), catalog=catalog)
    state = AppState(protocols={"mtproto_zig": PluginState(enabled=True)})

    availability = TrafficService(protocols=protocol_service).source_availability(state)

    assert availability == {"mtproto_zig": plugin._traffic_reason}


def test_unavailable_source_is_rendered_instead_of_a_zero(capsys):
    view = _view(
        ["mtproto_zig"],
        by_protocol={"mtproto_zig": 0},
        reasons={"mtproto_zig": "control API недоступен"},
        labels={"mtproto_zig": "MTProto Zig"},
    )

    _render_protocol_traffic(view)

    row = next(line for line in capsys.readouterr().out.splitlines() if "MTProto Zig" in line)
    assert "источник недоступен" in row
    assert "0 B" not in row
    assert "MTProto Zig" in row


def test_protocol_rows_keep_the_77_cell_layout_for_short_and_long_labels():
    names = ["short", "amneziawg_mobile", "a_very_long_protocol_name"]
    view = _view(names, by_protocol={name: 500 for name in names})

    for name in names:
        line = _strip(_protocol_row(view, name))
        assert visible_width(line) == PREFIX + TABLE_WIDTH
        assert line[PREFIX : PREFIX + PROTOCOL_WIDTH] == _cell(name, PROTOCOL_WIDTH)
        assert line[PREFIX + PROTOCOL_WIDTH] == " "
        assert line[TRAFFIC_START : TRAFFIC_START + TRAFFIC_WIDTH].strip() == "500 B"
        assert line[SHARE_START] == "█"
        assert line[SHARE_START - 1] == " "
        assert line[ACCOUNTING_START : ACCOUNTING_START + ACCOUNTING_WIDTH].strip() == "по пользов."
        assert line[STATUS_START : STATUS_START + STATUS_WIDTH].strip() == "Работает"

    assert _cell("amneziawg_mobile", PROTOCOL_WIDTH) == "amneziawg_mobile"
    truncated = _cell("a_very_long_protocol_name", PROTOCOL_WIDTH)
    assert truncated == "a_very_long_pro…"
    assert visible_width(truncated) == PROTOCOL_WIDTH


def test_protocol_table_header_and_divider_match_the_column_layout(capsys):
    _render_protocol_traffic(_view(["short"]))

    output = capsys.readouterr().out
    header = next(line for line in output.splitlines() if "Протокол" in line)
    divider = next(line for line in output.splitlines() if "─" in line)
    assert visible_width(_strip(header)) == PREFIX + TABLE_WIDTH
    assert _strip(divider) == "  " + "─" * TABLE_WIDTH


def test_status_column_reports_runtime_state_not_desired_enablement():
    view = _view(["demo"], enabled={"demo"}, runtime={"demo": (True, False)})

    row = _strip(_protocol_row(view, "demo"))

    assert "включён" not in row
    assert "Не рабо" in row
    assert _status_text(True, True, False) == "Не работает"
    assert _status_text(True, True, True) == "Работает"
    assert _status_text(False, True, False) == "Не установлен"
    assert _status_text(True, False, False) == "Отключён"


def test_share_bar_is_23_cells_and_small_nonzero_shares_show_one_block():
    assert visible_width(_share_bar(3, 100)) == SHARE_WIDTH
    assert _share_bar(3, 100).count("█") == 1
    assert _share_bar(1, 1000).count("█") == 1
    assert _share_bar(0, 100).count("█") == 0
    assert _share_bar(100, 100).count("█") == 16


def test_table_geometry_does_not_depend_on_terminal_width(monkeypatch):
    monkeypatch.setattr("hydra.ui.tui.TERM_WIDTH", 40)
    monkeypatch.setattr("hydra.ui.tui.PANEL_W", 36)

    line = _strip(_protocol_row(_view(["demo"], by_protocol={"demo": 500}), "demo"))

    assert visible_width(line) == PREFIX + TABLE_WIDTH


def test_profile_credentials_do_not_become_protocols(capsys):
    user = User(email="a@example.com", uuid="u1")
    user.credentials["amneziawg"] = {"traffic_used_bytes": 700}
    user.credentials["amneziawg_mobile"] = {"mobile_key": "secret"}
    state = AppState(
        users=[user],
        protocols={
            "amneziawg": PluginState(enabled=True),
            "zero_proto": PluginState(enabled=True),
        },
    )
    protocols = _FakeProtocols(names=("amneziawg", "zero_proto"))
    service = TrafficService(protocols=protocols)

    service.refresh(state)

    assert protocol_totals(state) == {"amneziawg": 700}

    view = _load_traffic_view(
        _app(service, state, [_plugin("amneziawg"), _plugin("zero_proto")])
    )
    assert view.names == ["amneziawg", "zero_proto"]

    _render_protocol_traffic(view)
    output = capsys.readouterr().out
    rows = [line for line in output.splitlines() if line.strip() and "─" not in line]
    assert sum("AmneziaWG" in line for line in rows) == 1
    assert any("zero_proto" in line for line in rows)
    assert "amneziawg_mobile" not in output
