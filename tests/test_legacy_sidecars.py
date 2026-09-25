"""Legacy WARP/AmneziaWG sidecar teardown: idempotent, safe-only, wired."""

from __future__ import annotations

from types import SimpleNamespace

from hydra.core import legacy_sidecars as ls


class FakeHost:
    """Records commands; answers by exact argv match, else returncode 1."""

    def __init__(self, answers: dict[str, tuple[int, str]] | None = None) -> None:
        self.answers = answers or {}
        self.calls: list[list[str]] = []

    def run(self, args, **_kwargs):
        argv = [str(a) for a in args]
        self.calls.append(argv)
        code, out = self.answers.get(" ".join(argv), (1, ""))
        return SimpleNamespace(returncode=code, stdout=out)


def test_purge_is_a_noop_on_a_clean_host(tmp_path, monkeypatch):
    monkeypatch.setattr(ls, "_LEGACY_FILES", ())
    monkeypatch.setattr(ls, "_LEGACY_TREES", ())
    host = FakeHost()  # every probe returns rc=1 → nothing present
    removed = ls.purge_legacy_sidecars(host)
    assert removed == {"units": [], "interfaces": [], "iptables": [], "files": []}
    # no destructive command was issued
    assert not any(c[:2] == ["systemctl", "disable"] for c in host.calls)
    assert not any(c[:3] == ["ip", "link", "delete"] for c in host.calls)


def test_purge_disables_present_units(monkeypatch):
    monkeypatch.setattr(ls, "_LEGACY_FILES", ())
    monkeypatch.setattr(ls, "_LEGACY_TREES", ())
    host = FakeHost(
        {
            "systemctl list-unit-files awg-quick@awg0.service --no-legend": (0, "awg-quick@awg0.service enabled"),
        }
    )
    removed = ls.purge_legacy_sidecars(host)
    assert "awg-quick@awg0" in removed["units"]
    assert ["systemctl", "disable", "--now", "awg-quick@awg0"] in host.calls
    # a unit that is neither listed nor active is left alone
    assert "wg-quick@wg-warp" not in removed["units"]


def test_purge_deletes_present_interface(monkeypatch):
    monkeypatch.setattr(ls, "_LEGACY_FILES", ())
    monkeypatch.setattr(ls, "_LEGACY_TREES", ())
    host = FakeHost({"ip link show awg0": (0, "3: awg0: <POINTOPOINT>")})
    removed = ls.purge_legacy_sidecars(host)
    assert "awg0" in removed["interfaces"]
    assert ["ip", "link", "delete", "awg0"] in host.calls
    assert "wg-warp" not in removed["interfaces"]


def test_purge_removes_only_iptables_rules_that_name_the_interface(monkeypatch):
    monkeypatch.setattr(ls, "_LEGACY_FILES", ())
    monkeypatch.setattr(ls, "_LEGACY_TREES", ())
    dump = (
        "-A POSTROUTING -s 10.67.67.0/24 -o awg0 -j MASQUERADE\n"
        "-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE\n"
    )
    host = FakeHost({"iptables-save -t nat": (0, dump)})
    removed = ls.purge_legacy_sidecars(host)
    assert any("awg0" in rule for rule in removed["iptables"])
    assert [
        "iptables", "-t", "nat", "-D", "POSTROUTING",
        "-s", "10.67.67.0/24", "-o", "awg0", "-j", "MASQUERADE",
    ] in host.calls
    # the unrelated eth0 rule is never touched
    assert not any(c[:1] == ["iptables"] and "eth0" in c for c in host.calls)


def test_remove_path_handles_file_dir_and_absent(tmp_path):
    file_path = tmp_path / "conf"
    file_path.write_text("x", encoding="utf-8")
    tree = tmp_path / "install"
    tree.mkdir()
    (tree / "inner").write_text("y", encoding="utf-8")
    absent = tmp_path / "absent"

    removed: dict[str, list[str]] = {"files": []}
    ls._remove_path(file_path, removed)
    ls._remove_path(tree, removed)
    ls._remove_path(absent, removed)

    assert not file_path.exists()
    assert not tree.exists()
    assert str(file_path) in removed["files"]
    assert str(tree) in removed["files"]
    assert str(absent) not in removed["files"]


def test_migrate_state_reports_sidecar_purge_when_something_was_removed():
    from hydra.services.system import SystemService

    service = SystemService(
        validate_state=lambda state: None,
        doctor_check=lambda state: {},
        upgrade_readiness=lambda state: {},
        migrate_persisted_state=lambda: {"imported": True},
        purge_sidecars=lambda: {"units": ["awg-quick@awg0"], "interfaces": [], "iptables": [], "files": []},
    )
    result = service.migrate_state()
    assert result["imported"] is True
    assert result["legacy_sidecars"]["units"] == ["awg-quick@awg0"]


def test_migrate_state_omits_sidecars_when_nothing_was_removed():
    from hydra.services.system import SystemService

    service = SystemService(
        validate_state=lambda state: None,
        doctor_check=lambda state: {},
        upgrade_readiness=lambda state: {},
        migrate_persisted_state=lambda: {"imported": True},
        purge_sidecars=lambda: {"units": [], "interfaces": [], "iptables": [], "files": []},
    )
    result = service.migrate_state()
    assert "legacy_sidecars" not in result
