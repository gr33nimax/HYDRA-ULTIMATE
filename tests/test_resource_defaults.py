from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_default_resource_policy_bounds_logs_without_hard_memory_caps() -> None:
    journal = (
        ROOT / "deploy" / "90-hydra-journald.conf"
    ).read_text(encoding="utf-8")
    singbox = (
        ROOT / "deploy" / "90-hydra-singbox-memory.conf"
    ).read_text(encoding="utf-8")

    assert "SystemMaxUse=128M" in journal
    assert "RuntimeMaxUse=64M" in journal
    assert "SystemMaxFileSize=16M" in journal
    assert "Environment=GOGC=50" in singbox
    assert "GOMEMLIMIT" not in singbox
    assert "MemoryMax" not in singbox


def test_resource_defaults_are_idempotent_and_used_by_install_and_upgrade() -> None:
    policy = (
        ROOT / "deploy" / "apply-resource-defaults.sh"
    ).read_text(encoding="utf-8")
    bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
    upgrade = (ROOT / "upgrade.sh").read_text(encoding="utf-8")

    assert "cmp -s" in policy
    assert "/etc/systemd/journald.conf.d/90-hydra-journald.conf" in policy
    assert "/etc/systemd/system/sing-box.service.d/90-hydra-memory.conf" in policy
    assert 'journalctl --rotate --vacuum-size=128M' in policy
    assert 'systemctl try-restart sing-box.service' in policy
    invocation = 'bash "$INSTALL_DIR/deploy/apply-resource-defaults.sh"'
    assert invocation in bootstrap
    assert invocation in upgrade
    assert upgrade.index(invocation) < upgrade.index("\nstart_previous_units\n")
