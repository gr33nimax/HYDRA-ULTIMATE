from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "upgrade.sh"


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_existing_install_updater_is_transactional_and_dev_by_default():
    source = _source()
    assert 'HYDRA_REF="${HYDRA_REF:-dev}"' in source
    assert "git ls-remote --exit-code" in source
    assert 'flock -n 9' in source
    assert 'python3 -m venv "$STAGE_DIR/.venv"' in source
    assert "-m hydra.cli upgrade check" in source
    assert "-m hydra.cli upgrade migrate-state" in source
    assert "hydra-backup.tar.gz" in source
    assert "wait_for_previous_units" in source


def test_upgrade_orders_preflight_backup_migration_and_cutover_safely():
    source = _source()
    preflight = source.index('info "Running read-only target preflight')
    quiesce = source.index('info "Quiescing')
    snapshot = source.index('cp -a "$STATE_DIR" "$ROLLBACK_DIR/state-before-upgrade"')
    backup = source.index('info "Creating and verifying an application-level backup"')
    migration = source.index('info "Persisting the target state schema')
    cutover = source.index('info "Switching /opt entrypoint')

    assert preflight < quiesce < snapshot < backup < migration < cutover


def test_rollback_restores_state_before_old_code_and_services():
    source = _source()
    rollback_start = source.index("rollback() {")
    rollback_end = source.index("trap 'rollback", rollback_start)
    rollback = source[rollback_start:rollback_end]

    assert rollback.index("stop_managed_units") < rollback.index(
        "restore_state_snapshot",
    )
    assert rollback.index("restore_state_snapshot") < rollback.index(
        "restore_installation",
    )
    assert rollback.index("restore_installation") < rollback.index(
        "start_previous_units",
    )


def test_updater_never_mutates_the_current_git_checkout_in_place():
    source = _source()
    forbidden = (
        'git -C "$INSTALL_DIR" checkout',
        'git -C "$INSTALL_DIR" pull',
        'git -C "$INSTALL_DIR" reset',
    )
    assert all(command not in source for command in forbidden)
