import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "upgrade.sh"
UPGRADE_DOCS = (ROOT / "README.md", ROOT / "docs" / "DEV_UPGRADE.md")


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_existing_install_updater_is_transactional_and_dev_by_default():
    source = _source()
    assert 'HYDRA_REF="${HYDRA_REF:-dev}"' in source
    assert "return 1; }" in source
    assert "exit 1; }" not in source
    assert "git ls-remote --exit-code" in source
    assert 'flock -n 9' in source
    assert 'python3 -m venv "$STAGE_DIR/.venv"' in source
    assert 'PYTHONPATH="$STAGE_DIR"' in source
    assert 'PYTHONPATH="$INSTALL_DIR"' in source
    assert "-m hydra.cli upgrade check" in source
    assert "-m hydra.cli upgrade migrate-state" in source
    assert "hydra-backup.tar.gz" in source
    assert "wait_for_previous_units" in source


def test_target_commands_do_not_depend_on_the_updater_working_directory():
    source = _source()

    stage_helper = source[
        source.index("run_stage_python() {") : source.index(
            "\n}\n",
            source.index("run_stage_python() {"),
        )
    ]
    install_helper = source[
        source.index("run_install_python() {") : source.index(
            "\n}\n",
            source.index("run_install_python() {"),
        )
    ]
    assert 'cd "$STAGE_DIR"' in stage_helper
    assert 'cd "$INSTALL_DIR"' in install_helper
    assert "trap - ERR" in stage_helper
    assert "trap - ERR" in install_helper
    assert len(
        re.findall(
            r"(?m)^\s*run_stage_python\s+(?:\\\s*)?-m hydra\.cli\b",
            source,
        ),
    ) == 7
    assert len(
        re.findall(
            r"(?m)^\s*run_install_python\s+(?:\\\s*)?-m hydra\.cli\b",
            source,
        ),
    ) == 3


def test_upgrade_orders_preflight_backup_migration_and_cutover_safely():
    source = _source()
    preflight = source.index('info "Running read-only target preflight')
    quiesce = source.index('info "Quiescing')
    snapshot = source.index('cp -a "$STATE_DIR" "$STATE_ROLLBACK_DIR"')
    backup = source.index('info "Creating and verifying an application-level backup"')
    migration = source.index('info "Persisting the target state schema')
    mutation = source.index("STATE_MUTATION_STARTED=1", migration)
    cutover = source.index('info "Switching /opt entrypoint')

    assert preflight < quiesce < snapshot < backup < migration < mutation < cutover


def test_rollback_restores_state_before_old_code_and_services():
    source = _source()
    rollback_start = source.index("rollback() {")
    rollback_end = source.index("handle_error() {", rollback_start)
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


def test_directory_cutover_attempt_is_recoverable_before_and_after_the_move():
    source = _source()
    directory_branch = source[
        source.index('PREVIOUS_KIND="directory"') : source.index(
            "\nfi",
            source.index('PREVIOUS_KIND="directory"'),
        )
    ]

    assert directory_branch.index("CUTOVER_STARTED=1") < directory_branch.index(
        'mv "$INSTALL_DIR" "$PREVIOUS_DIR"',
    )
    assert directory_branch.index('mv "$INSTALL_DIR" "$PREVIOUS_DIR"') < (
        directory_branch.index(
            'ln -s "$RELEASE_DIR" "$INSTALL_DIR"',
        )
    )
    assert '[[ -e "$PREVIOUS_DIR" ]] || return 0' in source
    assert "must share a filesystem" in source


def test_symlink_cutover_is_marked_before_atomic_replacement():
    source = _source()
    symlink_branch = source[
        source.index('PREVIOUS_KIND="symlink"') : source.index(
            "\nelse",
            source.index('PREVIOUS_KIND="symlink"'),
        )
    ]

    assert symlink_branch.index("CUTOVER_STARTED=1") < symlink_branch.index(
        'mv -Tf "$CUTOVER_LINK" "$INSTALL_DIR"',
    )


def test_transient_oneshot_services_are_not_expected_to_remain_active():
    source = _source()
    capture = source[
        source.index("capture_active_units() {") : source.index(
            "\n}\n",
            source.index("capture_active_units() {"),
        )
    ]

    assert "--property=ActiveState,Type,RemainAfterExit" in capture
    assert "cannot inspect systemd unit" in capture
    assert '"$unit_type" == "oneshot"' in capture
    assert "continue" in capture


def test_error_and_disconnect_handlers_only_roll_back_in_the_root_shell():
    source = _source()

    assert "UPDATER_BASHPID=$BASHPID" in source
    assert '[[ "$BASHPID" != "$UPDATER_BASHPID" ]]' in source
    assert "trap 'handle_error $? $LINENO' ERR" in source
    assert "trap 'handle_signal 129 $LINENO' HUP" in source
    assert "trap 'handle_signal 130 $LINENO' INT" in source
    assert "trap 'handle_signal 143 $LINENO' TERM" in source
    assert "trap - ERR HUP INT TERM" in source


def test_state_rollback_copy_is_local_and_only_restored_after_mutation():
    source = _source()
    restore = source[
        source.index("restore_state_snapshot() {") : source.index(
            "\n}\n",
            source.index("restore_state_snapshot() {"),
        )
    ]

    assert 'STATE_ROLLBACK_DIR="${STATE_DIR}.upgrade-rollback-' in source
    assert "((STATE_MUTATION_STARTED)) || return 0" in restore
    assert 'mv "$STATE_ROLLBACK_DIR" "$STATE_DIR"' in restore
    assert 'cp -a "$ROLLBACK_DIR/state-before-upgrade" "$STATE_DIR"' not in source


def test_documented_updater_is_fully_downloaded_before_sudo_execution():
    for path in UPGRADE_DOCS:
        documentation = path.read_text(encoding="utf-8")
        assert (
            re.search(
                r"upgrade\.sh[^\n]*\n\s*\|\s*sudo",
                documentation,
            )
            is None
        )
        assert '-o "$upgrade_script"' in documentation
        assert 'sudo env HYDRA_REF=dev bash "$upgrade_script"' in documentation
