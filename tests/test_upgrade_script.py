import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "upgrade.sh"
LAUNCHER = ROOT / "updater.sh"
UPGRADE_DOCS = (ROOT / "README.md", ROOT / "docs" / "UPGRADE.md")


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
    assert "-m hydra.cli --json upgrade check" in source
    assert "-m hydra.cli --json upgrade migrate-state" in source
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
    ) == 6
    assert len(
        re.findall(
            r"(?m)^\s*run_install_python\s+(?:\\\s*)?-m hydra\.cli\b",
            source,
        ),
    ) == 2


def test_upgrade_orders_preflight_backup_migration_and_cutover_safely():
    source = _source()
    preflight = source.index('step 4 7 "Безопасная проверка перед обновлением"')
    quiesce = source.index('info "Останавливаю активные службы HYDRA')
    snapshot = source.index('cp -a "$STATE_DIR" "$STATE_ROLLBACK_DIR"')
    backup = source.index('info "Создаю и проверяю резервную копию"')
    migration = source.index('info "Мигрирую state при остановленных службах"')
    mutation = source.index("STATE_MUTATION_STARTED=1", migration)
    cutover = source.index('step 6 7 "Переключение на новый release"')

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
            "curl -fsSL https://raw.githubusercontent.com/gr33nimax/"
            "HYDRA-ULTIMATE/dev/updater.sh | sudo bash"
        ) in documentation
        assert "upgrade_script=$(mktemp)" not in documentation
        assert '-o "$upgrade_script"' not in documentation


def test_one_command_launcher_downloads_engine_completely_before_execution():
    source = LAUNCHER.read_text(encoding="utf-8")

    assert 'HYDRA_REF="${HYDRA_REF:-dev}"' in source
    assert 'UPGRADE_SCRIPT=$(mktemp /tmp/hydra-updater.XXXXXX)' in source
    assert '"${RAW_BASE}/${HYDRA_REF}/upgrade.sh"' in source
    assert '-o "$UPGRADE_SCRIPT"' in source
    assert source.index('-o "$UPGRADE_SCRIPT"') < source.index(
        'env HYDRA_REF="$HYDRA_REF" HYDRA_UPDATER_LAUNCHED=1',
    )
    assert "git check-ref-format --branch" in source
    assert 'trap cleanup EXIT HUP INT TERM' in source


def test_updater_has_numbered_progress_and_clear_terminal_states():
    launcher = LAUNCHER.read_text(encoding="utf-8")
    engine = _source()

    assert 'title "ОБНОВЛЕНИЕ HYDRA"' in launcher
    assert 'step 1 3 "Проверка запуска"' in launcher
    assert 'step 3 3 "Транзакционное обновление"' in launcher
    assert 'step 1 7 "Проверка установленной версии"' in engine
    assert 'step 7 7 "Итоговая проверка"' in engine
    assert 'result_ok "HYDRA обновлена' in engine
    assert 'result_ok "Обновление не требуется' in engine
    assert 'result_error "Обновление не завершено' in engine


def test_all_dev_install_and_update_entrypoints_default_to_dev():
    bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
    launcher = LAUNCHER.read_text(encoding="utf-8")
    engine = _source()

    assert 'DEFAULT_BRANCH="dev"' in bootstrap
    assert 'HYDRA_REF="${HYDRA_REF:-dev}"' in launcher
    assert 'HYDRA_REF="${HYDRA_REF:-dev}"' in engine
