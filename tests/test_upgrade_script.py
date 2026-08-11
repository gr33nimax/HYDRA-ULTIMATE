import re
from pathlib import Path

from hydra.plugins.warp.parsing import parse_wg_conf


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "upgrade.sh"
LAUNCHER = ROOT / "updater.sh"
LINUX_INTEGRATION_SMOKE = (
    ROOT / ".github" / "scripts" / "linux-integration-smoke.sh"
)
LINUX_UPGRADE_SMOKE = ROOT / ".github" / "scripts" / "linux-upgrade-smoke.sh"
UPGRADE_DOCS = (ROOT / "README.md", ROOT / "docs" / "UPGRADE.md")


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_existing_install_updater_is_transactional_and_main_by_default():
    source = _source()
    assert 'HYDRA_REF="${HYDRA_REF:-main}"' in source
    fail_start = source.index("fail() {")
    fail_helper = source[fail_start : source.index("\n}\n", fail_start)]
    assert "return 1" in fail_helper
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


def test_linux_integration_smoke_uses_the_canonical_state_schema_version():
    for script in (LINUX_INTEGRATION_SMOKE, LINUX_UPGRADE_SMOKE):
        source = script.read_text(encoding="utf-8")

        assert "from hydra.core.state_models import SCHEMA_VERSION" in source
        assert 'state["version"] == SCHEMA_VERSION' in source
        assert '= "4"' not in source


def test_linux_upgrade_smoke_uses_the_target_checkout_version():
    source = LINUX_UPGRADE_SMOKE.read_text(encoding="utf-8")

    assert 'PYTHONPATH="$workspace"' in source
    assert '[[ "$installed_version" == "$target_version" ]]' in source
    assert not re.search(
        r'\[\[ "\$installed_version" == "\d+\.\d+\.\d+" \]\]',
        source,
    )


def test_linux_integration_smoke_provisions_the_migrated_warp_runtime():
    source = LINUX_INTEGRATION_SMOKE.read_text(encoding="utf-8")
    marker = 'cat > "$wgcf_profile" <<\'EOF\'\n'
    profile = source.split(marker, 1)[1].split("\nEOF", 1)[0]

    assert 'wgcf_profile=/etc/wireguard/wgcf-profile.conf' in source
    assert 'cat > "$wgcf_profile"' in source
    assert 'chmod 0600 "$wgcf_profile"' in source
    assert 'rm -f "$wgcf_profile"' in source
    assert parse_wg_conf(profile) is not None
    assert source.index('cat > "$wgcf_profile"') < source.index(
        "python -m hydra.cli validate",
    )


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


def test_quiesced_state_validation_does_not_depend_on_runtime_health():
    source = _source()
    migration = source.index('info "Мигрирую state при остановленных службах"')
    restart = source.index("start_previous_units", migration)
    quiesced_validation = source[migration:restart]

    assert "-m hydra.cli --json upgrade migrate-state" in quiesced_validation
    assert "-m hydra.cli --json upgrade check" in quiesced_validation
    assert "-m hydra.cli --json check" not in quiesced_validation


def test_caddy_l4_is_restored_when_quiescing_helpers_stops_it_transitively():
    source = _source()
    discovery = source[
        source.index("discover_units() {") : source.index(
            "\n}\n",
            source.index("discover_units() {"),
        )
    ]

    assert "'caddy-l4.service'" in discovery
    assert '"$unit" == "caddy-l4.service"' in discovery
    assert source.index("\ncapture_active_units\n") < source.index(
        "stop_managed_units",
        source.index('step 5 7 "Резервная копия и миграция state"'),
    )
    assert "printf '%s\\n' \"${ACTIVE_UNITS[@]}\"" in source


def test_failure_reports_name_the_operation_and_its_json_artifact():
    source = _source()
    rollback = source[
        source.index("rollback() {") : source.index(
            "handle_error() {",
            source.index("rollback() {"),
        )
    ]

    assert 'CURRENT_OPERATION=""' in source
    assert 'CURRENT_REPORT=""' in source
    assert "Сбой операции:" in rollback
    assert "Отчёт операции:" in rollback
    assert 'CURRENT_REPORT="$ROLLBACK_DIR/state-check.json"' in source


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
    assert "должны быть на одной файловой системе" in source


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
    assert "Не удалось проверить службу systemd" in capture
    assert '"$unit_type" == "oneshot"' in capture
    assert "continue" in capture


def test_template_units_are_replaced_with_loaded_instances_before_capture():
    source = _source()
    discovery = source[
        source.index("discover_units() {") : source.index(
            "\n}\n",
            source.index("discover_units() {"),
        )
    ]

    assert "systemctl list-unit-files" in discovery
    assert "systemctl list-units" in discovery
    assert '[[ "$unit" =~ @\\.(service|timer)$ ]] && continue' in discovery
    assert 'MANAGED_UNITS+=("$unit")' in discovery


def test_linux_upgrade_smoke_covers_active_template_instances():
    source = LINUX_UPGRADE_SMOKE.read_text(encoding="utf-8")

    assert "hydra-headless-creator-vk-calls@.service" in source
    assert "hydra-headless-creator-vk-calls@a-1.service" in source
    assert source.count('systemctl is-active --quiet "$calls_instance"') >= 3


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
    expected_commands = {
        ROOT / "README.md": (
            "curl -fsSL https://raw.githubusercontent.com/gr33nimax/"
            "HYDRA-ULTIMATE/dev/updater.sh | sudo env HYDRA_REF=dev bash"
        ),
        ROOT / "docs" / "UPGRADE.md": (
            "curl -fsSL https://raw.githubusercontent.com/gr33nimax/"
            "HYDRA-ULTIMATE/main/updater.sh | sudo bash"
        ),
    }
    for path in UPGRADE_DOCS:
        documentation = path.read_text(encoding="utf-8")
        assert expected_commands[path] in documentation
        assert "upgrade_script=$(mktemp)" not in documentation
        assert '-o "$upgrade_script"' not in documentation


def test_one_command_launcher_downloads_engine_completely_before_execution():
    source = LAUNCHER.read_text(encoding="utf-8")

    assert 'HYDRA_REF="${HYDRA_REF:-main}"' in source
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
    assert 'result_ok "Новая версия HYDRA установлена и проверена."' in engine
    assert 'result_ok "Обновление не требуется' in engine
    assert 'result_error "Обновление не завершено' in engine


def test_updater_uses_utf8_and_one_consistent_human_readable_style():
    launcher = LAUNCHER.read_text(encoding="utf-8")
    engine = _source()

    for source in (launcher, engine):
        assert "configure_utf8_locale" in source
        assert "HYDRA · ОБНОВЛЕНИЕ" in source
        assert "✓" in source
        assert "✗" in source
    assert "summary_row" in engine
    assert 'summary_row "Ветка"' in engine
    assert 'summary_row "Переход"' in engine
    assert 'summary_row "Снимок отката"' in engine
    assert 'summary_row "Подробный лог"' in engine


def test_updater_does_not_mix_english_operator_errors_into_russian_output():
    source = _source()
    broken_messages = (
        "run this updater as root",
        "required command is missing",
        "another HYDRA upgrade is already running",
        "local changes exist",
        "cannot identify the currently installed revision",
        "unit did not recover",
        "command wrapper restoration failed",
        "services could not be quiesced",
    )

    assert all(message not in source for message in broken_messages)


def test_all_main_install_and_update_entrypoints_default_to_main():
    bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
    launcher = LAUNCHER.read_text(encoding="utf-8")
    engine = _source()

    assert 'DEFAULT_BRANCH="main"' in bootstrap
    assert 'HYDRA_REF="${HYDRA_REF:-main}"' in launcher
    assert 'HYDRA_REF="${HYDRA_REF:-main}"' in engine
