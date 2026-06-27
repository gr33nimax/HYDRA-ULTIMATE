#!/usr/bin/env python3
"""Phase 4: extract blocks from _core.py and remove legacy dead code."""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "vless_installer" / "_core.py"
MOD = ROOT / "vless_installer" / "modules"

LAZY = '''
class _LazyCore:
    """Late-bind to vless_installer._core (avoids circular import at load time)."""
    _mod = None

    def _m(self):
        if self._mod is None:
            import vless_installer._core as m
            self._mod = m
        return self._mod

    def __getattr__(self, name: str):
        return getattr(self._m(), name)


core = _LazyCore()
'''

CORE_NAMES = [
    "STATE_FILE", "LOG_FILE", "CYAN", "NC", "BLUE", "GREEN", "YELLOW", "RED",
    "BOLD", "DIM", "WHITE", "TITLE", "MAGENTA", "BGBLUE",
    "TOTAL_RAM", "TOTAL_CPU", "INSTALL_MODE", "OPTIMIZER_CONF", "LIMITS_CONF",
    "SYSTEMD_CONF", "PROGRESS",
    "info", "success", "warn", "dim", "die", "log_to_file",
    "gen_uuid", "get_server_ip", "get_adaptive_value", "command_exists",
    "_run", "_box_top", "_box_row", "_box_sep", "_box_bottom", "_box_item",
    "_box_item_exit", "_box_back", "_box_warn", "_box_ok", "_box_info",
    "_box_input", "_box_dim", "_fmt_bytes_ru", "_bar_mini",
    "install_sync_agent", "uninstall_sync_agent",
    "do_manage_traffic_limits", "do_manage_ttl_users",
    "_ttl_expires_within_hours", "_ttl_is_expired",
    "_users_from_state",
]

REMOVE_RANGES = [
    (640, 660),
    (663, 744),
    (2100, 2274),
    (2306, 3163),
    (3771, 3924),
    (4036, 4334),
    (5193, 5347),
    (9819, 9845),
]

MIG_STUB = textwrap.dedent('''\
    # --- HYDRA migration/backup (Phase 4: modules/hydra_migration.py) ---
    def _hydra_collect_backup_paths():
        from vless_installer.modules.hydra_migration import collect_backup_paths
        return collect_backup_paths()

    def do_hydra_export_backup(encrypt: bool = False) -> None:
        from vless_installer.modules.hydra_migration import export_backup
        return export_backup(encrypt=encrypt)

    def do_hydra_import_backup() -> None:
        from vless_installer.modules.hydra_migration import import_backup
        return import_backup()

    def _backup_encrypt(archive_path, password):
        from vless_installer.modules.hydra_migration import backup_encrypt
        return backup_encrypt(archive_path, password)

    def _backup_decrypt(enc_path, password, out_path):
        from vless_installer.modules.hydra_migration import backup_decrypt
        return backup_decrypt(enc_path, password, out_path)

    def _scheduled_backup_run() -> None:
        from vless_installer.modules.hydra_migration import scheduled_backup_run
        return scheduled_backup_run()


''')

TUNE_STUB = textwrap.dedent('''\
    def apply_network_optimizations() -> None:
        from vless_installer.modules.system_tune import apply_network_optimizations as _fn
        return _fn()


''')

SUB_STUB = textwrap.dedent('''\
    # --- subscription menu (Phase 4: modules/subscription_menu.py) ---
    def ensure_subscription_tokens() -> None:
        from vless_installer.modules.subscription_menu import ensure_subscription_tokens as _fn
        return _fn()

    def do_subscription_menu() -> None:
        from vless_installer.modules.subscription_menu import do_subscription_menu as _fn
        return _fn()

    def do_update_all_user_configs() -> None:
        from vless_installer.modules.subscription_menu import do_update_all_user_configs as _fn
        return _fn()


''')

SYSCTL_STUB = textwrap.dedent('''\
    def apply_sysctl_and_limits() -> None:
        from vless_installer.modules.system_tune import apply_sysctl_and_limits as _fn
        return _fn()


''')

TRAFFIC_STUB = textwrap.dedent('''\

    def do_traffic_history() -> None:
        """ASCII-гистограмма трафика из hydra traffic snapshots."""
        import json as _json
        os.system("clear")
        print()
        _box_top("📈  ИСТОРИЯ ТРАФИКА")
        hist_path = TRAFFIC_HISTORY_FILE
        if not hist_path.exists():
            _box_warn("Нет данных — включите cron снимков (планировщик → snapshot)")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
            return
        try:
            history = _json.loads(hist_path.read_text())
        except Exception as e:
            _box_warn(f"Ошибка чтения: {e}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
            return
        dates = sorted(history.keys())[-14:]
        if not dates:
            _box_warn("История пуста")
        else:
            for d in dates:
                day = history[d]
                total = sum(v for k, v in day.items() if k.endswith("_max"))
                bar = _bar_mini(min(total, 10**12), 10**12, width=24)
                _box_row(f"  {d}  {bar}  {_fmt_bytes_ru(total)}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")

''')


def slice_lines(lines: list[str], start: int, end: int) -> str:
    return "".join(lines[start - 1 : end])


def replace_names(body: str, names: list[str]) -> str:
    for n in sorted(names, key=len, reverse=True):
        body = re.sub(rf"\b{n}\b", f"core.{n}", body)
    return body


def make_module(header: str, body: str, extra_imports: str = "") -> str:
    body = replace_names(body, CORE_NAMES)
    return (
        f'"""\n{header}\nExtracted from vless_installer/_core.py (Phase 4).\n"""\n'
        "from __future__ import annotations\n\n"
        "import json\nimport os\nimport re\nimport shutil\nimport socket\n"
        "import subprocess\nimport sys\nimport tempfile\nimport textwrap\n"
        "import time\nimport threading\nfrom datetime import datetime\n"
        f"from pathlib import Path\n{extra_imports}\n{LAZY}\n\n{body}"
    )


def rename_funcs(body: str, mapping: dict[str, str]) -> str:
    for old, new in mapping.items():
        body = re.sub(rf"^def {re.escape(old)}\(", f"def {new}(", body, flags=re.MULTILINE)
        body = body.replace(f"core.{old}", new if old.startswith("_") else f"core.{new}")
    return body


def build_core_without_ranges(lines: list[str], ranges: list[tuple[int, int]]) -> str:
    parts: list[str] = []
    prev = 0
    for start, end in ranges:
        parts.append("".join(lines[prev : start - 1]))
        prev = end
    parts.append("".join(lines[prev:]))
    return "".join(parts)


def main() -> None:
    orig_lines = CORE.read_text(encoding="utf-8").splitlines(keepends=True)
    orig_n = len(orig_lines)

    sub_body = slice_lines(orig_lines, 2306, 3163)
    mig_body = (
        slice_lines(orig_lines, 640, 660)
        + slice_lines(orig_lines, 663, 744)
        + slice_lines(orig_lines, 3771, 3924)
    )
    tune_body = slice_lines(orig_lines, 2100, 2274) + slice_lines(orig_lines, 9819, 9845)

    mig_body = rename_funcs(mig_body, {
        "_HYDRA_BACKUP_FILES": "HYDRA_BACKUP_FILES",
        "_hydra_collect_backup_paths": "collect_backup_paths",
        "do_hydra_export_backup": "export_backup",
        "do_hydra_import_backup": "import_backup",
        "_backup_encrypt": "backup_encrypt",
        "_backup_decrypt": "backup_decrypt",
        "_scheduled_backup_run": "scheduled_backup_run",
    })
    mig_body = mig_body.replace("        _HYDRA_BACKUP_FILES", "HYDRA_BACKUP_FILES")
    mig_body = mig_body.replace("core.HYDRA_BACKUP_FILES", "HYDRA_BACKUP_FILES")
    mig_body = re.sub(
        r"for p in (?:core\.)?HYDRA_BACKUP_FILES",
        "for p in HYDRA_BACKUP_FILES",
        mig_body,
    )
    mig_body = mig_body.replace("enc = core.backup_encrypt", "enc = backup_encrypt")
    mig_body = mig_body.replace("if not core.backup_decrypt", "if not backup_decrypt")
    mig_body = mig_body.replace("items = core.collect_backup_paths()", "items = collect_backup_paths()")

    (MOD / "subscription_menu.py").write_text(
        make_module("Subscription management TUI (menu section 2).", sub_body),
        encoding="utf-8",
    )
    (MOD / "hydra_migration.py").write_text(
        make_module("HYDRA backup export/import and scheduled backup.", mig_body),
        encoding="utf-8",
    )
    (MOD / "system_tune.py").write_text(
        make_module("Sysctl/limits network tuning for HYDRA.", tune_body),
        encoding="utf-8",
    )

    text = build_core_without_ranges(orig_lines, REMOVE_RANGES)
    text = text.replace(
        "# --- HYDRA helpers (single-node, без Xray/cascade) -------------------------",
        MIG_STUB + "# --- HYDRA helpers (single-node, без Xray/cascade) -------------------------",
        1,
    )
    text = text.replace(
        "#  ШАГ 3: ОПТИМИЗАЦИЯ СЕТЕВОГО СТЕКА\n# =============================================================================\n",
        "#  ШАГ 3: ОПТИМИЗАЦИЯ СЕТЕВОГО СТЕКА\n# =============================================================================\n" + TUNE_STUB,
        1,
    )
    text = text.replace(
        "# =============================================================================\n#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ\n",
        SUB_STUB + "# =============================================================================\n#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ\n",
        1,
    )
    text = text.replace(
        "# Удалён дублирующий пункт [2]",
        SYSCTL_STUB + "# Удалён дублирующий пункт [2]",
        1,
    )
    if "def do_traffic_history()" not in text:
        text = text.replace(
            "def do_system_dashboard() -> None:",
            TRAFFIC_STUB + "\ndef do_system_dashboard() -> None:",
            1,
        )

    CORE.write_text(text, encoding="utf-8")
    print(f"Phase 4 surgery: {orig_n} -> {len(text.splitlines())} lines in _core.py")


if __name__ == "__main__":
    main()
