"""
hydra/core/singbox.py — Управление Sing-Box.

Установка, запуск, генерация конфига, проверка статуса.
Sing-Box — центральный оркестратор: все протоколы → inbound'ы,
WARP/DNS/GeoIP → outbound/route/rules.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from hydra.contracts import ConfigFragment
from hydra.core.state import load_state
from hydra.core.state_models import AppState, PluginState
from hydra.core.host import HOST
from hydra.core import singbox_config
from hydra.core.singbox_upgrade import (
    UpgradeOperations,
    migrate_runtime_dns_config,
    parse_version,
    upgrade_kernel,
)
from hydra.core.singbox_service import failure_detail
from hydra.utils.commands import redact_text

SINGBOX_BIN = Path("/usr/local/bin/sing-box")
SINGBOX_CONFIG = Path("/etc/sing-box/config.json")
SINGBOX_SERVICE = Path("/etc/systemd/system/sing-box.service")
LOG_FILE = Path("/var/log/hydra/install.log")
_last_error = ""


def last_error() -> str:
    """Return the most recent user-facing configuration error."""
    return _last_error


def _set_error(message: str) -> None:
    global _last_error
    _last_error = message


def _find_singbox():
    """Ищет бинарник sing-box в известных путях."""
    for p in ("/usr/local/bin/sing-box", "/usr/bin/sing-box"):
        if Path(p).exists():
            return Path(p)
    w = shutil.which("sing-box")
    return Path(w) if w else None


def _log(level: str, msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        ts = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{level}] {redact_text(msg)}\n")
    except Exception:
        pass


def log(level: str, message: str) -> None:
    """Write a redacted Sing-Box lifecycle event through the public boundary."""
    _log(level, message)


def _run(cmd: list, capture: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    import os
    kw = {"timeout": timeout}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = os.environ.copy()
    env["ENABLE_DEPRECATED_LEGACY_DNS_SERVERS"] = "true"
    env["ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER"] = "true"
    return HOST.run(cmd, env=env, **kw)


def validate_current_config() -> tuple[bool | None, str]:
    """Validate the installed config without exposing private process helpers."""
    if not SINGBOX_CONFIG.exists():
        return None, ""
    binary = _find_singbox()
    if binary is None:
        return None, ""
    try:
        checked = _run(
            [str(binary), "check", "-c", str(SINGBOX_CONFIG)],
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if checked.returncode == 0:
        return True, ""
    output = str(checked.stderr or checked.stdout or "unknown error").strip()
    return False, output.splitlines()[-1] if output else "unknown error"


def preflight_conflicts(config: dict) -> list[str]:
    """Expose side-effect-free configuration conflict detection."""
    return _preflight_conflicts(config)


# ═════════════════════════════════════════════════════════════════════════════
#  Установка
# ═════════════════════════════════════════════════════════════════════════════

def is_installed() -> bool:
    """Проверяет, установлен ли Sing-Box."""
    return _find_singbox() is not None


def get_version() -> Optional[str]:
    """Возвращает версию установленного Sing-Box."""
    bin_path = _find_singbox()
    if not bin_path:
        return None
    r = _run([str(bin_path), "version"])
    if r.returncode == 0:
        first_line = r.stdout.strip().split("\n")[0]
        parts = first_line.split()
        for p in parts:
            if p[0].isdigit():
                return p
    return None


EXTENDED_REPO = "shtorm-7/sing-box-extended"


def install(force: bool = False) -> bool:
    """Устанавливает sing-box-extended из GitHub releases."""
    _set_error("")
    if not force and is_installed() and "extended" in (get_version() or "").lower():
        return True

    _log("INFO", "Installing sing-box-extended...")

    # Останавливаем службу перед заменой бинарника, чтобы не было конфликтов
    try:
        stop()
    except Exception as e:
        _log("WARNING", f"Failed to stop sing-box: {e}")

    from hydra.utils.net import detect_arch
    from hydra.utils.downloader import download_github_asset_filtered, extract_tarball

    arch = detect_arch()  # "amd64" | "arm64"

    def _match(name: str) -> bool:
        """Точный фильтр: linux-{arch}.tar.gz без суффиксов."""
        return (
            f"linux-{arch}.tar.gz" in name
            and "compressed" not in name
            and "musl" not in name
            and "glibc" not in name
            and "purego" not in name
        )

    dest = Path("/tmp/singbox-install")
    dest.mkdir(parents=True, exist_ok=True)
    tarball = dest / "sing-box.tar.gz"

    if not download_github_asset_filtered(EXTENDED_REPO, _match, tarball, on_error=_set_error):
        _log("ERROR", last_error() or "Failed to download sing-box-extended")
        return False

    extract_tarball(tarball, dest)

    # Найти бинарник sing-box в распакованном каталоге
    candidate = None
    for p in dest.rglob("sing-box"):
        if p.is_file() and p.stat().st_size > 1_000_000:  # >1MB = бинарник
            candidate = p
            break

    if not candidate:
        _log("ERROR", "sing-box binary not found in archive")
        shutil.rmtree(str(dest), ignore_errors=True)
        return False

    # Удаляем старый бинарник, если он существует, для исключения "Text file busy"
    if SINGBOX_BIN.exists():
        try:
            SINGBOX_BIN.unlink()
        except Exception as e:
            _log("WARNING", f"Failed to unlink {SINGBOX_BIN}: {e}")

    import shutil as _sh
    _sh.move(str(candidate), str(SINGBOX_BIN))
    SINGBOX_BIN.chmod(0o755)
    _sh.rmtree(str(dest), ignore_errors=True)

    _log("INFO", f"sing-box-extended installed: {get_version()}")
    return is_installed()


# ═════════════════════════════════════════════════════════════════════════════
#  Генерация конфига
# ═════════════════════════════════════════════════════════════════════════════

def generate_config(
    state: AppState,
    fragments: dict[str, ConfigFragment],
) -> dict:
    """Compatibility facade for the pure configuration assembler."""
    return singbox_config.generate_config(state, fragments)


def _preflight_conflicts(config: dict) -> list[str]:
    """Preserve released SNI semantics around the pure conflict validator.

    The pure validator owns generic tag, listener-overlap, and port checks.
    HYDRA 2.5.3 also permits one protocol's TCP/QUIC modes to share an SNI, so
    SNI ownership is evaluated here by normalized protocol scope.
    """
    import copy

    validation_config = copy.deepcopy(config)
    for item in validation_config.get("inbounds", []) or []:
        if not isinstance(item, dict):
            continue
        tls = item.get("tls")
        if isinstance(tls, dict):
            tls.pop("server_name", None)

    errors = singbox_config.preflight_conflicts(validation_config)
    snis: dict[str, tuple[str, str]] = {}

    for item in config.get("inbounds", []) or []:
        if not isinstance(item, dict):
            continue
        tag = item.get("tag")
        owner = str(tag or item.get("type", "inbound"))
        sni_scope = owner.lower()
        for suffix in ("-quic-in", "-tcp-in", "-udp-in", "-in"):
            if sni_scope.endswith(suffix):
                sni_scope = sni_scope.removesuffix(suffix)
                break

        tls = item.get("tls")
        if not isinstance(tls, dict):
            continue
        server_name = tls.get("server_name")
        names = server_name if isinstance(server_name, list) else [server_name]
        for name in names:
            normalized = str(name or "").strip().lower()
            if not normalized:
                continue
            existing = snis.get(normalized)
            if existing and existing[0] != sni_scope:
                errors.append(
                    f"SNI '{normalized}' назначен нескольким inbound "
                    f"({existing[1]} и {owner})",
                )
            else:
                snis[normalized] = (sni_scope, owner)
    return errors


def write_config(config: dict) -> bool:
    """Записывает конфиг и проверяет валидность."""
    SINGBOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)

    tmp = SINGBOX_CONFIG.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    if os.name != "nt":
        try:
            tmp.chmod(0o600)
        except OSError:
            pass

    # Валидация
    conflicts = _preflight_conflicts(config)
    if conflicts:
        message = "Проверка конфигурации не пройдена: " + "; ".join(conflicts)
        _set_error(message)
        _log("ERROR", message)
        tmp.unlink(missing_ok=True)
        return False
    bin_path = _find_singbox()
    if not bin_path:
        tmp.unlink(missing_ok=True)
        message = "Проверка конфигурации Sing-Box невозможна: бинарник не найден"
        _set_error(message)
        _log("ERROR", message)
        return False
    r = _run([str(bin_path), "check", "-c", str(tmp)])
    if r.returncode != 0:
        # Сохраним невалидный конфиг для отладки
        debug_path = Path("/var/log/hydra/warp_debug_config.json")
        try:
            debug_path.parent.mkdir(parents=True, exist_ok=True)
            debug_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
        message = f"Некорректная конфигурация Sing-Box: {r.stderr or r.stdout or 'неизвестная ошибка'}"
        _set_error(message)
        _log("ERROR", message)
        tmp.unlink(missing_ok=True)
        return False

    tmp.replace(SINGBOX_CONFIG)
    _set_error("")
    if os.name != "nt":
        try:
            SINGBOX_CONFIG.chmod(0o600)
        except OSError:
            pass
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  Управление службой
# ═════════════════════════════════════════════════════════════════════════════

def _install_service() -> bool:
    """Создаёт systemd-юнит для sing-box."""
    bin_path = _find_singbox()
    if not bin_path:
        return False

    # Создаём рабочую директорию (нужна для sing-box run)
    work_dir = Path("/var/lib/sing-box")
    work_dir.mkdir(parents=True, exist_ok=True)

    unit = f"""[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/sing-box
Environment=LEGACY_DNS_SERVERS=true ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true
ExecStart={bin_path} run -c {SINGBOX_CONFIG}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=30
LimitNPROC=500
LimitNOFILE=1000000
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
"""
    SINGBOX_SERVICE.parent.mkdir(parents=True, exist_ok=True)
    SINGBOX_SERVICE.write_text(unit)
    HOST.run(["systemctl", "daemon-reload"])
    return True


def start() -> bool:
    """Запускает sing-box. Создаёт минимальный конфиг, если его нет."""
    # Сбрасываем предыдущее состояние (мог застрять в auto-restart)
    _run(["systemctl", "stop", "sing-box"], capture=False)

    if not SINGBOX_CONFIG.exists():
        _log("INFO", "No config found, creating minimal default...")
        minimal = {
            "log": {"level": "info"},
            "inbounds": [
                {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"}
            ],
        }
        write_config(minimal)

    _install_service()
    r = _run(["systemctl", "start", "sing-box"], capture=False)
    if r.returncode != 0:
        _set_error("Не удалось запустить Sing-Box: ошибка systemd")
        return False
    if wait_until_stable():
        _set_error("")
        enable_autostart()
        return True
    message = f"Sing-Box завершился после запуска: {_service_failure_detail()}"
    _set_error(message)
    _log("ERROR", message)
    return False


def stop() -> bool:
    """Останавливает sing-box."""
    _run(["systemctl", "stop", "sing-box"], capture=False)
    return not is_running()


def _service_failure_detail() -> str:
    """Return a short systemd journal detail suitable for TUI and logs."""
    return failure_detail(_run)


def wait_until_stable(checks: int = 3, interval: float = 0.5) -> bool:
    """Require several consecutive active checks after start/reload."""
    for index in range(checks):
        if not is_running():
            return False
        if index + 1 < checks:
            time.sleep(interval)
    return True


def reload() -> bool:
    """Перезагружает конфиг sing-box (graceful)."""
    if not is_running():
        return start()
    r = _run(["systemctl", "reload", "sing-box"])
    if r.returncode != 0:
        message = f"Не удалось перезагрузить Sing-Box: {r.stderr or r.stdout or 'ошибка systemd'}"
        _set_error(message)
        _log("ERROR", message)
        return False
    if not wait_until_stable():
        message = f"Sing-Box завершился после применения: {_service_failure_detail()}"
        _set_error(message)
        _log("ERROR", message)
        return False
    _set_error("")
    return True


def restart() -> bool:
    """Полный перезапуск sing-box."""
    _run(["systemctl", "restart", "sing-box"], capture=False)
    time.sleep(1)
    return is_running()


def is_running() -> bool:
    """Проверяет, работает ли sing-box."""
    r = _run(["systemctl", "is-active", "--quiet", "sing-box"])
    return r.returncode == 0


def has_configured_inbound(tag: str) -> bool:
    """Return whether the applied Sing-Box artifact contains an inbound tag."""
    try:
        config = json.loads(SINGBOX_CONFIG.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return False
    return any(
        isinstance(inbound, dict) and inbound.get("tag") == tag
        for inbound in config.get("inbounds", [])
    )


def enable_autostart() -> None:
    """Включает автозапуск при загрузке."""
    _run(["systemctl", "enable", "sing-box"], capture=False)


def status_text() -> str:
    """Возвращает текстовый статус Sing-Box."""
    version = get_version()
    running = is_running()
    state = load_state()
    update_suffix = ""
    if state.install.get("singbox_update_available") and version:
        update_suffix = " (Доступно обновление)"
    return (
        f"Sing-Box: {version or 'не установлен'}{update_suffix} | "
        f"{'✓ запущен' if running else '✗ остановлен'}"
    )


def update_kernel() -> tuple[bool, str]:
    """Update Sing-Box through the isolated transactional upgrade service."""
    return upgrade_kernel(
        target_binary=SINGBOX_BIN,
        config_path=SINGBOX_CONFIG,
        operations=UpgradeOperations(
            find_binary=_find_singbox,
            is_running=is_running,
            install=install,
            get_version=get_version,
            run=_run,
            start=start,
            stop=stop,
            log=_log,
            install_error=last_error,
            migrate_config=migrate_runtime_dns_config,
        ),
    )

