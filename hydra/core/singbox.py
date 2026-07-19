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

from hydra.plugins.base import ConfigFragment
from hydra.core.state import AppState, PluginState, load_state, save_state
from hydra.core.host import HOST
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

    if not download_github_asset_filtered(EXTENDED_REPO, _match, tarball):
        _log("ERROR", "Failed to download sing-box-extended")
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

def _base_config(state: AppState) -> dict:
    config = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 1080,
            },
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct",
            }
        ],
        "route": {
            "rules": [],
            "auto_detect_interface": True,
            "default_mark": 255,
            "final": "direct",
        },
    }
    if state.network.tproxy_enabled:
        config["inbounds"].append({
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "::",
            "listen_port": state.network.tproxy_port,
        })
        # Предотвращение петель маршрутизации TPROXY
        config["route"]["rules"].append({
            "inbound": ["tproxy-in"],
            "port": [state.network.tproxy_port],
            "action": "reject"
        })
        config["route"]["rules"].append({
            "action": "sniff",
            "sniffer": ["http", "tls", "quic"],
        })
        
    if getattr(state.network, "clash_api_enabled", False):
        port = getattr(state.network, "clash_api_port", 9090)
        secret = getattr(state.network, "clash_api_secret", "")
        config["experimental"] = {
            "clash_api": {
                "external_controller": f"127.0.0.1:{port}",
                "secret": secret
            }
        }
        
    return config


def _dns_config(state: AppState) -> dict:
    """DNS-конфиг по умолчанию (публичные DoH)."""
    return {
        "servers": [
            {
                "tag": "dns-remote",
                "address": "https://dns.quad9.net/dns-query",
                "address_resolver": "dns-direct",
                "strategy": "ipv4_only",
                "detour": "direct",
            },
            {
                "tag": "dns-direct",
                "address": "1.1.1.1",
                "detour": "direct",
            },
        ],
        "rules": [],
    }


def generate_config(state: AppState, fragments: dict[str, ConfigFragment]) -> dict:
    config = _base_config(state)
    
    if "endpoints" not in config:
        config["endpoints"] = []

    for name, frag in fragments.items():
        config["inbounds"].extend(frag.inbounds)
        config["outbounds"].extend(frag.outbounds)
        config["route"]["rules"].extend(frag.route_rules)
        if hasattr(frag, "endpoints") and frag.endpoints:
            config["endpoints"].extend(frag.endpoints)

    if "endpoints" in config and not config["endpoints"]:
        config.pop("endpoints")

    # DNS-конфиг (DNSCrypt / публичные DoH)
    dns_config = {}
    for name, frag in fragments.items():
        if hasattr(frag, "dns") and frag.dns:
            dns_config = frag.dns
            break
    config["dns"] = dns_config if dns_config else _dns_config(state)

    # Если плагины не дали ни одного inbound — добавляем fallback
    if not config["inbounds"]:
        config["inbounds"].append({
            "type": "mixed", "tag": "mixed-in",
            "listen": "127.0.0.1", "listen_port": 2080,
        })
    # Гарантируем direct outbound (нужен для DNS и как fallback)
    has_direct = any(o.get("tag") == "direct" for o in config["outbounds"])
    if not has_direct:
        config["outbounds"].append({"type": "direct", "tag": "direct"})

    return config


def _preflight_conflicts(config: dict) -> list[str]:
    """Return human-readable conflicts that Sing-Box's schema check cannot catch."""
    errors: list[str] = []
    tags: dict[str, str] = {}
    ports: dict[tuple[str, int], str] = {}
    snis: dict[str, str] = {}

    for section in ("inbounds", "outbounds", "endpoints"):
        for item in config.get(section, []) or []:
            if not isinstance(item, dict):
                continue
            tag = item.get("tag")
            if tag:
                owner = f"{section}:{item.get('type', 'unknown')}"
                if tag in tags:
                    errors.append(f"дублирующийся tag '{tag}' ({tags[tag]} и {owner})")
                else:
                    tags[tag] = owner

            if section != "inbounds":
                continue
            try:
                port = int(item.get("listen_port", 0) or 0)
            except (TypeError, ValueError):
                continue
            if port <= 0:
                continue
            listen = str(item.get("listen", "0.0.0.0"))
            key = (listen, port)
            owner = str(tag or item.get("type", "inbound"))
            if key in ports:
                errors.append(f"порт {port} на {listen} используется дважды ({ports[key]} и {owner})")
            else:
                ports[key] = owner

            tls = item.get("tls")
            if isinstance(tls, dict):
                server_name = tls.get("server_name")
                names = server_name if isinstance(server_name, list) else [server_name]
                for name in names:
                    normalized = str(name or "").strip().lower()
                    if not normalized:
                        continue
                    if normalized in snis and snis[normalized] != owner:
                        errors.append(
                            f"SNI '{normalized}' назначен нескольким inbound ({snis[normalized]} и {owner})"
                        )
                    else:
                        snis[normalized] = owner
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
    try:
        result = _run(
            ["journalctl", "-u", "sing-box", "-n", "8", "--no-pager"],
            timeout=5,
        )
        lines = [line.strip() for line in (result.stdout or result.stderr or "").splitlines() if line.strip()]
        if lines:
            return lines[-1]
    except (OSError, subprocess.SubprocessError):
        pass
    return "служба не перешла в стабильное состояние"


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


def parse_version(v_str: Optional[str]) -> tuple[int, ...]:
    """Парсит строку версии в кортеж чисел для сравнения."""
    if not v_str:
        return (0,)
    import re
    parts = re.findall(r'\d+', v_str)
    if parts:
        try:
            return tuple(map(int, parts))
        except ValueError:
            pass
    return (0,)


def update_kernel() -> tuple[bool, str]:
    """
    Обновляет ядро sing-box до последней версии с созданием резервной копии и автооткатом.
    Возвращает (success, message).
    """
    installed_bin = _find_singbox()
    if installed_bin is None and SINGBOX_BIN.exists():
        installed_bin = SINGBOX_BIN
    if installed_bin is None:
        return False, "Sing-Box не установлен, обновление невозможно"

    backup_bin = SINGBOX_BIN.with_suffix(".bak")
    _log("INFO", f"Creating backup of sing-box binary to {backup_bin}")

    # 1. Создаем резервную копию бинарника
    try:
        if backup_bin.exists():
            backup_bin.unlink()
        shutil.copy2(installed_bin, backup_bin)
    except Exception as e:
        _log("ERROR", f"Failed to create backup: {e}")
        return False, f"Ошибка создания резервной копии: {e}"

    # Запоминаем, был ли сервис запущен до обновления
    was_running = is_running()

    def rollback(reason: str) -> tuple[bool, str]:
        """Restore the previous binary and verify the previous service state."""
        _log("ERROR", f"{reason}; rolling back to backup...")
        try:
            stop()
        except Exception:
            pass
        try:
            if SINGBOX_BIN.exists():
                SINGBOX_BIN.unlink()
            shutil.copy2(backup_bin, SINGBOX_BIN)
            SINGBOX_BIN.chmod(0o755)
        except Exception as rb_err:
            _log("CRITICAL", f"Rollback failed: {rb_err}")
            return False, f"{reason}. Сбой восстановления старого ядра: {rb_err}"

        if was_running:
            try:
                restored = start()
            except Exception as rb_err:
                restored = False
                _log("CRITICAL", f"Restored service start failed: {rb_err}")
            if not restored:
                _log("CRITICAL", "Old binary was restored, but sing-box did not start")
                return False, f"{reason}. Старое ядро восстановлено, но служба не запустилась."
        return False, f"{reason}. Выполнен откат."

    # 2. Скачиваем и устанавливаем обновление
    success_install = False
    try:
        # install(force=True) выполняет скачивание, остановку и замену
        success_install = install(force=True)
    except Exception as e:
        _log("ERROR", f"Installation failed during update: {e}")
        success_install = False

    if not success_install:
        return rollback("Не удалось скачать или распаковать обновление")

    # 3. Верифицируем новый бинарник
    new_version = get_version()
    if not new_version:
        return rollback("Новый бинарник не запускается")

    # 4. Проверяем валидность конфига
    if SINGBOX_CONFIG.exists():
        r = _run([str(SINGBOX_BIN), "check", "-c", str(SINGBOX_CONFIG)])
        if r.returncode != 0:
            _log("ERROR", f"New binary rejected existing config, rolling back. Stderr: {r.stderr}")
            return rollback("Конфигурация несовместима с новым ядром")

    # 5. Перезапуск и проверка службы
    if was_running:
        _log("INFO", "Restarting service and checking status...")
        if not start():
            return rollback("Служба не смогла запуститься с новым ядром")

    # Очистка
    try:
        backup_bin.unlink(missing_ok=True)
    except Exception as e:
        _log("WARNING", f"Failed to remove backup file: {e}")

    try:
        from hydra.core.state import update_state
        def reset_update_flag(latest):
            latest.install.pop("singbox_update_available", None)
            latest.install.pop("singbox_latest_version", None)
            return True
        update_state(reset_update_flag)
    except Exception as e:
        _log("WARNING", f"Failed to reset update flags in state: {e}")

    return True, f"Ядро успешно обновлено до версии {new_version}"

