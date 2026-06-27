#!/usr/bin/env python3
"""
HYDRA Multi-Proxy Manager — core runtime (_core.py)

Ubuntu/Debian server panel: NaiveProxy, Mieru, AmneziaWG, subscriptions, bots.
Legacy VLESS/Xray cascade (Mode B / exit-nodes) stubbed — single-node HYDRA only.
"""

# =============================================================================
#  STDLIB IMPORTS
# =============================================================================
import sys
import os
import re


# ---------------------------------------------------------------------------
# Safe input: protection against UnicodeDecodeError in non-standard terminals.
# Monkey-patches built-in input() globally so all 277 call sites are covered.
# ---------------------------------------------------------------------------
import builtins as _builtins
_builtin_input_orig = _builtins.input

def _safe_input(prompt: str = "") -> str:
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        raw = sys.stdin.buffer.readline()
        if not raw:
            raise EOFError
        return raw.decode("utf-8", errors="replace").rstrip("\n\r")
    except UnicodeDecodeError:
        return ""
    except (EOFError, OSError):
        raise EOFError

_builtins.input = _safe_input
# ---------------------------------------------------------------------------

import json
import time
import uuid
import random
import string
import shutil
import socket
import subprocess
import tempfile
import textwrap
import grp
import pwd
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
import getpass

# ── Модули v4.12.9 ──────────────────────────────────────────────────────────────
from vless_installer.modules.ipset_persist   import (
    ipset_save, ipset_restore_unit_install, ipset_restore_unit_remove,
    do_manage_ipset_persist,
)
from vless_installer.modules.ipban import do_manage_ipban
from vless_installer.modules.vkturn_menu import do_vkturn_menu
from vless_installer.modules.slipgate import do_slipgate_menu
from vless_installer.modules.wdtt import do_wdtt_menu
from vless_installer.modules.naiveproxy import do_naiveproxy_menu
from vless_installer.modules.mieru import do_mieru_menu
from vless_installer.modules.webdav_tunnel import do_webdav_tunnel_menu
from vless_installer.modules.ripe_file_age   import (
    check_ripe_file_age, ripe_file_age_banner,
)
from vless_installer.modules.box_renderer import (
    _get_box_width, _plain, _wcslen,
    _box_line_top, _box_line_sep, _box_line_bot,
    _box_row, _box_row_auto, _box_link, _box_top, _box_sep, _box_bottom,
    _box_item, _box_item_exit, _box_back, _box_desc,
    _box_wrap_msg, _box_info, _box_warn, _box_ok, _box_dim, _box_input,
    _submenu_header, _submenu_item, _submenu_back,
)
import vless_installer.modules.box_renderer as _br
_BOX_W = _br._BOX_W  # алиас для совместимости с кодом в _core.py
from vless_installer.modules.logrotate  import do_manage_logrotate
from vless_installer.modules.dns_rules         import do_manage_dns_rules

# Статический список uTLS-fingerprints
_FM_FP_LIST = ["chrome", "firefox", "safari", "ios", "android", "edge", "none"]
# =============================================================================
#  ЦВЕТА И ФОРМАТИРОВАНИЕ
#  Переменная окружения VLESS_THEME=light — светлый фон (белый терминал)
# =============================================================================
_LIGHT_THEME = os.environ.get("VLESS_THEME", "").lower() == "light"

if _LIGHT_THEME:
    RED     = '\033[0;31m'
    GREEN   = '\033[0;32m'
    YELLOW  = '\033[0;33m'
    CYAN    = '\033[0;34m'   # синий вместо циана — лучше на белом фоне
    BLUE    = '\033[0;35m'   # пурпурный вместо синего
    MAGENTA = '\033[0;35m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    WHITE   = '\033[0;30m'   # чёрный — виден на белом фоне
    BGBLUE  = '\033[44m'
    NC      = '\033[0m'
    TITLE   = '\033[1;37m'   # ярко-белый — для заголовков на тёмном фоне бокса
else:
    RED     = '\033[0;31m'
    GREEN   = '\033[0;32m'
    YELLOW  = '\033[1;33m'
    CYAN    = '\033[0;36m'
    BLUE    = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    WHITE   = '\033[1;37m'
    BGBLUE  = '\033[44m'
    NC      = '\033[0m'
    TITLE   = WHITE  # в тёмной теме TITLE = WHITE, без изменений

# =============================================================================
#  ЛОГИРОВАНИЕ
# =============================================================================
LOG_FILE          = Path("/var/log/vless-install.log")
BACKUP_DIR        = Path("/var/backups/xray")
HEALTH_CHECK_FILE = Path("/var/lib/xray-installer/health.status")
STATE_FILE        = Path("/var/lib/xray-installer/state.json")
INSTALL_START_TIME = time.time()

for _d in (LOG_FILE.parent, BACKUP_DIR, HEALTH_CHECK_FILE.parent):
    _d.mkdir(parents=True, exist_ok=True)
try:
    LOG_FILE.touch()
    LOG_FILE.chmod(0o600)
except Exception:
    pass


def log_to_file(level: str, msg: str) -> None:
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with LOG_FILE.open('a') as f:
            f.write(f"[{ts}] [{level}] {msg}\n")
    except Exception:
        pass


def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    log_to_file("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   log_to_file("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  log_to_file("WARN",    msg)
def dim(msg: str)     -> None: print(f"{DIM}{msg}{NC}")

def die(msg: str) -> None:
    print(f"{RED}[ERROR]{NC} {msg}", file=sys.stderr)
    log_to_file("ERROR", msg)
    sys.exit(1)


log_to_file("INFO", "=== Запуск VLESS Ultimate Installer v4.12.10 ===")
log_to_file("INFO", f"Время начала: {datetime.now()}")

# =============================================================================
#  БАННЕР
# =============================================================================
def _make_banner(show_ram_warning: bool = True) -> str:
    _OW = 64   # внутренняя ширина внешней рамки
    _IW = _OW - 6  # внутренняя ширина вложенной рамки (58)
    _blank  = "║" + " " * _OW + "║"
    _top    = "╔" + "═" * _OW + "╗"
    _bot    = "╚" + "═" * _OW + "╝"
    _itop   = "║  ╔" + "═" * _IW + "╗  ║"
    _ibot   = "║  ╚" + "═" * _IW + "╝  ║"
    def _art(a):
        return "║  " + a + " " * (_OW - 2 - len(a)) + "║"
    def _irow(t):
        return "║  ║ " + t + " " * (_OW - 8 - len(t)) + " ║  ║"
    _art_lines = [
        "  ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ",
        "  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗",
        "  ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║",
        "  ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║",
        "  ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║",
        "  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
    ]
    _info_lines = [
        "HYDRA: MULTI-PROTOCOL PROXY MANAGER v0.0.1",
        "Mieru | NaiveProxy | SlipGate | WARP | MTProxy",
        "AmneziaWG | VPN & DNS Tunnels",
        "Dynamic Subscriptions | Fail2ban | GeoIP Block",
    ]
    # Строки предупреждения о RAM (красные + жирные через ANSI)
    _BOLD_RED = '\033[1;31m'
    _NC_LOC   = '\033[0m'
    _ram_lines = [
        f"{_BOLD_RED}⚠  ВНИМАНИЕ: для корректной работы всех функций   {_NC_LOC}",
        f"{_BOLD_RED}⚠  рекомендуется ОЗУ VPS от 2 ГБ!                 {_NC_LOC}",
        f"{_BOLD_RED}⚠  При меньшем объёме работа скрипта и ПО          {_NC_LOC}",
        f"{_BOLD_RED}⚠  НЕ ГАРАНТИРУЕТСЯ.                               {_NC_LOC}",
    ]
    # Вспомогательная функция: строка рамки с ANSI (учитываем скрытые символы)
    def _irow_ansi(raw: str) -> str:
        """Строка внутренней рамки. raw уже содержит ANSI — ширина вычисляется по видимым символам."""
        import re as _re
        visible = _re.sub(r'\033\[[0-9;]*m', '', raw)
        pad = _OW - 8 - len(visible)
        return "║  ║ " + raw + " " * max(pad, 0) + " ║  ║"
    _ram_sep = "║  ║" + "─" * _IW + "║  ║"
    _ram_block = (
        [_ram_sep] + [_irow_ansi(rl) for rl in _ram_lines]
        if show_ram_warning else []
    )
    _rows = (
        [_top, _blank]
        + [_art(a) for a in _art_lines]
        + [_blank, _itop]
        + [_irow(il) for il in _info_lines]
        + _ram_block
        + [_ibot, _blank, _bot]
    )
    return "\n" + "\n".join(_rows) + "\n"

# Сохраняем глобальную BANNER для обратной совместимости (verify.py и
# любой другой код, ожидающий готовую строку с баннером). Это статичный
# вариант "по умолчанию" — с RAM-предупреждением, как раньше.
BANNER = _make_banner(show_ram_warning=True)

# Порог ОЗУ (МБ), ниже которого показывается предупреждение в баннере.
# 2048 МБ заявлено как рекомендуемый минимум в самом тексте плашки.
_RAM_WARNING_THRESHOLD_MB = 2048

def print_banner() -> None:
    # К моменту вызова print_banner() (из main.py или из меню) модуль
    # уже полностью импортирован, TOTAL_RAM определён ниже по файлу —
    # переменная доступна в момент вызова функции.
    _low_ram = TOTAL_RAM < _RAM_WARNING_THRESHOLD_MB
    print(_make_banner(show_ram_warning=_low_ram))

# =============================================================================
#  ПРОГРЕСС-БАР
# =============================================================================
class Progress:
    def __init__(self) -> None:
        self.total:   int = 100
        self.current: int = 0
        self.label:   str = ""

    def init(self, total: int = 100, label: str = "Установка") -> None:
        self.total   = total
        self.current = 0
        self.label   = label
        print()

    def update(self, increment: int = 1, label: str = "") -> None:
        if label:
            self.label = label
        self.current = min(self.current + increment, self.total)
        percent = self.current * 100 // self.total
        width   = 40
        filled  = percent * width // 100
        empty   = width - filled
        # Цвет градиентом по прогрессу
        if percent >= 100:   col = WHITE
        elif percent >= 75:  col = GREEN
        elif percent >= 40:  col = CYAN
        else:                col = BLUE
        bar_fill  = f"{col}{'▓' * filled}{NC}"
        bar_empty = f"{DIM}{'░' * empty}{NC}"
        print(
            f"\r{CYAN}[{self.label:<15}]{NC} "
            f"{bar_fill}{bar_empty} {col}{percent:3d}%{NC}\033[K",
            end="", flush=True
        )
        if percent == 100:
            print()


PROGRESS = Progress()

# =============================================================================
#  СИСТЕМНЫЕ ПЕРЕМЕННЫЕ
# =============================================================================
CONFIG_DIR           = Path("/etc/xray")
NGINX_CONF_DIR       = Path("/etc/nginx/sites-available")
NGINX_ENABLED_DIR    = Path("/etc/nginx/sites-enabled")
XRAY_BIN             = Path("/usr/local/bin/xray")
XRAY_SERVICE         = Path("/etc/systemd/system/xray.service")
OPTIMIZER_CONF       = Path("/etc/sysctl.d/99-vless-performance.conf")
LIMITS_CONF          = Path("/etc/security/limits.d/99-vless-limits.conf")
SYSTEMD_CONF         = Path("/etc/systemd/system.conf.d/99-vless-limits.conf")
FAIL2BAN_CONF        = Path("/etc/fail2ban/jail.d/xray-reality.conf")
NGINX_RATE_LIMIT_CONF= Path("/etc/nginx/conf.d/rate-limit.conf")
LOCK_FILE            = CONFIG_DIR / ".vless_installed"
UFW_MARK_FILE        = Path("/var/lib/xray-installer/ufw-rules")
XRAY_BACKUP_DIR      = BACKUP_DIR / "binaries"

# Пути для модуля диагностики (check_split_tunnel)
DIAG_CONFIG_FILE     = CONFIG_DIR / "config.json"
DIAG_ALT_CONFIG_FILE = Path("/usr/local/etc/xray/config.json")
DIAG_ACCESS_LOG      = Path("/var/log/xray/access.log")
DIAG_ERROR_LOG       = Path("/var/log/xray/error.log")

# Порт Stats API (должен совпадать с _DIAG_STATS_API_ADDR в модуле диагностики)
XRAY_STATS_API_PORT = 10085


def _get_total_ram_mb() -> int:
    try:
        result = subprocess.run(["free", "-m"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("Mem:"):
                return int(line.split()[1])
    except Exception:
        pass
    return 1024

def _get_total_cpu() -> int:
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1

TOTAL_RAM = _get_total_ram_mb()
TOTAL_CPU = _get_total_cpu()

IS_IPV6_AVAILABLE: bool = False
IPV6_PREFLIGHT:    str  = ""
IPV6_ROUTE_OK:     bool = False

PARAM_UUID:            str  = ""
PARAM_DOMAIN:          str  = ""
PARAM_SHORTID:         str  = ""
PARAM_PUBLIC_KEY:      str  = ""
PARAM_PRIVATE_KEY:     str  = ""
PARAM_EMAIL:           str  = ""
PARAM_SPIDERX:         str  = ""
PARAM_SOCKET_PATH:     str  = ""
PARAM_REALITY_DEST:    str  = ""   # dest/sni для REALITY при AWG-транспорте (чужой сайт, напр. www.microsoft.com)
PARAM_DOMAIN_STRATEGY: str  = ""
PARAM_SITE_TEMPLATE:   str  = ""
PARAM_FINGERPRINT:     str  = "chrome"   # TLS/uTLS fingerprint, выбирается при установке
PRIVATE_KEY_MODE:      str  = "auto"

ROLLBACK_AVAILABLE: bool = False
BACKUP_TIMESTAMP:   str  = ""
INSTALL_STARTED:    bool = False
STAGE_UFW_DONE:     bool = False
STAGE_XRAY_DONE:    bool = False
STAGE_NGINX_DONE:   bool = False

# DNSCrypt-proxy globals
DNSCRYPT_BIN         = Path("/usr/local/bin/dnscrypt-proxy")
DNSCRYPT_CONF_DIR    = Path("/etc/dnscrypt-proxy")
DNSCRYPT_CONF        = DNSCRYPT_CONF_DIR / "dnscrypt-proxy.toml"
DNSCRYPT_SERVICE     = Path("/etc/systemd/system/dnscrypt-proxy.service")
DNSCRYPT_LISTEN_ADDR = "127.0.0.1"
DNSCRYPT_LISTEN_PORT = 5300
DNSCRYPT_INSTALLED:  bool = False
PARAM_USE_DNSCRYPT:  bool = False

# =============================================================================
#  CLOUDFLARE WARP GLOBALS
# =============================================================================
WARP_INSTALLED:      bool = False
WARP_CONNECTED:      bool = False

# Режим маршрутизации WARP:
#   "full"      — весь трафик через WARP (кроме SSH-клиента)
#   "selective" — только указанные пользователем IP/домены
#   "runet"     — заблокированные РФ ресурсы (списки runetfreedom)
WARP_MODE:           str  = "full"

# IP SSH-клиента — всегда исключается из WARP для защиты доступа
WARP_SSH_CLIENT_IP:  str  = ""

# Пользовательские ресурсы для selective-режима
WARP_CUSTOM_IPS:     list[str] = []
WARP_CUSTOM_DOMAINS: list[str] = []

# Путь к конфигу WARP MDM (для переопределения настроек)
WARP_MDM_FILE = Path("/var/lib/cloudflare-warp/mdm.xml")

PKG_MGR: str = ""

# =============================================================================
#  РЕЖИМ УСТАНОВКИ (A = одиночный сервер, B = каскад / chained proxy)
# =============================================================================
INSTALL_MODE: str = "A"   # "A" или "B"

# Параметры для Режима B (российский VPS → зарубежный VPS)
CHAIN_EXIT_HOST:    str  = ""   # IP / домен зарубежного VPS
CHAIN_EXIT_PORT:    int  = 443  # порт, на котором зарубежный VPS слушает VLESS
CHAIN_EXIT_UUID:    str  = ""   # UUID зарубежного VPS
CHAIN_EXIT_PUBKEY:  str  = ""   # PublicKey зарубежного VPS
CHAIN_EXIT_SHORTID: str  = ""   # ShortID зарубежного VPS
CHAIN_EXIT_SNI:     str  = ""   # SNI зарубежного VPS (его домен)
CHAIN_EXIT_FP:      str  = "chrome"

# Список всех exit-нод для мульти-каскада (Режим B, до 10 нод)
# Каждый элемент — dict: {host, port, uuid, pubkey, shortid, sni, fp}
CHAIN_NODES: list[dict] = []

MAX_CHAIN_NODES: int = 10

# Стратегия балансировки между exit-нодами (Режим B, только при 2+ нодах)
# "roundRobin" — по очереди, равномерно
# "leastPing"  — к ноде с наименьшим RTT (нужен observatory)
# "leastLoad"  — к ноде с наименьшей нагрузкой (нужен observatory)
# "random"     — случайный выбор при каждом подключении
CHAIN_BALANCER_STRATEGY: str = "roundRobin"

# Индекс "прикреплённой" exit-ноды (0-based). -1 = балансировщик активен (авто).
# При значении >= 0 весь трафик идёт только через эту ноду, балансировщик отключён.
CHAIN_PINNED_NODE_INDEX: int = -1

# =============================================================================
#  AWG 2.0 (AmneziaWG) — параметры для Режима B
# =============================================================================
AWG_EXIT_ENABLED:    bool = False  # True если выбран AWG как транспорт exit
# ── Hysteria2 транспорт (Режим B, аддитивно) ──────────────────────────────────
H2_EXIT_ENABLED:     bool = False  # True если выбран Hysteria2 как транспорт exit
# При H2_EXIT_ENABLED=True: AWG_EXIT_ENABLED=False, prompt_chain_params_multi() пропускается.
# Xray конфиг генерируется стандартным generate_xray_config_chain_entry_multi() без изменений.
# После установки вызывается h2_exit_install_local() из hysteria2_exit_mgr.
# ──────────────────────────────────────────────────────────────────────────────
AWG_EXIT_HOST:       str  = ""     # IP зарубежного VPS с AWG-сервером
AWG_EXIT_PORT:       int  = 51820  # UDP-порт AWG-сервера
AWG_CLIENT_LISTEN_PORT: int = 11100  # UDP-порт на котором слушает AWG-клиент (entry-нода)
AWG_INTERFACE:       str  = "awg0" # имя WG-интерфейса на RU-сервере
AWG_SUBNET:          str  = "10.66.66.0/24"
AWG_CLIENT_IP:       str  = "10.66.66.2/32"
AWG_SERVER_IP:       str  = "10.66.66.1/32"
# AWG 2.0 — IPv6 Dual-Stack (ULA-подсеть, не конфликтует с глобальными адресами)
AWG_SUBNET_V6:       str  = "fd66:66:66::/64"
AWG_CLIENT_IPv6:     str  = "fd66:66:66::2/128"
AWG_SERVER_IPv6:     str  = "fd66:66:66::1/128"
AWG_MTU:             int  = 1280
AWG_INSTALLED:       bool = False
# Ключи — заполняются в awg_generate_keys()
AWG_SERVER_PRIVKEY:  str  = ""
AWG_SERVER_PUBKEY:   str  = ""
AWG_CLIENT_PRIVKEY:  str  = ""
AWG_CLIENT_PUBKEY:   str  = ""
AWG_PRESHARED_KEY:   str  = ""
# Параметры обфускации AmneziaWG
AWG_JC:   int = 4       # Junk packet count  (4-10 рекоменд.)
AWG_JMIN: int = 40      # Junk packet min size
AWG_JMAX: int = 70      # Junk packet max size
AWG_S1:   int = 0       # Init packet junk size
AWG_S2:   int = 0       # Response packet junk size
AWG_H1:   int = 1       # Init packet magic header
AWG_H2:   int = 2       # Response packet magic header
AWG_H3:   int = 3       # Under load packet magic header
AWG_H4:   int = 4       # Transport packet magic header
# Routing mark для policy routing
AWG_FWMARK:      int = 1000
AWG_ROUTE_TABLE: int = 1000

# === PATCH v2: globals ===
AWG_NODES: list = []            # [] → одна нода (совместимость с одиночным режимом)
AWG_ACTIVE_NODE_INDEX: int = 0  # индекс активной ноды в AWG_NODES
AWG_PREFER_INDEX: int = 0       # предпочтительная нода (для возврата после failover)
_AWG_SSH_CLIENT_IP: str = ""    # IP SSH-клиента — исключается из AWG-маршрутизации
# === END PATCH v2: globals ===
# Бинарники AWG
AWG_BIN:       str = "awg"
AWG_QUICK_BIN: str = "awg-quick"

# =============================================================================
#  РЕЖИМ ПРОТОКОЛА (REALITY / xHTTP_TLS)
# =============================================================================
# "reality"  — VLESS + TCP + REALITY (xtls-rprx-vision)  — классический
# "xhttp"    — VLESS + xHTTP + TLS   (H2/HTTPS маскировка)
PROTOCOL_MODE: str = "reality"   # "reality" | "xhttp"

# Режим XTLS-flow (только для PROTOCOL_MODE == "reality")
# "xtls-rprx-vision"  — Vision (умолчание, лучшая совместимость, рекомендуется)
# "xtls-rprx-splice"  — Splice (меньше копирований в ядре, выше скорость на Linux)
# ""                  — без flow (fallback для старых клиентов / отладки)
XTLS_FLOW: str = "xtls-rprx-vision"

# Режим работы xHTTP (только для PROTOCOL_MODE == "xhttp")
# "streamup" | "streamone" | "packetup"
XHTTP_MODE: str = "streamup"

# Порт прослушивания Xray (общий для REALITY и xHTTP, по умолчанию 443)
# Пользователь может выбрать любой порт 1–65535 при установке.
SERVER_PORT: int = 443
XHTTP_PORT:  int = 443   # backward-compat alias, всегда == SERVER_PORT

# Путь (path) xHTTP endpoint
XHTTP_PATH: str = ""   # авто-генерируется если пусто
XHTTP_MODE_SUPPORTED: bool = False  # True только после _detect_xhttp_mode_support(); безопасный дефолт — False

# Пресет производительности xHTTP (smux / sockopt / TLS)
# "auto"    — умолчания Xray, без дополнительных параметров
# "speed"   — максимальная пропускная способность (32 потока, tcpNoDelay, TLS 1.3)
# "balance" — компромисс скорость/стабильность (16 потоков, tcpNoDelay, TLS 1.2+)
XHTTP_PERF_PRESET: str = "auto"

# =============================================================================
#  ДОПОЛНИТЕЛЬНЫЕ ПАРАМЕТРЫ ОПТИМИЗАЦИИ xHTTP (по документации XHTTP: Beyond REALITY)
# =============================================================================
# xPaddingBytes — размер padding в заголовках запросов/ответов.
#   Диапазон "min-max" (рекомендуется "100-1000"), каждый раз случайный.
#   Уменьшает fingerprint по фиксированной длине заголовка.
XHTTP_PADDING_BYTES: str = "100-1000"

# noSSEHeader — отключить Content-Type: text/event-stream в ответе сервера.
#   false = SSE-заголовок включён (по умолчанию, лучшая совместимость).
#   true  = отключить (если CDN блокирует SSE).
XHTTP_NO_SSE_HEADER: bool = False

# scStreamUpServerSecs — только для stream-up, только сервер.
#   Сервер каждые N секунд отправляет xPaddingBytes байт для поддержания соединения.
#   Диапазон "20-80" (по умолч.), предотвращает разрыв CF/CDN через 100 с без данных.
#   -1 = отключить механизм.
XHTTP_SC_STREAM_UP_SERVER_SECS: str = "20-80"

# scMaxEachPostBytes — только для packet-up.
#   Максимальный объём данных в одном POST-запросе клиента.
#   Должно быть меньше лимита CDN/middlebox. По умолчанию 1000000 (1 МБ).
#   Поддерживает диапазон: "500000-1000000".
XHTTP_SC_MAX_EACH_POST_BYTES: str = "1000000"

# scMaxBufferedPosts — только для packet-up, только сервер.
#   Максимальное количество буферизованных POST-запросов на сервере (на одну сессию).
#   При превышении соединение разрывается. По умолчанию 30.
XHTTP_SC_MAX_BUFFERED_POSTS: int = 30

# =============================================================================
#  ДОПОЛНИТЕЛЬНЫЕ ПАРАМЕТРЫ xHTTP (блок extra, новая структура документации)
# =============================================================================
# host — заголовок Host HTTP-запросов клиента. Отдельно от SNI.
#   Нужен при CDN/domain fronting, когда SNI и Host различаются.
#   Пустая строка = использовать SNI из tlsSettings.
XHTTP_HOST: str = ""

# noGRPCHeader — отключить Content-Type: application/grpc в upload-запросах (клиент).
#   false = заголовок grpc включён (маскировка под gRPC, умолчание).
#   true  = отключить (если gRPC фильтруется провайдером/CDN).
XHTTP_NO_GRPC_HEADER: bool = False

# scMinPostsIntervalMs — только для packet-up, только клиент.
#   Минимальный интервал в мс между POST-запросами клиента в одном соединении.
#   По умолч. 30 мс. Диапазон "10-50" снижает fingerprint.
#   Слишком малый — перегружает буфер сервера; слишком большой — снижает скорость.
XHTTP_SC_MIN_POSTS_INTERVAL_MS: str = "30"

# xmux — мультиплексирование proxy-потоков внутри одного HTTP/2 соединения (клиент).
#   Существенно повышает пропускную способность при H2, особенно на высоком RTT.
#   Применяется в основном для streamup / streamone / auto.
XHTTP_XMUX_ENABLED: bool = False
XHTTP_XMUX_MAX_CONCURRENCY:   str = "16-32"   # параллельных proxy-потоков на соединение
XHTTP_XMUX_MAX_CONNECTIONS:   int = 0          # 0 = без лимита
XHTTP_XMUX_C_MAX_REUSE_TIMES: str = "0"        # переиспользований соединения; 0 = без лимита
XHTTP_XMUX_H_MAX_REQUEST_TIMES: str = "600-900" # запросов через H2-соединение до замены
XHTTP_XMUX_H_MAX_REUSABLE_SECS: str = "1800-3000" # время жизни соединения (сек)
XHTTP_XMUX_H_KEEP_ALIVE_PERIOD: int = 0        # keepalive период (сек); 0 = выкл

# enableSessionResumption — возобновление TLS-сессий (tlsSettings, сервер+клиент).
#   При включении TLS-хендшейк при переподключении не требует повторной передачи сертификата.
XHTTP_ENABLE_SESSION_RESUMPTION: bool = False

# tcpNoDelay — отключить алгоритм Nagle для xhttp sockopt (снижает латентность).
#   В пресете speed/balance уже включён, здесь — явное управление.
XHTTP_TCP_NO_DELAY: bool = False

# INSTALL_COMPLETED — сигнализирует EXIT TRAP что работа завершена нормально
INSTALL_COMPLETED: bool = False

# =============================================================================
#  РАЗДЕЛЬНОЕ ТУННЕЛИРОВАНИЕ (SPLIT TUNNELING)
# =============================================================================
# Если True — заблокированный в РФ трафик идёт через proxy, остальной — direct
SPLIT_TUNNEL_ENABLED: bool = False

# Пути к dat-файлам на диске
GEOSITE_DAT = CONFIG_DIR / "geosite.dat"
GEOIP_DAT   = CONFIG_DIR / "geoip.dat"

# URL актуальных списков runetfreedom (регулярно обновляются)
GEOSITE_URL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
GEOIP_URL   = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"

# Дополнительные домены/IP, добавленные вручную пользователем
# Формат: список строк — домен ("example.com") или CIDR ("1.2.3.0/24")
SPLIT_TUNNEL_EXTRA_DOMAINS: list[str] = []
SPLIT_TUNNEL_EXTRA_IPS:     list[str] = []

# Конфигурационный файл с пользовательскими дополнениями
SPLIT_TUNNEL_CUSTOM_FILE = Path("/etc/xray/split_tunnel_custom.json")

# =============================================================================
#  EXIT TRAP
# =============================================================================
import atexit

def _on_exit() -> None:
    global INSTALL_STARTED
    if INSTALL_COMPLETED or not INSTALL_STARTED:
        return
    print()
    print(f"{RED}[ERROR]{NC} Скрипт завершился с ошибкой.")
    print(f"{YELLOW}[WARN]{NC}  Система может быть в неполном состоянии.")
    if shutil.which("ufw"):
        _run(["ufw", "allow", "22/tcp", "comment", "SSH (emergency restore)"],
             check=False, quiet=True)
    print(f"{YELLOW}[WARN]{NC}  Полный лог: {LOG_FILE}")

atexit.register(_on_exit)

# =============================================================================
#  УТИЛИТЫ
# =============================================================================
def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None

# --- HYDRA helpers (single-node, без Xray/cascade) -------------------------
def _nodes_from_state(state: dict) -> list:
    """Cascade nodes не используются в HYDRA."""
    return []


def _users_from_state() -> list[dict]:
    """Пользователи подписок из state.json."""
    if not STATE_FILE.exists():
        return []
    try:
        state = json.loads(STATE_FILE.read_text())
        out: list[dict] = []
        for email, meta in state.get("users", {}).items():
            row = {"email": email, "name": email}
            if isinstance(meta, dict):
                row.update(meta)
            out.append(row)
        return out
    except Exception:
        return []


_HYDRA_BACKUP_FILES = (
    STATE_FILE,
    Path("/var/lib/xray-installer/naiveproxy.json"),
    Path("/var/lib/xray-installer/mieru.json"),
    Path("/var/lib/xray-installer/sub_server.json"),
    Path("/var/lib/xray-installer/tg_bot.json"),
    Path("/var/lib/xray-installer/ingress_geoip.json"),
    Path("/var/lib/xray-installer/ipban.json"),
)


def _hydra_collect_backup_paths() -> list[tuple[Path, str]]:
    items: list[tuple[Path, str]] = []
    for p in _HYDRA_BACKUP_FILES:
        if p.exists():
            items.append((p, p.name))
    sub_dir = Path("/var/lib/xray-installer/subscriptions")
    if sub_dir.is_dir():
        for f in sub_dir.glob("*.json"):
            items.append((f, f"subscriptions/{f.name}"))
    return items


def do_hydra_export_backup(encrypt: bool = False) -> None:
    """Архив state + конфигов HYDRA-стека."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_path = Path(f"/root/hydra-backup-{ts}.tar.gz")
    items = _hydra_collect_backup_paths()
    if not items:
        warn("Нет файлов для экспорта — сначала выполните установку HYDRA")
        return
    info(f"Экспорт HYDRA → {archive_path}")
    import tarfile
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        manifest = []
        for src, arcname in items:
            dst = tmpdir / arcname
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            manifest.append(arcname)
        (tmpdir / "MANIFEST.txt").write_text("\n".join(manifest), encoding="utf-8")
        with tarfile.open(archive_path, "w:gz") as tar:
            for f in tmpdir.rglob("*"):
                if f.is_file():
                    tar.add(f, arcname=f.relative_to(tmpdir).as_posix())
    archive_path.chmod(0o600)
    success(f"Архив создан: {archive_path} ({len(items)} файлов)")
    if encrypt:
        try:
            import getpass
            pwd = getpass.getpass("  Пароль для шифрования: ")
            pwd2 = getpass.getpass("  Повторите пароль: ")
        except Exception:
            pwd = input("  Пароль: ").strip()
            pwd2 = input("  Повторите: ").strip()
        if pwd != pwd2 or not pwd:
            warn("Пароли не совпали — архив оставлен без шифрования")
            return
        enc = _backup_encrypt(archive_path, pwd)
        if enc:
            archive_path.unlink(missing_ok=True)
            success(f"Зашифровано: {enc}")


def do_hydra_import_backup() -> None:
    """Восстановление state/конфигов HYDRA из tar.gz."""
    raw = input("  Путь к архиву (.tar.gz или .gz.enc): ").strip()
    ap = Path(raw)
    if not ap.exists():
        warn(f"Файл не найден: {ap}")
        return
    if ap.suffix == ".enc":
        try:
            import getpass
            pwd = getpass.getpass("  Пароль для расшифровки: ")
        except Exception:
            pwd = input("  Пароль: ").strip()
        dec_path = ap.with_suffix("").with_suffix(".tar.gz")
        if not _backup_decrypt(ap, pwd, dec_path):
            return
        ap = dec_path
    import tarfile
    import tempfile
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        with tarfile.open(ap, "r:gz") as tar:
            tar.extractall(tmpdir)
        restored = 0
        for f in tmpdir.rglob("*"):
            if not f.is_file() or f.name == "MANIFEST.txt":
                continue
            rel = f.relative_to(tmpdir)
            if str(rel).startswith("subscriptions/"):
                dest = Path("/var/lib/xray-installer") / rel
            else:
                dest = Path("/var/lib/xray-installer") / f.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
            dest.chmod(0o600)
            restored += 1
    success(f"Восстановлено файлов: {restored}")
    warn("Перезапустите сервисы HYDRA при необходимости (Naive, Mieru, sub-server, боты)")


def do_full_diagnostic() -> None:
    """Диагностика HYDRA-стека без Xray."""
    print()
    _box_top("HYDRA — полная диагностика")
    ts = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    _box_row(f"  {DIM}{ts}{NC}")
    _box_row(f"  {BOLD}Сервисы:{NC}")
    hydra_svcs = (
        "caddy-naive", "mita", "hydra-sub-server",
        "hydra-tg-bot", "hydra-tg-admin", "dnscrypt-proxy",
    )
    for svc in hydra_svcs:
        r = _run(["systemctl", "is-active", svc], capture=True, check=False)
        st = r.stdout.strip()
        if st == "active":
            _box_row(f"  {GREEN}●{NC} {svc:<24} {GREEN}активен{NC}")
        elif st == "inactive":
            _box_row(f"  {DIM}○{NC} {svc:<24} {DIM}не запущен{NC}")
        else:
            _box_row(f"  {RED}✗{NC} {svc:<24} {RED}{st or 'нет'}{NC}")
    _box_row()
    if STATE_FILE.exists():
        try:
            st = json.loads(STATE_FILE.read_text())
            dom = st.get("sub_domain") or st.get("domain", "")
            users_n = len(st.get("users", {}))
            _box_row(f"  {BOLD}State:{NC} домен={dom or '—'}  пользователей={users_n}")
        except Exception as e:
            _box_row(f"  {RED}state.json: {e}{NC}")
    else:
        _box_row(f"  {YELLOW}state.json не найден{NC}")
    _box_row()
    _box_row(f"  {BOLD}Сеть:{NC}")
    try:
        verify_connectivity()
    except Exception as e:
        warn(f"verify_connectivity: {e}")
    _box_row()
    try:
        do_dns_leak_test()
    except Exception:
        pass
    _box_bottom()



def find_nginx_bin() -> str | None:
    """Возвращает полный путь к бинарнику nginx, проверяя реальное существование файла."""
    found = shutil.which("nginx")
    if found:
        try:
            if Path(found).resolve().exists():
                return found
        except Exception:
            pass
    for p in ("/usr/sbin/nginx", "/usr/bin/nginx",
              "/usr/local/sbin/nginx", "/usr/local/bin/nginx",
              "/opt/nginx/sbin/nginx"):
        try:
            pp = Path(p)
            if pp.exists() and pp.resolve().exists():
                return p
        except Exception:
            pass
    try:
        import subprocess as _sp
        r = _sp.run(
            ["find", "/usr", "/opt", "/snap", "-name", "nginx",
             "-type", "f", "-executable"],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.splitlines():
            if line.strip():
                return line.strip()
    except Exception:
        pass
    return None

def _run(
    args: list[str],
    check: bool = True,
    quiet: bool = False,
    capture: bool = False,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    cwd: str = None,  # <-- ДОБАВИТЬ ЭТУ СТРОКУ
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        result = subprocess.run(
            args,
            capture_output=(capture or quiet),
            text=True,
            input=input_text,
            env=merged_env,
            cwd=cwd,
        )
    except FileNotFoundError:
        if check:
            raise
        # check=False: команда не найдена — возвращаем фиктивный результат с кодом 127
        return subprocess.CompletedProcess(args, 127, stdout="", stderr=f"command not found: {args[0]}")
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, args,
                                            result.stdout, result.stderr)
    return result


def get_adaptive_value(param: str) -> str:
    if TOTAL_RAM < 512:
        mapping: dict[str, str] = {
            "overcommit": "0", "swappiness": "1",
            "conntrack": "262144", "file_max": "524288",
        }
    elif TOTAL_RAM < 1024:
        mapping = {
            "overcommit": "0", "swappiness": "5",
            "conntrack": "524288", "file_max": "1048576",
        }
    else:
        mapping = {
            "overcommit": "1", "swappiness": "10",
            "conntrack": "2000000", "file_max": "2097152",
        }
    return mapping.get(param, "")


def gen_uuid() -> str:
    return str(uuid.uuid4())


def gen_hex(n: int = 8) -> str:
    try:
        result = _run(["openssl", "rand", "-hex", str(n)], capture=True, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return ''.join(random.choices('0123456789abcdef', k=n * 2))


def gen_spiderx() -> str:
    chars = string.ascii_lowercase + string.digits
    length = random.randint(6, 15)
    return '/' + ''.join(random.choices(chars, k=length))


def get_server_ip(ip_type: str = "4") -> str:
    if ip_type == "6":
        urls = ["https://api64.ipify.org"]
        flag = "-6"
    else:
        urls = ["https://api4.ipify.org"]
        flag = "-4"
    for url in urls:
        try:
            r = _run(["curl", "-s", flag, "-m", "5", url],
                     capture=True, check=False)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass

    # ПАТЧ: fallback через 'ip route get 8.8.8.8' — работает без доступа в интернет,
    # на серверах со сложной маршрутизацией или несколькими интерфейсами.
    # Критично для awg_apply_policy_routing: без корректного локального IP
    # исключение из AWG-маршрутизации не будет добавлено → потеря SSH после ребута.
    if ip_type == "4":
        try:
            r2 = _run(["ip", "route", "get", "8.8.8.8"],
                      capture=True, check=False)
            if r2.returncode == 0:
                # Парсим строку вида: "8.8.8.8 via ... src 1.2.3.4 uid ..."
                for token in r2.stdout.split():
                    if token == "src":
                        idx = r2.stdout.split().index("src")
                        candidate = r2.stdout.split()[idx + 1]
                        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate):
                            return candidate
        except Exception:
            pass

    return ""


def country_flag_emoji(country_code: str) -> str:
    """
    Возвращает эмодзи флага страны по двухбуквенному коду ISO 3166-1 alpha-2.
    Принцип: буквы A-Z маппятся на региональные индикаторы Unicode (U+1F1E6..U+1F1FF).
    """
    cc = country_code.upper().strip()
    if len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc)


def get_server_country() -> tuple[str, str, str]:
    """
    Определяет страну сервера по его публичному IPv4 через ip-api.com.
    Возвращает (country_code, country_name, flag_emoji).
    """
    try:
        r = _run(
            ["curl", "-s", "--max-time", "8",
             "http://ip-api.com/json?fields=status,country,countryCode,city"],
            capture=True, check=False
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout.strip())
            if data.get("status") == "success":
                cc   = data.get("countryCode", "??")
                name = data.get("country", "Unknown")
                return cc, name, country_flag_emoji(cc)
    except Exception:
        pass
    return "??", "Unknown", "🌐"


# Кеш страны сервера — заполняется один раз при первом вызове get_server_country_cached()
_SERVER_CC:   str = ""
_SERVER_NAME: str = ""
_SERVER_FLAG: str = ""


def get_server_country_cached() -> tuple[str, str, str]:
    """Возвращает (country_code, country_name, flag_emoji), кешируя результат."""
    global _SERVER_CC, _SERVER_NAME, _SERVER_FLAG
    if not _SERVER_CC:
        _SERVER_CC, _SERVER_NAME, _SERVER_FLAG = get_server_country()
    return _SERVER_CC, _SERVER_NAME, _SERVER_FLAG


def generate_self_signed_cert(domain: str) -> None:
    le_path = Path(f"/etc/letsencrypt/live/{domain}")
    info(f"Генерация самоподписанного сертификата для {domain}...")
    le_path.mkdir(parents=True, exist_ok=True)
    _run([
        "openssl", "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", str(le_path / "privkey.pem"),
        "-out",    str(le_path / "fullchain.pem"),
        "-subj",   f"/CN={domain}/O=SelfSigned/C=US",
        "-addext", f"subjectAltName=DNS:{domain}",
    ], quiet=True, check=False)
    try:
        (le_path / "privkey.pem").chmod(0o600)
        (le_path / "fullchain.pem").chmod(0o644)
    except Exception:
        pass
    success("Самоподписанный сертификат создан")

# =============================================================================
#  ПРОВЕРКА РЕСУРСОВ
# =============================================================================
def _check_resources() -> None:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable"):
                    mem_free_mb = int(line.split()[1]) // 1024
                    break
            else:
                mem_free_mb = 0
    except Exception:
        mem_free_mb = 0

    if mem_free_mb < 256:
        warn(f"Мало свободной RAM: {mem_free_mb} МБ (рекомендуется ≥ 256 МБ)")
        ans = input(f"{YELLOW}Продолжить? [y/N]:{NC} ").strip().lower()
        if ans != 'y':
            info("Отменено.")
            sys.exit(0)
    else:
        info(f"RAM: {mem_free_mb} МБ — OK | CPU: {TOTAL_CPU} ядер")

    try:
        r = _run(["df", "-BG", "/"], capture=True, check=False)
        parts = r.stdout.splitlines()[1].split()
        disk_free_gb = int(parts[3].rstrip('G'))
    except Exception:
        disk_free_gb = 0

    if disk_free_gb < 1:
        warn(f"Мало места на диске: {disk_free_gb} ГБ (рекомендуется ≥ 1 ГБ)")
        ans = input(f"{YELLOW}Продолжить? [y/N]:{NC} ").strip().lower()
        if ans != 'y':
            info("Отменено.")
            sys.exit(0)
    else:
        info(f"Диск: {disk_free_gb} ГБ свободно — OK")

# =============================================================================
#  IPV6 PREFLIGHT
# =============================================================================
def _check_ipv6_preflight() -> None:
    global IS_IPV6_AVAILABLE, IPV6_PREFLIGHT, IPV6_ROUTE_OK

    try:
        r = _run(["ip", "-6", "addr", "show", "scope", "global"],
                 capture=True, check=False)
        addrs = re.findall(r'inet6\s+([0-9a-f:]+)/', r.stdout)
        addrs = [a for a in addrs if not a.startswith('fe80')]
        IPV6_PREFLIGHT = addrs[0] if addrs else ""
    except Exception:
        IPV6_PREFLIGHT = ""

    if not IPV6_PREFLIGHT:
        warn("Публичный IPv6 не обнаружен — только IPv4.")
        IS_IPV6_AVAILABLE = False
        return

    info(f"IPv6-адрес: {IPV6_PREFLIGHT}")

    try:
        r = _run(["ip", "-6", "route", "show", "default"], capture=True, check=False)
        if "default" not in r.stdout:
            warn("IPv6-адрес есть, но маршрут по умолчанию отсутствует.")
            IS_IPV6_AVAILABLE = False
            return
    except Exception:
        IS_IPV6_AVAILABLE = False
        return

    ipv6_conn = False
    if command_exists("ping6"):
        r = _run(["ping6", "-c1", "-W2", "2001:4860:4860::8888"],
                 check=False, quiet=True)
        if r.returncode == 0:
            ipv6_conn = True

    if not ipv6_conn:
        r = _run(["curl", "-6", "-s", "--connect-timeout", "4",
                  "https://ipv6.icanhazip.com"],
                 check=False, quiet=True)
        if r.returncode == 0:
            ipv6_conn = True

    if not ipv6_conn:
        warn("IPv6-адрес и маршрут есть, но связность не подтверждена.")
        IS_IPV6_AVAILABLE = False
    else:
        IPV6_ROUTE_OK     = True
        IS_IPV6_AVAILABLE = True
        success(f"IPv6: {IPV6_PREFLIGHT} — маршрут и связность OK (dual-stack активен)")

# =============================================================================
#  МЕНЕДЖЕР ПАКЕТОВ
# =============================================================================
def _init_pkg_mgr() -> None:
    global PKG_MGR
    if command_exists("apt-get"):
        PKG_MGR = "apt"
    elif command_exists("dnf"):
        PKG_MGR = "dnf"
    else:
        die("Поддерживаются только apt / dnf системы")


def _pkg_install(*pkgs: str) -> None:
    if PKG_MGR == "apt":
        _run(["apt-get", "install", "-y", "-q", *pkgs],
             env={"DEBIAN_FRONTEND": "noninteractive"}, check=False, quiet=True)
    else:
        _run(["dnf", "install", "-y", "-q", *pkgs], check=False, quiet=True)


def _pkg_update() -> None:
    if PKG_MGR == "apt":
        _run(["apt-get", "update", "-q"], check=False, quiet=True)
    else:
        _run(["dnf", "check-update", "-q"], check=False, quiet=True)


# =============================================================================
#  КАРТА КОМАНДА → APT/DNF ПАКЕТ  (используется умным обработчиком ошибок)
# =============================================================================
# Ключ  — имя исполняемого файла, который скрипт вызывает через subprocess.
# Значение — (apt_pkg, dnf_pkg) или просто строка если имя совпадает.
_CMD_TO_PKG: dict[str, tuple[str, str]] = {
    # bootstrap
    "fuser":           ("psmisc",          "psmisc"),
    "killall":         ("psmisc",          "psmisc"),
    "gpg":             ("gnupg",           "gnupg2"),
    "gpg2":            ("gnupg",           "gnupg2"),
    "lsb_release":     ("lsb-release",     "redhat-lsb-core"),
    "modprobe":        ("kmod",            "kmod"),
    # сеть / загрузка
    "curl":            ("curl",            "curl"),
    "wget":            ("wget",            "wget"),
    "unzip":           ("unzip",           "unzip"),
    "tar":             ("tar",             "tar"),
    # криптография / идентификаторы
    "openssl":         ("openssl",         "openssl"),
    "uuidgen":         ("uuid-runtime",    "util-linux"),
    "sha256sum":       ("coreutils",       "coreutils"),
    # системные утилиты
    "timeout":         ("coreutils",       "coreutils"),
    "date":            ("coreutils",       "coreutils"),
    "df":              ("coreutils",       "coreutils"),
    "uname":           ("coreutils",       "coreutils"),
    "id":              ("coreutils",       "coreutils"),
    "tail":            ("coreutils",       "coreutils"),
    "ip":              ("iproute2",        "iproute"),
    "ss":              ("iproute2",        "iproute"),
    "tc":              ("iproute2",        "iproute"),
    "sysctl":          ("procps",          "procps-ng"),
    "pgrep":           ("procps",          "procps-ng"),
    "free":            ("procps",          "procps-ng"),
    "hostname":        ("hostname",        "hostname"),
    "file":            ("file",            "file"),
    "useradd":         ("passwd",          "shadow-utils"),
    "journalctl":      ("systemd",         "systemd"),
    # сеть / файрволл
    "ufw":             ("ufw",             "ufw"),
    "iptables":        ("iptables",        "iptables"),
    "ip6tables":       ("iptables",        "iptables"),
    "iptables-save":   ("iptables",        "iptables"),
    "ip6tables-save":  ("iptables",        "iptables"),
    "ipset":           ("ipset",           "ipset"),
    "ping6":           ("iputils-ping",    "iputils"),
    # DNS
    "dig":             ("dnsutils",        "bind-utils"),
    "nslookup":        ("dnsutils",        "bind-utils"),
    # cron / логи
    "crontab":         ("cron",            "cronie"),
    "logrotate":       ("logrotate",       "logrotate"),
    # мониторинг
    "htop":            ("htop",            "htop"),
    "jq":              ("jq",              "jq"),
    "zstd":            ("zstd",            "zstd"),
    "irqbalance":      ("irqbalance",      "irqbalance"),
    # SSH
    "sshd":            ("openssh-server",  "openssh-server"),
    # QR
    "qrencode":        ("qrencode",        "qrencode"),
}

# Обратный маппинг: пакет → список команд (для сообщений пользователю)
_PKG_TO_CMDS: dict[str, list[str]] = {}
for _c, (_a, _d) in _CMD_TO_PKG.items():
    _PKG_TO_CMDS.setdefault(_a, []).append(_c)


def _find_pkg_for_missing_cmd(cmd: str) -> tuple[str, str] | None:
    """
    По имени команды возвращает (apt_pkg, dnf_pkg) или None если неизвестна.
    Также пробует dpkg-query / dnf provides как fallback.
    """
    if cmd in _CMD_TO_PKG:
        return _CMD_TO_PKG[cmd]
    # Fallback: спросить пакетный менеджер
    if PKG_MGR == "apt" and shutil.which("apt-file"):
        r = _run(["apt-file", "search", f"bin/{cmd}"], capture=True, check=False)
        if r.stdout:
            first = r.stdout.splitlines()[0].split(":")[0].strip()
            if first:
                return (first, first)
    return None


def _smart_recover(exc: FileNotFoundError) -> bool:
    """
    Вызывается при перехвате FileNotFoundError.
    Определяет отсутствующую команду, находит нужный пакет,
    спрашивает пользователя (или устанавливает автоматически),
    возвращает True если пакет установлен и можно попробовать повторить.
    """
    import traceback as _tb

    # Извлекаем имя команды из исключения
    missing_cmd = ""
    if exc.filename:
        missing_cmd = os.path.basename(str(exc.filename))
    elif exc.args:
        m = re.search(r"'([^']+)'", str(exc.args))
        if m:
            missing_cmd = os.path.basename(m.group(1))

    tb_str = _tb.format_exc()

    print()
    print(f"{RED}{'═'*64}{NC}")
    print(f"{RED}  💥 КОМАНДА НЕ НАЙДЕНА: {BOLD}{missing_cmd or '?'}{NC}")
    print(f"{RED}{'═'*64}{NC}")

    pkg_info = _find_pkg_for_missing_cmd(missing_cmd) if missing_cmd else None
    apt_pkg  = pkg_info[0] if pkg_info else None
    dnf_pkg  = pkg_info[1] if pkg_info else None
    install_pkg = apt_pkg if PKG_MGR == "apt" else dnf_pkg

    if install_pkg:
        print(f"{YELLOW}  Пакет для установки:{NC} {CYAN}{install_pkg}{NC}")
    else:
        print(f"{YELLOW}  Пакет для '{missing_cmd}' неизвестен.{NC}")
        print(f"{DIM}  Попробуйте: apt-get install -y $(apt-file search bin/{missing_cmd} | head -1 | cut -d: -f1){NC}")

    print()
    print(f"{DIM}  Трассировка:{NC}")
    for line in tb_str.strip().splitlines()[-6:]:
        print(f"  {DIM}{line}{NC}")
    print()
    log_to_file("ERROR", f"FileNotFoundError: команда '{missing_cmd}', пакет '{install_pkg}'")
    log_to_file("ERROR", tb_str)

    if not install_pkg:
        return False

    # Предлагаем авто-установку
    print(f"{YELLOW}  Что делать?{NC}")
    print(f"  {DIM}[{NC}{WHITE}{BOLD}A{NC}{DIM}]{NC}  Установить {CYAN}{install_pkg}{NC} автоматически")
    print(f"  {DIM}[{NC}{WHITE}{BOLD}S{NC}{DIM}]{NC}  Пропустить (продолжить без этого пакета)")
    print(f"  {DIM}[{NC}{RED}{BOLD}Q{NC}{DIM}]{NC}  Выйти из скрипта")
    print()
    try:
        choice = input(f"{CYAN}  Выбор [A/S/Q]:{NC} ").strip().upper()
    except (KeyboardInterrupt, EOFError):
        print()
        return False

    if choice == "Q":
        print(f"{YELLOW}Выход.{NC}")
        sys.exit(1)
    elif choice == "S":
        warn(f"Пропускаем установку {install_pkg} — скрипт продолжает работу")
        return False
    else:
        # Авто-установка
        print()
        info(f"Устанавливаю {install_pkg}...")
        try:
            if PKG_MGR == "apt":
                _run(["apt-get", "install", "-y", "-q", install_pkg],
                     env={"DEBIAN_FRONTEND": "noninteractive"}, check=False, quiet=True)
            else:
                _run(["dnf", "install", "-y", "-q", install_pkg], check=False, quiet=True)
            if shutil.which(missing_cmd) or _run(
                    ["dpkg", "-l", install_pkg], capture=True, check=False
               ).stdout and any(
                    l.startswith("ii") for l in _run(
                        ["dpkg", "-l", install_pkg], capture=True, check=False
                    ).stdout.splitlines()):
                success(f"{install_pkg} установлен успешно")
                return True
            else:
                warn(f"Пакет {install_pkg} установлен, но команда '{missing_cmd}' всё ещё не найдена")
                return False
        except Exception as e2:
            warn(f"Не удалось установить {install_pkg}: {e2}")
            return False


def _wait_apt_lock_startup() -> None:
    """
    Ожидание снятия блокировки apt (используется при стартовой проверке).
    Безопасно работает даже если fuser (psmisc) ещё не установлен:
    в этом случае проверяет блокировку через /proc напрямую.
    """
    if PKG_MGR != "apt":
        return

    import glob as _glob

    def _lock_held() -> bool:
        lock = "/var/lib/dpkg/lock-frontend"
        if shutil.which("fuser"):
            r = _run(["fuser", lock], capture=True, check=False)
            return r.returncode == 0
        # Fallback без fuser: смотрим /proc/*/fd/*
        try:
            lock_real = os.path.realpath(lock)
            for fd_path in _glob.glob("/proc/*/fd/*"):
                try:
                    if os.path.realpath(fd_path) == lock_real:
                        return True
                except (OSError, PermissionError):
                    pass
        except Exception:
            pass
        return False

    waited = 0
    while _lock_held():
        if waited == 0:
            warn("apt заблокирован — ждём освобождения...")
        time.sleep(2)
        waited += 2
        if waited >= 60:
            warn("apt lock не освободился за 60с — продолжаем")
            return
    if waited > 0:
        info(f"apt lock освобождён ({waited}с)")


def ensure_startup_dependencies() -> None:
    """
    Проверка и установка ВСЕХ зависимостей, необходимых для работы скрипта
    и устанавливаемого им ПО. Вызывается единожды при старте, ДО любых операций.

    Сюда вынесены все пакеты/модули, которые ранее могли устанавливаться
    разбросанно по ходу скрипта (в install_dependencies, отдельных шагах и т.д.).

    Перед фактической установкой пользователю показывается полный список
    пакетов и запрашивается подтверждение (один раз — согласие сохраняется
    в /var/lib/xray-installer/.deps_consent, чтобы retry-попытки после сбоя
    не спрашивали повторно).
    """

    # ── Живой прогресс-бар ───────────────────────────────────────────────────
    # Единый бар на всю функцию. Фазы и их веса (в условных "единицах"):
    #   [apt-update]   5   [bootstrap]  5   [sys-pkgs] 50
    #   [nginx]        10  [certbot]   10   [optional] 15  [checks] 5  = 100
    _BAR_W    = 40          # ширина заполняемой части
    _TOTAL_W  = 100         # 100 условных единиц = 100%
    _progress = [0]         # текущий вес
    _cur_pkg  = [""]        # имя текущего пакета/этапа

    def _bar_draw(force_pct: int | None = None) -> None:
        pct    = force_pct if force_pct is not None else int(_progress[0] / _TOTAL_W * 100)
        pct    = min(pct, 100)
        filled = int(_BAR_W * pct / 100)
        bar    = f"\033[96m{'█' * filled}\033[2;96m{'░' * (_BAR_W - filled)}\033[0m"
        label  = _cur_pkg[0][:28].ljust(28)
        line   = (f"  \033[96m[\033[0m{bar}\033[96m]\033[0m"
                  f" \033[1;96m{pct:3d}%\033[0m  \033[2m{label}\033[0m")
        sys.stdout.write(f"\r{line:<90}")
        sys.stdout.flush()

    def _bar_advance(weight: int, label: str = "") -> None:
        if label:
            _cur_pkg[0] = label
        _progress[0] = min(_progress[0] + weight, _TOTAL_W)
        _bar_draw()

    def _bar_set_label(label: str) -> None:
        _cur_pkg[0] = label
        _bar_draw()

    def _is_pkg(pkg: str) -> bool:
        if command_exists(pkg):
            return True
        if PKG_MGR == "apt":
            r = _run(["dpkg", "-l", pkg], capture=True, check=False)
            return any(line.startswith("ii")
                       for line in (r.stdout or "").splitlines())
        else:
            r = _run(["rpm", "-q", pkg], capture=True, check=False)
            return r.returncode == 0

    # ── Экран подтверждения зависимостей (один раз за установку) ────────────
    _consent_flag = Path("/var/lib/xray-installer/.deps_consent")
    if not _consent_flag.exists():
        _all_pkgs_apt = (
            ["psmisc", "gnupg", "lsb-release", "kmod"] +
            ["curl", "wget", "unzip", "tar", "openssl", "uuid-runtime",
             "coreutils", "iproute2", "procps", "jq",
             "ufw", "dnsutils", "zstd", "htop",
             "ipset", "iptables",
             "logrotate", "hostname", "iputils-ping",
             "cron", "file", "openssh-server", "passwd",
             "git", "make", "golang-go"] +
            ["fail2ban", "qrencode", "python3-pip",
             "irqbalance", "unattended-upgrades", "docker.io"]
        )
        _all_pkgs_dnf = (
            ["psmisc", "gnupg2", "redhat-lsb-core", "kmod"] +
            ["curl", "wget", "unzip", "tar", "openssl", "util-linux",
             "coreutils", "iproute", "procps-ng", "jq",
             "ipset", "iptables",
             "logrotate", "hostname", "iputils",
             "cronie", "file", "openssh-server", "shadow-utils",
             "git", "make", "golang"] +
            ["fail2ban", "qrencode", "python3-pip", "irqbalance", "docker"]
        )
        _all_pkgs = _all_pkgs_apt if PKG_MGR == "apt" else _all_pkgs_dnf
        # Уже установленные пакеты не показываем отдельно от тех, что
        # будут ставиться — используем ту же _is_pkg(), что и сама установка.
        _already    = [p for p in _all_pkgs if _is_pkg(p)]
        _to_install = [p for p in _all_pkgs if not _is_pkg(p)]

        print()
        print(f"  {BOLD}{CYAN}Перед началом установки скрипт поставит следующие зависимости:{NC}")
        print()
        if _to_install:
            for i in range(0, len(_to_install), 4):
                row = _to_install[i:i+4]
                print("    " + "  ".join(f"{DIM}•{NC} {p}" for p in row))
        else:
            print(f"    {DIM}все необходимые пакеты уже установлены{NC}")
        print()
        if _already:
            print(f"  {DIM}Уже установлены и не будут переустанавливаться: "
                  f"{', '.join(_already)}{NC}")
            print()
        print(f"  {YELLOW}Среди них есть пакеты, включающие системные службы "
              f"(fail2ban, irqbalance,{NC}")
        print(f"  {YELLOW}unattended-upgrades) — они нужны для работы защиты fail2ban, "
              f"автообновлений{NC}")
        print(f"  {YELLOW}безопасности и балансировки прерываний между ядрами CPU.{NC}")
        print()

        _answer = input(f"  {BOLD}Продолжить установку зависимостей? [Y/n]: {NC}").strip().lower()
        if _answer in ("n", "no", "н", "нет"):
            print()
            info("Установка отменена пользователем. Зависимости не установлены.")
            info("Запустите скрипт повторно, когда будете готовы продолжить.")
            sys.exit(0)

        try:
            _consent_flag.parent.mkdir(parents=True, exist_ok=True)
            _consent_flag.write_text(datetime.now().isoformat())
        except Exception:
            pass
        print()

    # Печатаем заголовок и пустую строку для бара
    info("Проверка и установка зависимостей скрипта...")
    sys.stdout.write("\n")
    sys.stdout.flush()
    _bar_draw()

    # ── 1. Обновляем индекс пакетов ──────────────────────────────────────────
    _bar_set_label("apt-get update...")
    _wait_apt_lock_startup()
    _pkg_update()
    _wait_apt_lock_startup()
    _bar_advance(5, "индекс пакетов обновлён")

    # ── 2. Bootstrap-пакеты ──────────────────────────────────────────────────
    bootstrap_apt = ["psmisc", "gnupg", "lsb-release", "kmod"]
    bootstrap_dnf = ["psmisc", "gnupg2", "redhat-lsb-core", "kmod"]
    boot_pkgs    = bootstrap_apt if PKG_MGR == "apt" else bootstrap_dnf
    boot_missing = [p for p in boot_pkgs if not _is_pkg(p)]
    if boot_missing:
        for pkg in boot_missing:
            _bar_set_label(f"bootstrap: {pkg}")
            _pkg_install(pkg)
    _bar_advance(5, "bootstrap OK")
    _wait_apt_lock_startup()

    # ── 3. Системные пакеты (основная волна) ─────────────────────────────────
    sys_apt = [
        "curl", "wget", "unzip", "tar", "openssl", "uuid-runtime",
        "coreutils", "iproute2", "procps", "jq",
        "ufw", "dnsutils", "zstd", "htop",
        "ipset", "iptables",
        "logrotate", "hostname", "iputils-ping",
        "cron", "file", "openssh-server", "passwd",
        "git", "make", "golang-go",
        "docker.io",
    ]
    sys_dnf = [
        "curl", "wget", "unzip", "tar", "openssl", "util-linux",
        "coreutils", "iproute", "procps-ng", "jq",
        "ipset", "iptables",
        "logrotate", "hostname", "iputils",
        "cronie", "file", "openssh-server", "shadow-utils",
        "git", "make", "golang",
        "docker",
    ]
    pkgs        = sys_apt if PKG_MGR == "apt" else sys_dnf
    missing_sys = [p for p in pkgs if not _is_pkg(p)]

    if missing_sys:
        total_sys = len(missing_sys)
        _bar_set_label(f"системные пакеты (0/{total_sys})")
        _wait_apt_lock_startup()

        import subprocess as _sp_deps
        cmd_deps = (
            ["apt-get", "install", "-y", "--no-install-recommends", *missing_sys]
            if PKG_MGR == "apt"
            else ["dnf", "install", "-y", *missing_sys]
        )
        env_deps = {**os.environ,
                    "DEBIAN_FRONTEND": "noninteractive",
                    "LANGUAGE": "C", "LC_ALL": "C", "LANG": "C"}

        _sys_done  = [0]
        _sys_total = total_sys
        # вес волны B = 50 единиц
        _SYS_WEIGHT = 50

        proc_deps = _sp_deps.Popen(
            cmd_deps,
            stdout=_sp_deps.PIPE, stderr=_sp_deps.STDOUT,
            text=True, env=env_deps, bufsize=1,
        )
        for _line in proc_deps.stdout:  # type: ignore[union-attr]
            _line = _line.rstrip()
            _pkg = ""
            if _line.startswith("Unpacking "):
                _parts = _line.split()
                _pkg = _parts[1].split(":")[0] if len(_parts) >= 2 else ""
            elif _line.startswith("Setting up "):
                _parts = _line.split()
                _pkg = _parts[2].split(":")[0] if len(_parts) >= 3 else ""
                if _pkg in missing_sys:
                    _sys_done[0] += 1
                    _progress[0] = 10 + int(_sys_done[0] / _sys_total * _SYS_WEIGHT)
            elif _line.startswith("E:") or _line.startswith("Err:"):
                log_to_file("WARN", f"apt: {_line}")
                continue
            else:
                continue
            if _pkg:
                _cur_pkg[0] = f"{_pkg} ({_sys_done[0]}/{_sys_total})"
            _bar_draw()

        proc_deps.wait()

        _progress[0] = 10 + _SYS_WEIGHT   # = 60
        _cur_pkg[0]  = f"пакеты ({total_sys}/{total_sys})"
        _bar_draw()

        if proc_deps.returncode != 0:
            warn(f"\napt-get завершился с кодом {proc_deps.returncode} — часть пакетов могла не установиться")
        # success без newline — бар ещё не завершён
    else:
        _progress[0] = 60
        _cur_pkg[0]  = "системные пакеты: уже установлены"
        _bar_draw()

    # ── 4–5. nginx/certbot (legacy VLESS) — не требуются для HYDRA (Caddy) ───
    _bar_advance(20, "nginx/certbot: пропущено (HYDRA)")

    # ── 6. Опциональные пакеты ────────────────────────────────────────────────
    opt_apt = ["fail2ban", "qrencode", "python3-pip",
               "irqbalance", "unattended-upgrades"]
    opt_dnf = ["fail2ban", "qrencode", "python3-pip", "irqbalance"]
    opt_list = opt_apt if PKG_MGR == "apt" else opt_dnf
    for _i, pkg in enumerate(opt_list):
        if not _is_pkg(pkg):
            _bar_set_label(f"опц: {pkg} ({_i+1}/{len(opt_list)})")
            _pkg_install(pkg)
    _bar_advance(10, "опциональные пакеты OK")

    if PKG_MGR == "apt":
        _run(["systemctl", "enable", "--now", "unattended-upgrades"],
             check=False, quiet=True)

    # fail2ban — повторная попытка если не поднялся
    if not command_exists("fail2ban-server"):
        _bar_set_label("fail2ban: повторная попытка...")
        _wait_apt_lock_startup()
        _pkg_install("fail2ban")

    # qrencode — fallback через python3-qrcode
    if not command_exists("qrencode"):
        _bar_set_label("qrencode: pip fallback...")
        for pip_cmd in (["pip3"], ["python3", "-m", "pip"]):
            if command_exists(pip_cmd[0]):
                _run([*pip_cmd, "install", "--break-system-packages",
                      "--quiet", "qrcode[pil]"], check=False, quiet=True)
                break

    # ── 7. Python stdlib ──────────────────────────────────────────────────────
    try:
        import unicodedata  # noqa: F401
    except ImportError:
        warn("\nМодуль unicodedata недоступен — отрисовка меню может быть нарушена")

    # ── 8. Финальная проверка критичных зависимостей ──────────────────────────
    _bar_advance(5, "финальная проверка...")
    critical_missing: list[str] = []
    if not find_nginx_bin():
        critical_missing.append("nginx")
    if not (command_exists("certbot") or Path("/usr/bin/certbot").exists()
            or Path("/snap/bin/certbot").exists()):
        critical_missing.append("certbot")
    for cmd in ("curl", "openssl", "jq"):
        if not (command_exists(cmd) or Path(f"/usr/bin/{cmd}").exists()):
            critical_missing.append(cmd)

    if critical_missing:
        _bar_draw(force_pct=100)
        sys.stdout.write("\n\n")
        sys.stdout.flush()
        print(file=sys.stderr)
        print(f"\033[31m[ERROR]\033[0m Не удалось установить: {' '.join(critical_missing)}",
              file=sys.stderr)
        print(f"\033[33m[HINT]\033[0m  Попробуйте вручную:", file=sys.stderr)
        for pkg in critical_missing:
            print(f"         apt-get install -y {pkg}", file=sys.stderr)
        log_to_file("ERROR",
                    f"Стартовая проверка: недоступны {' '.join(critical_missing)}")
        die("Запуск прерван: критичные зависимости отсутствуют.")

    # Завершаем бар на 100% и переходим на новую строку
    _bar_draw(force_pct=100)
    sys.stdout.write("\n\n")
    sys.stdout.flush()

    success("Все зависимости проверены и готовы к работе")


# =============================================================================
#  BACKUP / ROLLBACK
# =============================================================================
# =============================================================================
#  HEALTH CHECK
# health — перенесено в vless_installer/modules/health.py
def run_unit_tests() -> None:
    passed = 0
    failed = 0
    _box_top("🧪  UNIT-ТЕСТЫ")
    _box_row()
    _box_info("Запуск unit тестов...")
    _box_row()

    def _test(num: int, desc: str, ok: bool) -> None:
        nonlocal passed, failed
        if ok:
            _box_ok(f"Тест {num}: {desc} — OK")
            passed += 1
        else:
            _box_warn(f"Тест {num}: {desc} — FAIL")
            failed += 1

    _test(1, "Python 3.12+",     sys.version_info >= (3, 12))
    _test(2, "Root права",       os.geteuid() == 0)
    _test(3, "jq",               command_exists("jq"))
    _test(4, "UUID генерация",   bool(re.match(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        gen_uuid())))
    _test(5, "ShortID генерация", (lambda s: len(s)==16 and bool(re.match(r'^[0-9a-f]+$',s)))(gen_hex(8)))
    _test(6, f"RAM ({TOTAL_RAM}MB)", TOTAL_RAM >= 256)
    _test(7, "openssl",          command_exists("openssl"))

    _certbot = next((p for p in (Path("/snap/bin/certbot"), Path("/usr/bin/certbot"))
                     if p.exists()), None)
    _test(8, "certbot", _certbot is not None)

    _box_row()
    col = GREEN if failed == 0 else YELLOW
    _box_row(f"  {BOLD}Результаты:{NC} {GREEN}{passed} пройдено{NC} / {col}{failed} провалено{NC}")
    _box_row()
    _box_bottom()


def verify_connectivity() -> None:
    _box_row()
    ipv4 = get_server_ip("4")
    ipv6 = get_server_ip("6")

    if ipv4:
        r = _run(["curl", "-s", "-4", "-m", "5", "https://api4.ipify.org"],
                 check=False, quiet=True)
        if r.returncode == 0:
            _box_ok(f"IPv4: рабочий ({ipv4})")
        else:
            _box_warn("IPv4: проблемы с соединением")
    else:
        _box_warn("IPv4: адрес не определён")

    if IS_IPV6_AVAILABLE and ipv6:
        r = _run(["curl", "-s", "-6", "-m", "5", "https://api64.ipify.org"],
                 check=False, quiet=True)
        if r.returncode == 0:
            _box_ok(f"IPv6: рабочий ({ipv6})")
        else:
            _box_info(f"{BOLD}IPv6: проблемы с соединением{NC}")
    else:
        _box_info(f"{BOLD}IPv6: не доступен{NC}")

    # Проверяем только SSH-порт (22) — Xray/Nginx проверяются отдельно
    r = _run(["ss", "-tlnp"], capture=True, check=False)
    if ":22 " in r.stdout:
        _box_ok("Порт 22 (SSH): OK")
    else:
        _box_warn("Порт 22 (SSH): не слушает")
    _box_row()

# =============================================================================
#  ИНТЕРАКТИВНЫЙ ЗАПРОС ПАРАМЕТРОВ
# =============================================================================
# =============================================================================
#  ВЫБОР РЕЖИМА УСТАНОВКИ (A / B)
# =============================================================================
# =============================================================================
#  ВЫБОР РЕЖИМА EXIT-НОДЫ ДЛЯ РЕЖИМА B: VLESS или AWG
# =============================================================================
# Глобальные параметры SSH-аутентификации для удалённой настройки AWG.
# Заполняются в prompt_awg_exit_mode(), потребляются awg_setup_remote_server().
AWG_SSH_AUTH_METHOD: str = "key"    # "key" | "password"
AWG_SSH_PASSWORD:    str = ""       # хранится только до конца сессии настройки


# =============================================================================
#  ГЕНЕРАЦИЯ КОНФИГА XRAY ДЛЯ РЕЖИМА B — российский (entry) VPS
# =============================================================================
# =============================================================================
#  ГЕНЕРАЦИЯ КОНФИГА XRAY ДЛЯ РЕЖИМА B — зарубежный (exit) VPS
# =============================================================================
# =============================================================================
#  МУЛЬТИ-КАСКАД: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (до 10 exit-нод)
# =============================================================================

# =============================================================================
#  ГЕНЕРАЦИЯ ИТОГОВЫХ ФАЙЛОВ ДЛЯ РЕЖИМА B
# =============================================================================
# =============================================================================
#  ШАГ 1: ЗАВИСИМОСТИ
# =============================================================================
# =============================================================================
#  ШАГ 1.5: УСТАНОВКА DNSCRYPT-PROXY
# =============================================================================
def _get_dnscrypt_port() -> int:
    """Надёжное определение реального порта DNSCrypt-proxy"""
    if not DNSCRYPT_CONF.exists():
        return DNSCRYPT_LISTEN_PORT
    try:
        content = DNSCRYPT_CONF.read_text()
        m = re.search(r'listen_addresses\s*=\s*\[\s*[\'"][^:]+:(\d+)', content, re.IGNORECASE)
        if m:
            port = int(m.group(1))
            if 1024 <= port <= 65535:
                return port
    except Exception:
        pass
    return DNSCRYPT_LISTEN_PORT

def install_dnscrypt(force: bool = False) -> None:
    global DNSCRYPT_INSTALLED, DNSCRYPT_LISTEN_PORT

    if not force and not PARAM_USE_DNSCRYPT:
        info("DNSCrypt-proxy: пропускаем по выбору пользователя")
        DNSCRYPT_INSTALLED = False
        return

    info("Установка DNSCrypt-proxy...")
    PROGRESS.update(2, "DNSCrypt")

    arch = _run(["uname", "-m"], capture=True, check=False).stdout.strip()
    arch_map = {
        "x86_64": "linux_x86_64", "aarch64": "linux_arm64",
        "armv7l": "linux_arm",    "i386": "linux_386", "i686": "linux_386",
    }
    dc_arch = arch_map.get(arch)
    if not dc_arch:
        warn(f"Неподдерживаемая архитектура для DNSCrypt: {arch} — пропускаем")
        return

    r_active = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                    capture=True, check=False)
    if r_active.stdout.strip() == "active" and DNSCRYPT_BIN.exists():
        info("DNSCrypt-proxy уже установлен и запущен — пропускаем")
        DNSCRYPT_INSTALLED = True
        PROGRESS.update(3, "DNSCrypt")
        return

    dc_tag = ""
    for attempt in range(1, 4):
        try:
            r = _run(["curl", "-fsSL", "--connect-timeout", "10",
                      "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"],
                     capture=True, check=False)
            data = json.loads(r.stdout)
            dc_tag = data.get("tag_name", "")
            if dc_tag:
                break
        except Exception:
            pass
        warn(f"Попытка {attempt}: не удалось получить тег DNSCrypt, повтор...")
        time.sleep(3)

    if not dc_tag:
        warn("Не удалось получить версию DNSCrypt-proxy — пропускаем")
        warn("Xray будет использовать публичные DNS (1.1.1.1 / 8.8.8.8)")
        return

    info(f"DNSCrypt-proxy: {dc_tag} ({dc_arch})")
    dc_url = (f"https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/"
              f"{dc_tag}/dnscrypt-proxy-{dc_arch}-{dc_tag}.tar.gz")

    with tempfile.TemporaryDirectory(prefix="dnscrypt.") as dc_tmp:
        dc_archive = Path(dc_tmp) / "dnscrypt.tar.gz"
        r = _run(["curl", "-fsSL", "--connect-timeout", "30", "--retry", "3",
                  dc_url, "-o", str(dc_archive)], check=False, quiet=True)
        if r.returncode != 0:
            warn("Не удалось скачать DNSCrypt-proxy — пропускаем")
            return

        _run(["tar", "-xzf", str(dc_archive), "-C", dc_tmp],
             check=False, quiet=True)

        bin_found: Path | None = None
        for p in Path(dc_tmp).rglob("dnscrypt-proxy"):
            if p.is_file():
                bin_found = p
                break

        if not bin_found:
            warn("Бинарник dnscrypt-proxy не найден в архиве — пропускаем")
            return

        shutil.copy2(bin_found, DNSCRYPT_BIN)
        DNSCRYPT_BIN.chmod(0o755)

    success(f"Бинарник DNSCrypt-proxy установлен: {DNSCRYPT_BIN}")
    DNSCRYPT_CONF_DIR.mkdir(parents=True, exist_ok=True)

    _dnscrypt_server_names = (
        'server_names = ["cloudflare", "cloudflare-ipv6", "google", "google-ipv6"]'
        if IS_IPV6_AVAILABLE else
        'server_names = ["cloudflare", "google"]'
    )
    DNSCRYPT_CONF.write_text(textwrap.dedent(f"""\
        ## dnscrypt-proxy.toml — сгенерирован VLESS Ultimate Installer v4.12.10
        ## Слушает на {DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}

        listen_addresses = ['{DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}']

        max_clients = 250

        ipv4_servers = true
        ipv6_servers = {'true' if IS_IPV6_AVAILABLE else 'false'}
        dnscrypt_servers = true
        doh_servers = true
        odoh_servers = false

        require_dnssec = false
        require_nolog = true
        require_nofilter = false

        force_tcp = false
        ## Фиксируем быстрые резолверы. Для смены: Сеть → DNSCrypt → Выбор резолверов.
        {_dnscrypt_server_names}
        lb_strategy = 'p2'
        lb_estimator = true
        timeout = 5000
        keepalive = 30

        log_level = 1
        use_syslog = true

        cert_refresh_delay = 240

        bootstrap_resolvers = ['1.1.1.1:53', '8.8.8.8:53']
        ignore_system_dns = true

        fallback_resolvers = ['1.1.1.1:53', '8.8.8.8:53']

        netprobe_timeout = 5
        netprobe_address = '1.1.1.1:53'

        offline_mode = false
        reject_ttl = 10

        cache = true
        cache_size = 32768
        cache_min_ttl = 300
        cache_max_ttl = 86400
        cache_neg_min_ttl = 60
        cache_neg_max_ttl = 600

        [blocked_names]
          blocked_names_file = '/etc/dnscrypt-proxy/blocked-names.txt'
          log_file = '/var/log/dnscrypt-proxy-blocked.log'
          log_format = 'tsv'

        [blocked_ips]
          blocked_ips_file = '/etc/dnscrypt-proxy/blocked-ips.txt'

        [sources]
          [sources.public-resolvers]
            urls = [
              'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
              'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md'
            ]
            cache_file = '/etc/dnscrypt-proxy/public-resolvers.md'
            minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
            refresh_delay = 72
            prefix = ''

          [sources.relays]
            urls = [
              'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
              'https://download.dnscrypt.info/resolvers-list/v3/relays.md'
            ]
            cache_file = '/etc/dnscrypt-proxy/relays.md'
            minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
            refresh_delay = 72
            prefix = ''
    """))

    for f in ("blocked-names.txt", "blocked-ips.txt"):
        fp = DNSCRYPT_CONF_DIR / f
        fp.touch()
        fp.chmod(0o644)
    DNSCRYPT_CONF.chmod(0o644)

    # ИСПРАВЛЕНИЕ: создаём отдельного пользователя dnscrypt.
    # При AWG iptables mangle маркирует трафик по --uid-owner.
    # Если dnscrypt-proxy работает от root (uid=0), его исходящие соединения
    # к DNS upstream-серверам (138.124.98.4:443 и т.п.) НЕ получают AWG fwmark
    # и уходят через дефолтный маршрут провайдера, где DoT/DNSCrypt блокируется.
    # Запуск от отдельного uid позволяет добавить его в AWG mark-правила.
    _run(["useradd", "-r", "-s", "/usr/sbin/nologin", "-d", "/var/lib/dnscrypt-proxy",
          "-m", "dnscrypt"], check=False, quiet=True)
    _run(["chown", "-R", "dnscrypt:dnscrypt", str(DNSCRYPT_CONF_DIR)],
         check=False, quiet=True)

    DNSCRYPT_SERVICE.write_text(textwrap.dedent("""\
        [Unit]
        Description=DNSCrypt-proxy — зашифрованный DNS-резолвер
        Documentation=https://github.com/DNSCrypt/dnscrypt-proxy
        After=network.target network-online.target
        Wants=network-online.target
        Before=xray.service nginx.service

        [Service]
        Type=simple
        NonBlocking=true
        ExecStart=/usr/local/bin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
        Restart=on-failure
        RestartSec=5s
        TimeoutStartSec=60s
        TimeoutStopSec=10s
        User=dnscrypt
        Group=dnscrypt
        AmbientCapabilities=CAP_NET_BIND_SERVICE
        CapabilityBoundingSet=CAP_NET_BIND_SERVICE
        NoNewPrivileges=yes

        [Install]
        WantedBy=multi-user.target
    """))

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "dnscrypt-proxy"], check=False, quiet=True)
    _run(["systemctl", "start",  "dnscrypt-proxy"], check=False, quiet=True)

    dc_ok = False
    for _ in range(30):
        time.sleep(1)
        r = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                 capture=True, check=False)
        if r.stdout.strip() == "active":
            dc_ok = True
            break
        r2 = _run(["systemctl", "is-failed", "dnscrypt-proxy"],
                  capture=True, check=False)
        if r2.stdout.strip() == "failed":
            warn("DNSCrypt-proxy перешёл в состояние failed")
            break

    if dc_ok:
        port_ok = False
        for _ in range(3):
            r = _run(["ss", "-ulnp"], capture=True, check=False)
            if f":{DNSCRYPT_LISTEN_PORT} " in r.stdout:
                port_ok = True
                break
            time.sleep(1)
        if port_ok:
            DNSCRYPT_INSTALLED = True
            success(f"DNSCrypt-proxy {dc_tag} запущен на "
                    f"{DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}")
        else:
            warn(f"DNSCrypt-proxy активен, но порт {DNSCRYPT_LISTEN_PORT} не слушает")
    else:
        warn("DNSCrypt-proxy не запустился — Xray будет использовать публичные DNS")
        warn("Проверьте вручную: journalctl -u dnscrypt-proxy -n 30")

    PROGRESS.update(3, "DNSCrypt")

# =============================================================================
#  ШАГ 1.6: ОПТИМИЗАЦИЯ КОНФИГА DNSCRYPT
# =============================================================================
def apply_dnscrypt_tuning() -> None:
    if not DNSCRYPT_BIN.exists():
        warn("DNSCrypt-proxy не установлен")
        return
    info("Применение оптимизированного конфига DNSCrypt-proxy...")

    if not DNSCRYPT_CONF.exists():
        warn(f"Конфиг не найден: {DNSCRYPT_CONF}")
        return

    bak = DNSCRYPT_CONF.parent / (
        DNSCRYPT_CONF.name + "." +
        datetime.now().strftime("%Y%m%d%H%M%S") + ".bak"
    )
    shutil.copy2(DNSCRYPT_CONF, bak)

    TOP_PARAMS: dict[str, str] = {
        "doh_servers":        "true",
        "force_tcp":          "false",
        "odoh_servers":       "false",
        "timeout":            "1500",
        "netprobe_timeout":   "5",
        "reject_ttl":         "10",
        "fallback_resolvers": "['1.1.1.1:53', '8.8.8.8:53']",
        "cache":              "true",
        "cache_size":         "32768",
        "cache_min_ttl":      "300",
        "lb_strategy":        "'p2'",
        "lb_estimator":       "true",
        "use_syslog":         "true",
    }

    lines = DNSCRYPT_CONF.read_text().splitlines(keepends=True)
    result: list[str] = []
    in_section = False
    applied_top: set[str] = set()

    for line in lines:
        stripped = line.strip()
        if re.match(r'^\[', stripped):
            in_section = True
        if not in_section:
            if re.match(r'^log_file\s*=', stripped):
                result.append("## log_file удалён apply_dnscrypt_tuning — используем journald\n")
                continue
            m = re.match(r'^(\w+)\s*=\s*.*$', stripped)
            if m and m.group(1) in TOP_PARAMS:
                key = m.group(1)
                indent = line[: len(line) - len(line.lstrip())]
                line = f"{indent}{key} = {TOP_PARAMS[key]}\n"
                applied_top.add(key)
        result.append(line)

    missing_top = [k for k in TOP_PARAMS if k not in applied_top]
    if missing_top:
        result.append("\n## Добавлено apply_dnscrypt_tuning\n")
        for k in missing_top:
            result.append(f"{k} = {TOP_PARAMS[k]}\n")

    DNSCRYPT_CONF.write_text("".join(result))
    success(f"Конфиг обновлён: {DNSCRYPT_CONF}")

    _run(["systemctl", "restart", "dnscrypt-proxy"], check=False, quiet=True)
    time.sleep(2)
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
    if r.stdout.strip() == "active":
        success("DNSCrypt-proxy перезапущен с оптимизированным конфигом")
        info("Активные параметры:")
        content = DNSCRYPT_CONF.read_text()
        for key in ("doh_servers", "timeout", "cache_size", "cache_min_ttl", "server_names"):
            m = re.search(rf'^{key}\s*=\s*(.+)$', content, re.MULTILINE)
            val = m.group(1).strip() if m else "?"
            dim(f"  {key} = {val}")
    else:
        warn("DNSCrypt-proxy не запустился: journalctl -u dnscrypt-proxy -n 20")

# =============================================================================
#  ШАГ 2: ФАЙРВОЛЛ
# =============================================================================
# =============================================================================
#  ШАГ 3: ОПТИМИЗАЦИЯ СЕТЕВОГО СТЕКА
# =============================================================================
def apply_network_optimizations() -> None:
    info(f"Оптимизация сетевого стека (RAM: {TOTAL_RAM}MB)...")
    PROGRESS.update(2, "Оптимизация")

    overcommit = get_adaptive_value("overcommit") or "1"
    swappiness  = get_adaptive_value("swappiness") or "10"
    conntrack   = get_adaptive_value("conntrack")  or "1048576"
    file_max    = get_adaptive_value("file_max")   or "2097152"

    # BBR detection
    try:
        kernel_ver = _run(["uname", "-r"], capture=True, check=False).stdout.strip()
        parts = kernel_ver.split(".")
        k_major = int(re.match(r'^(\d+)', parts[0]).group(1)) if parts else 4
        k_minor = int(re.match(r'^(\d+)', parts[1]).group(1)) if len(parts) > 1 else 0
    except Exception:
        k_major, k_minor = 4, 0

    bbr_available = False
    if k_major > 4 or (k_major == 4 and k_minor >= 9):
        _run(["modprobe", "tcp_bbr"], check=False, quiet=True)
        r = _run(["sysctl", "net.ipv4.tcp_available_congestion_control"],
                 capture=True, check=False)
        if "bbr" in r.stdout:
            bbr_available = True

    congestion_lines = (
        "net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq\n"
        if bbr_available else
        "net.ipv4.tcp_congestion_control = cubic\n"
    )

    sysctl_content = textwrap.dedent(f"""\
        # =============================================================
        #  Сетевые оптимизации для VLESS REALITY
        #  Адаптировано под: {TOTAL_RAM}MB RAM, {TOTAL_CPU} CPU
        # =============================================================
        {congestion_lines}net.ipv4.tcp_fastopen = 3
        net.core.rmem_max = 134217728
        net.core.wmem_max = 134217728
        net.core.rmem_default = 1048576
        net.core.wmem_default = 1048576
        net.ipv4.tcp_rmem = 4096 1048576 134217728
        net.ipv4.tcp_wmem = 4096 1048576 134217728
        net.ipv4.tcp_mem = 786432 1048576 26777216
        net.core.optmem_max = 65536
        net.ipv4.tcp_moderate_rcvbuf = 1
        net.core.netdev_budget = 600
        net.core.somaxconn = 65535
        net.ipv4.tcp_max_syn_backlog = 65535
        net.core.netdev_max_backlog = 250000
        net.netfilter.nf_conntrack_max = {conntrack}
        net.ipv4.ip_local_port_range = 1024 65535
        net.ipv4.tcp_tw_reuse = 1
        net.ipv4.tcp_max_tw_buckets = 2000000
        net.ipv4.tcp_slow_start_after_idle = 0
        net.ipv4.tcp_sack = 1
        net.ipv4.tcp_ecn = 1
        net.ipv4.tcp_mtu_probing = 1
        net.ipv4.tcp_keepalive_time = 600
        net.ipv4.tcp_keepalive_intvl = 60
        net.ipv4.tcp_keepalive_probes = 6
        net.ipv4.tcp_fin_timeout = 30
        # BUGFIX: Режим B (каскадный прокси) требует ip_forward=1 для маршрутизации.
        # Значение подставляется динамически в зависимости от режима установки.
        net.ipv4.ip_forward = {1 if INSTALL_MODE == "B" else 0}
        net.ipv6.conf.all.disable_ipv6 = 0
        net.ipv6.conf.default.disable_ipv6 = 0
        net.ipv6.conf.lo.disable_ipv6 = 0
        net.ipv6.conf.all.accept_ra = 2
        net.ipv6.conf.default.accept_ra = 2
        # BUGFIX: должен совпадать с ip_forward — иначе диагностика (--check) сообщает ошибку
        net.ipv6.conf.all.forwarding = {1 if INSTALL_MODE == "B" else 0}
        net.ipv6.conf.all.use_tempaddr = 2
        net.ipv6.conf.default.use_tempaddr = 2
        net.ipv6.conf.all.temp_prefered_lft = 86400
        net.ipv6.conf.all.temp_valid_lft = 604800
        net.ipv6.conf.all.hop_limit = 128
        net.ipv6.neigh.default.gc_thresh1 = 512
        net.ipv6.neigh.default.gc_thresh2 = 2048
        net.ipv6.neigh.default.gc_thresh3 = 4096
        net.ipv6.flowlabel_consistency = 1
        net.ipv6.flowlabel_state_ranges = 1
        net.ipv6.conf.all.accept_redirects = 0
        net.ipv6.conf.default.accept_redirects = 0
        net.ipv6.conf.all.drop_unsolicited_na = 1
        net.ipv6.conf.default.drop_unsolicited_na = 1
        net.ipv6.conf.all.accept_dad = 1
        net.ipv6.conf.default.accept_dad = 1
        net.ipv6.conf.all.accept_source_route = 0
        net.ipv6.conf.default.accept_source_route = 0
        net.ipv4.udp_mem = 786432 1048576 26214400
        net.ipv4.udp_rmem_min = 16384
        net.ipv4.udp_wmem_min = 16384
        net.ipv4.tcp_syncookies = 1
        net.ipv4.tcp_window_scaling = 1
        net.ipv4.tcp_timestamps = 1
        net.ipv4.tcp_syn_retries = 3
        net.ipv4.tcp_synack_retries = 3
        fs.file-max = {file_max}
        fs.nr_open = 2097152
        vm.overcommit_memory = {overcommit}
        vm.swappiness = {swappiness}
        vm.dirty_ratio = 15
        vm.dirty_background_ratio = 5
        kernel.numa_balancing = 1
        kernel.sched_min_granularity_ns = 10000000
        kernel.sched_wakeup_granularity_ns = 15000000
        kernel.panic = 10
        kernel.panic_on_oops = 1
    """)

    OPTIMIZER_CONF.parent.mkdir(parents=True, exist_ok=True)
    OPTIMIZER_CONF.write_text(sysctl_content)
    _run(["sysctl", "-p", str(OPTIMIZER_CONF)], check=False, quiet=True)

    LIMITS_CONF.parent.mkdir(parents=True, exist_ok=True)
    LIMITS_CONF.write_text(textwrap.dedent("""\
        * soft nofile 1048576
        * hard nofile 1048576
        * soft nproc  unlimited
        * hard nproc  unlimited
        root soft nofile 1048576
        root hard nofile 1048576
        root soft nproc  unlimited
        root hard nproc  unlimited
    """))

    SYSTEMD_CONF.parent.mkdir(parents=True, exist_ok=True)
    SYSTEMD_CONF.write_text(textwrap.dedent("""\
        [Manager]
        DefaultLimitNOFILE=1048576
        DefaultLimitNPROC=infinity
    """))
    _run(["systemctl", "daemon-reexec"], check=False, quiet=True)

    thp = Path("/sys/kernel/mm/transparent_hugepage/enabled")
    if thp.exists():
        try:
            thp.write_text("madvise")
        except Exception:
            pass

    if command_exists("irqbalance"):
        _run(["systemctl", "enable", "--now", "irqbalance"], check=False, quiet=True)
        success("irqbalance запущен")

    if bbr_available:
        r = _run(["ip", "-o", "link", "show"], capture=True, check=False)
        ifaces = [
            m.group(1) for line in r.stdout.splitlines()
            if (m := re.match(r'\d+:\s+(\S+):', line)) and m.group(1) != "lo"
        ]
        for iface in ifaces:
            _run(["tc", "qdisc", "replace", "dev", iface, "root", "fq"],
                 check=False, quiet=True)
        try:
            with open("/etc/modules-load.d/bbr.conf", "a") as f:
                f.write("tcp_bbr\n")
        except Exception:
            pass
        success("BBR активирован + fq планировщик")
    else:
        info(f"BBR недоступен на ядре {k_major}.{k_minor}, используется cubic")

    _run(["modprobe", "nf_conntrack"], check=False, quiet=True)
    hashsize = Path("/sys/module/nf_conntrack/parameters/hashsize")
    if hashsize.exists():
        try:
            hashsize.write_text("131072")
        except Exception:
            pass

    PROGRESS.update(3, "Оптимизация")
    success(f"Сетевой стек оптимизирован (адаптивно под {TOTAL_RAM}MB RAM)")

# =============================================================================
#  ШАГ 4: УСТАНОВКА XRAY + SHA256
# =============================================================================
# =============================================================================
#  ШАГ 5: ГЕНЕРАЦИЯ КЛЮЧЕЙ REALITY
# =============================================================================
# =============================================================================
# =============================================================================
# =============================================================================
#  ШАГ 8: FAIL2BAN + NGINX RATE LIMITING
# =============================================================================
# =============================================================================
#  ШАГ 9: САЙТЫ-ЗАГЛУШКИ
# =============================================================================
# =============================================================================
#  ШАГ 10: NGINX ВРЕМЕННЫЙ КОНФИГ
# =============================================================================
# =============================================================================
#  ШАГ 11: SSL СЕРТИФИКАТ
# =============================================================================
# =============================================================================
#  ШАГ 12.1: NGINX SYSTEMD OVERRIDE
# =============================================================================
# =============================================================================
#  ШАГ 13: АВТООБНОВЛЕНИЕ СЕРТИФИКАТА
# =============================================================================

# =============================================================================
#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# =============================================================================
def ensure_subscription_tokens() -> None:
    """Убедиться, что у всех существующих пользователей есть подписочный токен в state.json."""
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        sub_tokens = state.setdefault("sub_tokens", {})
        changed = False
        
        for email in state.get("users", {}):
            if email and email not in sub_tokens:
                sub_tokens[email] = gen_uuid()
                changed = True

        # NaiveProxy users
        naive_users = []
        np_state_file = Path("/var/lib/xray-installer/naiveproxy.json")
        if np_state_file.exists():
            try:
                naive_users = json.loads(np_state_file.read_text(encoding="utf-8")).get("users", [])
            except Exception:
                pass
        for nu in naive_users:
            username = nu.get("username")
            if username and username not in sub_tokens:
                sub_tokens[username] = gen_uuid()
                changed = True
                
        # Mieru users
        mieru_users = []
        mieru_state_file = Path("/var/lib/xray-installer/mieru.json")
        if mieru_state_file.exists():
            try:
                mieru_users = json.loads(mieru_state_file.read_text(encoding="utf-8")).get("users", [])
            except Exception:
                pass
        for mu in mieru_users:
            username = mu.get("username")
            if username and username not in sub_tokens:
                sub_tokens[username] = gen_uuid()
                changed = True
                
        main_email = state.get("email") or "admin"
        if main_email and main_email not in sub_tokens:
            sub_tokens[main_email] = state.get("uuid") or gen_uuid()
            changed = True
            
        if changed:
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception:
        pass


def _setup_subscription_domain_ssl() -> None:
    print()
    _box_top("НАСТРОЙКА ДОМЕНА + SSL")
    _box_row(f"  {YELLOW}Внимание:{NC} Будет выполнен выпуск SSL-сертификата Let's Encrypt.")
    _box_row("  Для этого порт 80 должен быть свободен. Скрипт автоматически")
    _box_row("  остановит Caddy / Nginx на время выпуска и запустит обратно.")
    _box_bottom()
    
    new_domain = input(f"{CYAN}Введите домен для подписок (например, sub.yourdomain.com):{NC} ").strip()
    if not new_domain:
        warn("Домен не введен. Отмена.")
        time.sleep(1.5)
        return
        
    certbot_bin = next(
        (p for p in (Path("/snap/bin/certbot"), Path("/usr/bin/certbot"))
         if p.exists()), None
    )
    if not certbot_bin:
        warn("certbot не найден. Пожалуйста, установите certbot на сервере.")
        time.sleep(2)
        return

    # Останавливаем веб-серверы
    nginx_was_active = False
    caddy_was_active = False

    try:
        r = subprocess.run(["systemctl", "is-active", "nginx"], capture_output=True, text=True)
        if r.stdout.strip() == "active":
            info("Временная остановка Nginx...")
            subprocess.run(["systemctl", "stop", "nginx"], check=False)
            nginx_was_active = True
    except Exception:
        pass

    try:
        r = subprocess.run(["systemctl", "is-active", "caddy"], capture_output=True, text=True)
        if r.stdout.strip() == "active":
            info("Временная остановка Caddy...")
            subprocess.run(["systemctl", "stop", "caddy"], check=False)
            caddy_was_active = True
    except Exception:
        pass

    info(f"Запуск certbot для домена {new_domain}...")
    try:
        r = subprocess.run([
            str(certbot_bin), "certonly", "--standalone",
            "-d", new_domain,
            "--non-interactive", "--agree-tos",
            "-m", f"admin@{new_domain}",
            "--keep-until-expiring"
        ], capture_output=True, text=True)
        certbot_ok = (r.returncode == 0)
    except Exception as e:
        certbot_ok = False
        warn(f"Ошибка вызова certbot: {e}")

    # Запускаем веб-серверы обратно
    if nginx_was_active:
        info("Запуск Nginx...")
        subprocess.run(["systemctl", "start", "nginx"], check=False)
    if caddy_was_active:
        info("Запуск Caddy...")
        subprocess.run(["systemctl", "start", "caddy"], check=False)

    if certbot_ok:
        # Проверяем файлы
        cert_file = Path(f"/etc/letsencrypt/live/{new_domain}/fullchain.pem")
        key_file = Path(f"/etc/letsencrypt/live/{new_domain}/privkey.pem")
        if cert_file.exists() and key_file.exists():
            state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
            state["sub_domain"] = new_domain
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
            success(f"SSL-сертификат успешно получен для домена {new_domain}!")
            
            # Переустанавливаем сервис подписок, чтобы обновить домен и порт
            sub_port = state.get("sub_port", 9443)
            info("Перезапуск службы подписок с новым SSL-сертификатом...")
            from vless_installer.modules.sub_server import install_sub_service
            install_sub_service("0.0.0.0", sub_port)
            try:
                from vless_installer.modules.naiveproxy import sync_caddy_config
                sync_caddy_config()
            except Exception:
                pass
        else:
            warn("Certbot сообщил об успехе, но файлы сертификата не найдены по стандартному пути.")
    else:
        err_msg = r.stderr or r.stdout or "Неизвестная ошибка"
        warn(f"Не удалось получить SSL-сертификат:\n{err_msg}")

    time.sleep(3.5)


def _add_subscription_user() -> None:
    print()
    _box_top("ДОБАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ПОДПИСОК")
    _box_row()
    _box_bottom()
    
    while True:
        new_email = input(f"{CYAN}Введите имя/email нового пользователя:{NC} ").strip()
        if not new_email:
            warn("Имя не может быть пустым")
            continue
        if ' ' in new_email:
            warn("Имя не должно содержать пробелов")
            continue
            
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
        sub_tokens = state.setdefault("sub_tokens", {})
        if new_email in sub_tokens:
            warn(f"Пользователь '{new_email}' уже зарегистрирован в подписках")
            continue
        break
        
    try:
        from vless_installer.modules.user_lifecycle import sync_user_lifecycle
        sync_user_lifecycle(new_email, "add")
        success(f"Пользователь '{new_email}' успешно добавлен в систему подписок и все VPN-службы.")
    except Exception as e:
        warn(f"Ошибка при добавлении пользователя: {e}")
        
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    users_db = state.get("users", {})
    token = users_db.get(new_email, {}).get("token", "")
    
    # Сразу показываем ссылки
    sub_domain = state.get("sub_domain", "")
    domain = sub_domain or state.get("domain", "") or get_server_ip("4")
    port_suffix = ""
    base_url = f"https://{domain}{port_suffix}/sub/{token}"
    
    print()
    _box_top(f"ССЫЛКИ ДЛЯ {new_email}")
    _box_row(f"  {BOLD}Токен:{NC} {token}")
    _box_sep()
    _box_row(f"  {CYAN}Base64:{NC} {base_url}")
    _box_bottom()
    
    input(f"\n{BLUE}Нажмите Enter для продолжения...{NC}")


def _delete_subscription_user() -> None:
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    sub_tokens = state.get("sub_tokens", {})
    if not sub_tokens:
        warn("Нет зарегистрированных пользователей подписок")
        time.sleep(1.5)
        return
        
    print()
    _box_top("УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ПОДПИСОК")
    users_list = list(sub_tokens.keys())
    for idx, name in enumerate(users_list, 1):
        _box_row(f"  [{idx}] {name}")
    _box_bottom()
    
    choice = input(f"{CYAN}Выберите номер или введите email для удаления:{NC} ").strip()
    if not choice:
        warn("Отменено")
        return
        
    target = None
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(users_list):
            target = users_list[idx]
    if not target:
        if choice in sub_tokens:
            target = choice
            
    if not target:
        warn(f"Пользователь '{choice}' не найден")
        time.sleep(1.5)
        return
        
    ans = input(f"{YELLOW}Вы уверены, что хотите удалить пользователя {target}? [y/N]:{NC} ").strip().lower()
    if ans == "y":
        try:
            from vless_installer.modules.user_lifecycle import sync_user_lifecycle
            sync_user_lifecycle(target, "delete")
            success(f"Пользователь '{target}' удален из системы подписок и всех VPN-служб")
        except Exception as e:
            warn(f"Ошибка при удалении пользователя: {e}")
    else:
        info("Отменено")
    time.sleep(1.5)


def _change_subscription_port() -> None:
    try:
        new_port_str = input(f"{CYAN}Введите новый порт сервера подписок (1-65535, по умолчанию 9443):{NC} ").strip()
        new_port = int(new_port_str) if new_port_str else 9443
        if not (1 <= new_port <= 65535):
            raise ValueError
        
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
        state["sub_port"] = new_port
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        success(f"Порт изменен на {new_port}")
        
        # Проверяем, активен ли сервис подписок
        sub_svc_active = False
        try:
            r = subprocess.run(["systemctl", "is-active", "vless-sub"], capture_output=True, text=True)
            sub_svc_active = (r.stdout.strip() == "active")
        except Exception:
            pass

        if sub_svc_active:
            info("Перезапуск службы с новым портом...")
            from vless_installer.modules.sub_server import install_sub_service
            install_sub_service("0.0.0.0", new_port)
            try:
                from vless_installer.modules.naiveproxy import sync_caddy_config
                sync_caddy_config()
            except Exception:
                pass
    except ValueError:
        warn("Некорректный порт")
    except Exception as e:
        warn(f"Ошибка изменения porta: {e}")
    time.sleep(2)


def do_update_all_user_configs() -> None:
    """Проверяет пользователей подписок и создает конфигурации в NaiveProxy, Mieru и AmneziaWG."""
    print()
    _box_top("СИНХРОНИЗАЦИЯ И ОБНОВЛЕНИЕ КОНФИГУРАЦИЙ")
    _box_row()
    
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    sub_tokens = state.get("sub_tokens", {})
    if not sub_tokens:
        _box_warn("Нет зарегистрированных пользователей подписок.")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    # Проверяем, какие протоколы установлены в принципе
    np_installed = False
    try:
        from vless_installer.modules.naiveproxy import _is_installed as np_is_installed
        np_installed = np_is_installed()
    except Exception:
        pass
        
    mieru_installed = False
    try:
        from vless_installer.modules.mieru import _is_installed as mieru_is_installed
        mieru_installed = mieru_is_installed()
    except Exception:
        pass

    awg_installed = False
    try:
        from vless_installer.modules.amnezia_vpn import _container_exists as awg_exists
        awg_installed = awg_exists()
    except Exception:
        pass

    _box_info("Статус установленных протоколов на сервере:")
    _box_row(f"  NaiveProxy: {'🟢 установлен' if np_installed else '🔴 не установлен'}")
    _box_row(f"  Mieru:      {'🟢 установлен' if mieru_installed else '🔴 не установлен'}")
    _box_row(f"  AmneziaWG:  {'🟢 установлен' if awg_installed else '🔴 не установлен'}")
    _box_sep()

    changes_made = 0
    
    for email in sub_tokens.keys():
        _box_info(f"Проверка пользователя {email}:")
        
        # 1. NaiveProxy
        if np_installed:
            try:
                from vless_installer.modules.naiveproxy import add_user_noninteractive as np_add
                res = np_add(email)
                if res:
                    _box_ok(f"  NaiveProxy: создан новый аккаунт")
                    changes_made += 1
                else:
                    _box_row(f"  NaiveProxy: уже существует")
            except Exception as e:
                _box_warn(f"  NaiveProxy: ошибка создания: {e}")
        else:
            _box_row("  NaiveProxy: пропущено (протокол не установлен)")

        # 2. Mieru
        if mieru_installed:
            try:
                from vless_installer.modules.mieru import add_user_noninteractive as mieru_add
                res = mieru_add(email)
                if res:
                    _box_ok(f"  Mieru: создан новый аккаунт")
                    changes_made += 1
                else:
                    _box_row(f"  Mieru: уже существует")
            except Exception as e:
                _box_warn(f"  Mieru: ошибка создания: {e}")
        else:
            _box_row("  Mieru: пропущено (протокол не установлен)")

        # 3. AmneziaWG
        if awg_installed:
            try:
                from vless_installer.modules.amnezia_vpn import ensure_awg_user
                username_clean = re.sub(r'[^a-zA-Z0-9_-]', '', email)
                if not username_clean:
                    _box_warn(f"  AmneziaWG: имя пользователя '{email}' недопустимо для AWG")
                else:
                    created, msg = ensure_awg_user(username_clean)
                    if created:
                        _box_ok(f"  AmneziaWG: создан новый аккаунт")
                        changes_made += 1
                    else:
                        if "уже существует" in msg:
                            _box_row(f"  AmneziaWG: уже существует")
                        else:
                            _box_warn(f"  AmneziaWG: {msg}")
            except Exception as e:
                _box_warn(f"  AmneziaWG: ошибка создания: {e}")
        else:
            _box_row("  AmneziaWG: пропущено (протокол не установлен)")
        _box_sep()

    if changes_made > 0:
        success("Все отсутствующие конфигурации успешно созданы!")
    else:
        info("Все конфигурации пользователей уже актуальны, изменений не требуется.")
        
    _box_bottom()
    input(f"\n{BLUE}Нажмите Enter для продолжения...{NC}")


def do_subscription_menu() -> None:
    """Интерактивное меню для управления подписками пользователей."""
    ensure_subscription_tokens()

    while True:
        os.system("clear")
        
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
        users_db = state.get("users", {})
        _ttl_expiring = sum(
            1 for r in users_db.values()
            if r.get("expires_at")
            and _ttl_expires_within_hours(r.get("expires_at"), 24)
            and not _ttl_is_expired(r.get("expires_at"))
        )
        _ttl_badge = (
            f"  {YELLOW}⚠ {_ttl_expiring} истекают < 24ч{NC}" if _ttl_expiring else ""
        )

        _box_top("📋 УПРАВЛЕНИЕ ПОДПИСКАМИ")
        _box_row(f"  {DIM}Управление системой подписок пользователей{NC}")
        _box_sep()

        sub_svc_active = False
        try:
            r = subprocess.run(["systemctl", "is-active", "vless-sub"], capture_output=True, text=True)
            sub_svc_active = (r.stdout.strip() == "active")
        except Exception:
            pass

        sub_domain = state.get("sub_domain", "")
        sub_port = state.get("sub_port", 9443)
        domain = sub_domain or state.get("domain", "") or get_server_ip("4")

        # Проверка SSL-сертификата
        ssl_status = f"{YELLOW}не найден{NC}"
        if sub_domain:
            cert_file = Path(f"/etc/letsencrypt/live/{sub_domain}/fullchain.pem")
            key_file = Path(f"/etc/letsencrypt/live/{sub_domain}/privkey.pem")
            if cert_file.exists() and key_file.exists():
                ssl_status = f"{GREEN}активен (OK){NC}"
            else:
                ssl_status = f"{RED}ошибка (сертификаты не найдены){NC}"

        svc_status = f"{GREEN}активен{NC}" if sub_svc_active else f"{YELLOW}не активен{NC}"
        port_suffix = ""

        _box_row(f"  Сервис подписок:  {svc_status}")
        _box_row(f"  Домен подписок:   {sub_domain if sub_domain else f'{YELLOW}не настроен{NC}'}")
        _box_row(f"  Порт подписок:    {sub_port}")
        _box_row(f"  SSL-сертификат:   {ssl_status}")
        if sub_domain:
            _box_row(f"  Внешний URL:      https://{domain}{port_suffix}/sub/<токен>")
        else:
            _box_row(f"  Внешний URL:      (необходима настройка домена)")
            
        _box_sep()

        _box_item("1", "⚙️ Настроить сервис подписок (Домен + SSL)")
        _box_item("2", f"{'Выключить' if sub_svc_active else 'Включить'} сервис подписок")
        _box_sep()
        _box_item("3", "👤 Добавить пользователя подписок")
        _box_item("4", "❌ Удалить пользователя подписок")
        _box_item("5", "🔗 Получить ссылки подписок для пользователя")
        _box_item("6", "🔄 Перегенерировать токен пользователя")
        _box_item("7", f"🔌 Изменить порт подписок {DIM}(текущий: {sub_port}){NC}")
        _box_item("8", "📊 Лимиты трафика на пользователя")
        _box_item(
            "9",
            f"⏱  Временные пользователи (TTL)"
            f"  {DIM}({sum(1 for u in users_db.values() if u.get('expires_at'))} записей){NC}{_ttl_badge}"
        )
        _box_item("10", "🔄 Синхронизировать и обновить все конфигурации")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break

        if ch in ("0", "q", "Q", ""):
            break

        elif ch == "1":
            _setup_subscription_domain_ssl()

        elif ch == "2":
            if sub_svc_active:
                info("Отключение службы подписок...")
                try:
                    from vless_installer.modules.sub_server import uninstall_sub_service
                    uninstall_sub_service()
                    try:
                        from vless_installer.modules.naiveproxy import sync_caddy_config
                        sync_caddy_config()
                    except Exception:
                        pass
                    uninstall_sync_agent()
                    success("Служба подписок отключена")
                except Exception as e:
                    warn(f"Ошибка отключения: {e}")
            else:
                info("Включение службы подписок...")
                try:
                    from vless_installer.modules.sub_server import install_sub_service
                    install_sub_service("0.0.0.0", sub_port)
                    try:
                        from vless_installer.modules.naiveproxy import sync_caddy_config
                        sync_caddy_config()
                    except Exception:
                        pass
                    install_sync_agent()
                    success("Служба подписок включена")
                except Exception as e:
                    warn(f"Ошибка включения: {e}")
            time.sleep(2)

        elif ch == "3":
            _add_subscription_user()

        elif ch == "4":
            _delete_subscription_user()

        elif ch == "5":
            _show_user_subscription_links()

        elif ch == "6":
            _regenerate_user_token()

        elif ch == "7":
            _change_subscription_port()

        elif ch == "8":
            do_manage_traffic_limits()

        elif ch == "9":
            do_manage_ttl_users()

        elif ch == "10":
            do_update_all_user_configs()

        elif ch in ("a", "A"):
            _ensure_awg_for_user()


def _ensure_awg_for_user() -> None:
    """Добавляет AWG-пользователя из подписочного списка если ещё нет."""
    users = _get_all_sub_users()
    if not users:
        warn("Пользователи не найдены")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    os.system("clear")
    _box_top("🛱  HYDRA → AmneziaWG: Добавить AWG-пользователя")
    _box_row(f"  {DIM}Пользователь будет добавлен в AmneziaWG через Docker если ещё не существует{NC}")
    _box_sep()
    for i, u in enumerate(users, 1):
        _box_item(f"{i}", u.get("email", "?"))
    _box_item_exit("0", "← Отмена")
    _box_bottom()

    raw = input(f"{CYAN}Номер (Enter = все сразу):{NC} ").strip()
    if raw in ("0", "q", "Q"):
        return

    targets = []
    if raw == "":
        # Всем подряд
        targets = [u["email"] for u in users]
    elif raw.isdigit() and 1 <= int(raw) <= len(users):
        targets = [users[int(raw) - 1]["email"]]
    else:
        targets = [raw]

    try:
        from vless_installer.modules.amnezia_vpn import ensure_awg_user
    except ImportError as e:
        warn(f"Не удалось загрузить модуль amnezia_vpn: {e}")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    print()
    created = 0
    for email in targets:
        username = email.split("@")[0] if "@" in email else email
        ok, msg = ensure_awg_user(username)
        if ok:
            success(f"✅ {email}: {msg}")
            created += 1
        else:
            info(f"ℹ️  {email}: {msg}")

    print()
    if created:
        success(f"Создано AWG-пользователей: {created}")
    else:
        info("Все пользователи уже имеют AWG-профиль")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _get_all_sub_users() -> list[dict]:
    """Возвращает список пользователей HYDRA из state, NaiveProxy и Mieru."""
    users = []
    seen = set()

    # Из state.json
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            
            # NaiveProxy users
            naive_users = []
            np_state_file = Path("/var/lib/xray-installer/naiveproxy.json")
            if np_state_file.exists():
                try:
                    naive_users = json.loads(np_state_file.read_text(encoding="utf-8")).get("users", [])
                except Exception:
                    pass
            for nu in naive_users:
                username = nu.get("username")
                if username and username not in seen:
                    users.append({"email": username, "id": "NaiveProxy User", "source": "NaiveProxy"})
                    seen.add(username)
                    
            # Mieru users
            mieru_users = []
            mieru_state_file = Path("/var/lib/xray-installer/mieru.json")
            if mieru_state_file.exists():
                try:
                    mieru_users = json.loads(mieru_state_file.read_text(encoding="utf-8")).get("users", [])
                except Exception:
                    pass
            for mu in mieru_users:
                username = mu.get("username")
                if username and username not in seen:
                    users.append({"email": username, "id": "Mieru User", "source": "Mieru"})
                    seen.add(username)
                    
            # Из существующих токенов подписок
            sub_tokens = state.get("sub_tokens", {})
            for email in sub_tokens.keys():
                if email and email not in seen:
                    users.append({"email": email, "id": "Token only", "source": "Subscription"})
                    seen.add(email)
        except Exception:
            pass
            
    return users


def _show_user_subscription_links() -> None:
    users = _get_all_sub_users()
    _box_top("СПИСОК ПОЛЬЗОВАТЕЛЕЙ ПОДПИСОК")
    if not users:
        _box_row(f"  {DIM}Пользователи не найдены.{NC}")
        _box_bottom()
        time.sleep(1.5)
        return
    else:
        _box_row(f"  {'N':<4} {'Email/имя':<30} {'Идентификатор/Тип':<30} {'Источник':<20}")
        _box_bottom()
        print("  " + "─" * 90)
        for i, u in enumerate(users, 1):
            print(f"  {i:<4} {u['email']:<30} {u['id']:<30} {u['source']:<20}")
            
    print()
    target = input(f"{CYAN}Email пользователя (или порядковый номер):{NC} ").strip()
    if not target:
        warn("Отмена")
        return

    found = None
    if target.isdigit():
        idx = int(target) - 1
        if 0 <= idx < len(users):
            found = users[idx]
    if not found:
        found = next((u for u in users if u["email"] == target or u["id"] == target), None)

    if not found:
        warn(f"Пользователь '{target}' не найден")
        time.sleep(1.5)
        return

    email = found["email"]
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    sub_tokens = state.setdefault("sub_tokens", {})
    token = sub_tokens.get(email)

    if not token:
        token = gen_uuid()
        sub_tokens[email] = token
        state["sub_tokens"] = sub_tokens
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))

    sub_domain = state.get("sub_domain", "")
    sub_port = state.get("sub_port", 9443)
    domain = sub_domain or state.get("domain", "") or get_server_ip("4")
    port_suffix = ""
    base_url = f"https://{domain}{port_suffix}/sub/{token}"

    while True:
        os.system("clear")
        _box_top(f"ПОДПИСКИ ПОЛЬЗОВАТЕЛЯ {email}")
        _box_row(f"  {BOLD}Токен:{NC} {token}")
        _box_sep()
        _box_row("  Вставьте эту ссылку в клиент (v2rayNG, Hiddify, Nekobox):")
        _box_row()
        _box_row(f"  {CYAN}Base64 подписка (мобильная){NC} (v2rayNG, Shadowrocket, Hiddify):")
        _box_link(base_url)
        _box_row()
        _box_row(f"  {CYAN}PC подписка (для NekoBox PC / NyameBox){NC}:")
        _box_link(f"{base_url}/pc")
        _box_sep()
        _box_item("1", "📱 Показать QR-код для мобильной подписки")
        _box_item("2", "💻 Показать QR-код для ПК подписки")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            choice = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if choice in ("0", ""):
            break
        elif choice == "1":
            _show_qr(base_url, f"{email} Base64 Sub", f"/root/sub_base64_qr_{email}.png")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif choice == "2":
            _show_qr(f"{base_url}/pc", f"{email} PC Sub", f"/root/sub_pc_qr_{email}.png")
            input(f"{BLUE}Нажмите Enter...{NC}")


def _regenerate_user_token() -> None:
    users = _get_all_sub_users()
    _box_top("СПИСОК ПОЛЬЗОВАТЕЛЕЙ ПОДПИСОК")
    if not users:
        _box_row(f"  {DIM}Пользователи не найдены.{NC}")
        _box_bottom()
        time.sleep(1.5)
        return
    else:
        _box_row(f"  {'N':<4} {'Email/имя':<30} {'Идентификатор/Тип':<30} {'Источник':<20}")
        _box_bottom()
        print("  " + "─" * 90)
        for i, u in enumerate(users, 1):
            print(f"  {i:<4} {u['email']:<30} {u['id']:<30} {u['source']:<20}")
            
    print()
    target = input(f"{CYAN}Email пользователя для сброса токена (или номер):{NC} ").strip()
    if not target:
        warn("Отмена")
        return

    found = None
    if target.isdigit():
        idx = int(target) - 1
        if 0 <= idx < len(users):
            found = users[idx]
    if not found:
        found = next((u for u in users if u["email"] == target or u["id"] == target), None)

    if not found:
        warn(f"Пользователь '{target}' не найден")
        time.sleep(1.5)
        return

    email = found["email"]
    ans = input(f"{YELLOW}Вы уверены, что хотите перегенерировать токен для {email}? Старая ссылка перестанет работать! [y/N]:{NC} ").strip().lower()
    if ans == "y":
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
        sub_tokens = state.setdefault("sub_tokens", {})
        new_token = gen_uuid()
        sub_tokens[email] = new_token
        state["sub_tokens"] = sub_tokens
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        success(f"Токен для {email} успешно обновлен")
    else:
        info("Отменено")
    time.sleep(2)

# =============================================================================
#  ГЕНЕРАЦИЯ ССЫЛОК + QR
# =============================================================================
def _show_qr(link: str, label: str, png_path: str) -> None:
    """Выводит QR-код внутри рамки бокса."""
    print()
    _box_top(f"QR-код [{label}]")
    _box_row(f"  {CYAN}Отсканируйте в v2rayNG / Hiddify / Nekobox:{NC}")
    _box_sep()

    qrencode = shutil.which("qrencode")
    if qrencode:
        # Выводим QR в терминал — каждая строка через _box_row
        import subprocess as _sp
        # ГОЛУБОЙ QR: используем ANSI256 foreground (цвет модулей) через
        # --foreground / --background если qrencode >= 4.1, иначе оборачиваем
        # строки вывода в ANSI-escape для голубого цвета.
        _QR_COLOR = "\033[96m"   # bright cyan (ANSI 96)
        _QR_RESET = "\033[0m"
        try:
            _qr_proc = _sp.run(
                [qrencode, "-t", "ANSIUTF8", "-m", "1",
                 "--foreground=00BFFF", "--background=000000",
                 "--strict-version", link],
                capture_output=True, text=True
            )
            _qr_lines = _qr_proc.stdout.splitlines()
        except Exception:
            _qr_lines = []
        if not _qr_lines:
            # fallback: пробуем без --foreground (старые версии qrencode)
            try:
                _qr_proc = _sp.run(
                    [qrencode, "-t", "ANSIUTF8", "-m", "1", link],
                    capture_output=True, text=True
                )
                _qr_lines = _qr_proc.stdout.splitlines()
            except Exception:
                _qr_lines = []
        for _ql in _qr_lines:
            # Вставляем QR-строку внутрь рамки с отступом.
            # Если qrencode не поддержал --foreground, оборачиваем в CYAN escape.
            if _QR_COLOR not in _ql and "\033[" not in _ql:
                _box_row(f"  {_QR_COLOR}{_ql}{_QR_RESET}")
            else:
                _box_row(f"  {_ql}")
        # Сохраняем PNG
        r = _run([qrencode, "-t", "PNG", "-o", png_path, "-s", "8", "-m", "4", link],
                 check=False, quiet=True)
        _box_sep()
        if r.returncode == 0:
            _box_ok(f"QR PNG сохранён: {png_path}")
        else:
            _box_warn(f"Не удалось сохранить QR PNG: {png_path}")
    else:
        # Fallback: python3-qrcode
        try:
            import qrcode  # type: ignore
            import io as _io
            qr = qrcode.QRCode(border=1)
            qr.add_data(link)
            qr.make(fit=True)
            # Захватываем ASCII-вывод
            _buf = _io.StringIO()
            import sys as _sys
            _old_stdout = _sys.stdout
            _sys.stdout = _buf
            qr.print_ascii(invert=True)
            _sys.stdout = _old_stdout
            _QR_COLOR = "\033[96m"
            _QR_RESET = "\033[0m"
            for _ql in _buf.getvalue().splitlines():
                _box_row(f"  {_QR_COLOR}{_ql}{_QR_RESET}")
            img = qr.make_image(fill_color='#00BFFF', back_color='black')
            img.save(png_path)
            _box_sep()
            _box_ok(f"QR PNG сохранён: {png_path}")
        except ImportError:
            _box_warn("python3-qrcode не установлен: pip3 install qrcode[pil]")
        except Exception as e:
            _box_warn(f"Ошибка QR: {e}")

    _box_bottom()


# =============================================================================
#  УДАЛЕНИЕ
# =============================================================================
def do_uninstall() -> None:
    """Полное удаление HYDRA-стека (делегирует hydra_setup)."""
    from vless_installer.modules.hydra_setup import do_hydra_uninstall
    do_hydra_uninstall()


# =============================================================================
#  РАЗДЕЛЬНОЕ ТУННЕЛИРОВАНИЕ — ФУНКЦИИ
# =============================================================================

# =============================================================================
#  ПОЛНАЯ УСТАНОВКА
# =============================================================================
def _wait_service_active(svc: str, max_sec: int = 30, silent: bool = False) -> bool:
    """Ждёт активации сервиса. silent=True подавляет прямой вывод (для вызовов внутри рамки)."""
    for i in range(1, max_sec + 1):
        r = _run(["systemctl", "is-active", svc], capture=True, check=False)
        if r.stdout.strip() == "active":
            if not silent:
                success(f"  ✓ {svc} активен ({i}с)")
            log_to_file("SUCCESS", f"{svc} активен ({i}с)")
            return True
        r2 = _run(["systemctl", "is-failed", svc], capture=True, check=False)
        if r2.stdout.strip() == "failed":
            if not silent:
                warn(f"  ✗ {svc} перешёл в failed")
            log_to_file("WARN", f"{svc} перешёл в failed")
            try:
                logs = _run(["journalctl", "-u", svc, "-n", "15", "--no-pager"],
                            capture=True, check=False).stdout
                log_to_file("WARN", logs[-2000:])
            except Exception:
                pass
            return False
        time.sleep(1)
    if not silent:
        warn(f"  ✗ {svc} не запустился за {max_sec}с")
    log_to_file("WARN", f"{svc} не запустился за {max_sec}с")
    return False



# =============================================================================
#  AWG 2.0 (AmneziaWG) — ПОЛНАЯ УСТАНОВКА И НАСТРОЙКА
# =============================================================================

_AWG_CONF_DIR        = Path("/etc/amnezia/amneziawg")
_AWG_SERVER_CONF     = _AWG_CONF_DIR / "awg0.conf"          # серверный конфиг (для exit-VPS)
_AWG_CLIENT_CONF     = _AWG_CONF_DIR / "awg0-client.conf"   # клиентский конфиг (RU-VPS)
_AWG_ACTIVE_CONF     = _AWG_CONF_DIR / "awg0.conf"          # используется awg-quick на RU
_AWG_REMOTE_CONF_PATH = "/etc/amnezia/amneziawg/awg0.conf"


# =============================================================================
#  DRY-RUN РЕЖИМ УСТАНОВКИ
#  Показывает план всех изменений без реального выполнения.
# =============================================================================

# =============================================================================
#  MTU/MSS АВТОТЮНИНГ
#  Определяет оптимальный MTU до каждой exit-ноды через path MTU discovery
#  и применяет ограничение MSS в iptables/nftables.
# =============================================================================

_MTU_STATE_FILE = Path("/var/lib/xray-installer/mtu_tuning.json")


def _mtu_probe(host: str, max_mtu: int = 1500, min_mtu: int = 576) -> int:
    """
    Бинарный поиск максимального MTU до хоста через ICMP ping с DF-битом.
    Возвращает найденный MTU или 0 при ошибке.
    """
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return 0

    lo, hi = min_mtu, max_mtu
    best = 0

    while lo <= hi:
        mid = (lo + hi) // 2
        # ping -M do  — не фрагментировать (DF bit)
        # -s (mid-28): payload = MTU - 20 (IP) - 8 (ICMP)
        payload = mid - 28
        if payload < 0:
            lo = mid + 1
            continue
        r = _run(
            ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), ip],
            capture=True, check=False,
        )
        if r.returncode == 0:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1

    return best


def _mtu_get_iface() -> str:
    """Возвращает основной сетевой интерфейс (не lo)."""
    r = _run(["ip", "route", "show", "default"], capture=True, check=False)
    for line in r.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return "eth0"


def _mtu_apply(iface: str, mtu: int, nodes: list) -> None:
    """
    Применяет MTU на интерфейс и ограничение MSS в iptables
    для каждой exit-ноды (только для трафика каскада).
    """
    # 1. Устанавливаем MTU на интерфейсе
    _run(["ip", "link", "set", iface, "mtu", str(mtu)], check=False, quiet=True)

    # 2. MSS clamping для каждой exit-ноды
    mss = mtu - 40  # TCP/IP заголовки: 20 IP + 20 TCP
    for nd in nodes:
        host = nd.get("host", "")
        port = str(nd.get("port", 443))
        if not host:
            continue
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            continue
        # Удалим старое правило если есть, потом добавим новое
        _run([
            "iptables", "-t", "mangle", "-D", "FORWARD",
            "-d", ip, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--set-mss", str(mss),
        ], check=False, quiet=True)
        _run([
            "iptables", "-t", "mangle", "-A", "FORWARD",
            "-d", ip, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--set-mss", str(mss),
        ], check=False, quiet=True)

    # 3. Общий FORWARD MSS clamping
    _run([
        "iptables", "-t", "mangle", "-C", "FORWARD",
        "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ], check=False, quiet=True)


def _mtu_remove_rules(nodes: list) -> None:
    """Удаляет MSS-правила iptables для всех нод."""
    for nd in nodes:
        host = nd.get("host", "")
        if not host:
            continue
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            continue
        _run([
            "iptables", "-t", "mangle", "-D", "FORWARD",
            "-d", ip, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--set-mss", "1400",
        ], check=False, quiet=True)


def _mtu_state_load() -> dict:
    try:
        if _MTU_STATE_FILE.exists():
            return json.loads(_MTU_STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _mtu_state_save(data: dict) -> None:
    try:
        _MTU_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _MTU_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception:
        pass


def do_mtu_tuning() -> None:
    """
    Интерактивный MTU/MSS автотюнинг (одна нода HYDRA).
    Зондирует MTU до внешних узлов и применяет на основной интерфейс + MSS clamp.
    """
    os.system("clear")
    print()
    _box_top("📡  MTU / MSS АВТОТЮНИНГ")
    _box_row(f"  {DIM}ICMP Path MTU Discovery до внешних узлов, затем ip link + MSS clamp{NC}")
    _box_sep()

    try:
        from vless_installer.modules.network_mtu import detect_network_stack, recommend_mtu_for_awg, stack_label
        stack = detect_network_stack()
        _awg_mtu = recommend_mtu_for_awg(stack)
        _stack_str = stack_label(stack)
    except Exception:
        stack = {}
        _awg_mtu = 1280
        _stack_str = "—"

    probe_targets = [
        {"host": "1.1.1.1",        "label": "Cloudflare DNS", "port": 443},
        {"host": "8.8.8.8",        "label": "Google DNS",     "port": 443},
        {"host": "208.67.222.222", "label": "OpenDNS",        "port": 443},
    ]
    _box_row(f"  {CYAN}Режим HYDRA:{NC} зондирование uplink  {DIM}({_stack_str}){NC}")
    _box_row(f"  {DIM}Рекомендуемый MTU для AWG-клиентов: {CYAN}{_awg_mtu}{NC}")
    nodes: list = []

    iface = _mtu_get_iface()
    _box_row(f"  Интерфейс: {CYAN}{iface}{NC}")

    # Текущий MTU интерфейса
    try:
        r = _run(["cat", f"/sys/class/net/{iface}/mtu"], capture=True, check=False)
        current_mtu = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 1500
    except Exception:
        current_mtu = 1500
    _box_row(f"  Текущий MTU: {CYAN}{current_mtu}{NC}")

    # Предыдущий тюнинг
    prev = _mtu_state_load()
    if prev:
        prev_ts  = prev.get("timestamp", "—")
        prev_mtu = prev.get("applied_mtu", "—")
        _box_row(f"  {DIM}Последний тюнинг: {prev_ts}  →  MTU {prev_mtu}{NC}")

    _box_sep()
    _box_row(f"  {CYAN}[1]{NC}  Запустить зондирование и применить")
    _box_row(f"  {CYAN}[2]{NC}  Только зондирование (без применения)")
    _box_row(f"  {CYAN}[3]{NC}  Сбросить — восстановить MTU 1500 и удалить MSS-правила")
    _box_row(f"  {CYAN}[4]{NC}  Показать текущие MSS-правила iptables")
    _box_row(f"  {CYAN}[5]{NC}  Диагностика MTU по маршруту  {DIM}(tracepath + ping sweep){NC}")

    _box_row()
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip()
    except KeyboardInterrupt:
        return

    if ch == "5":
        do_mtu_tracepath_diag()
        return

    if ch in ("q", ""):
        return

    if ch == "3":
        # Сброс
        os.system("clear")
        print()
        _box_top("📡  MTU — СБРОС")
        _run(["ip", "link", "set", iface, "mtu", "1500"], check=False, quiet=True)
        _mtu_remove_rules(nodes)
        _MTU_STATE_FILE.unlink(missing_ok=True)
        _box_ok(f"MTU {iface} восстановлен → 1500, MSS-правила удалены")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    if ch == "4":
        os.system("clear")
        print()
        _box_top("📡  MSS-ПРАВИЛА IPTABLES")
        r = _run(["iptables", "-t", "mangle", "-L", "FORWARD", "-n", "-v"],
                 capture=True, check=False)
        if r.stdout.strip():
            max_w = _BOX_W - 4
            for line in r.stdout.strip().splitlines():
                if "TCPMSS" in line or "target" in line.lower():
                    if len(line) > max_w:
                        line = line[:max_w - 1] + "…"
                    _box_row(f"  {DIM}{line}{NC}")
        else:
            _box_row(f"  {DIM}Правил не найдено{NC}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── Зондирование ─────────────────────────────────────────────────────────
    os.system("clear")
    print()
    _box_top("📡  ЗОНДИРОВАНИЕ MTU")
    _box_row(f"  {DIM}Бинарный поиск максимального MTU с DF-битом (не фрагментировать){NC}")
    _box_row(f"  {DIM}Диапазон: 576–1500 байт  |  ~12 ping-пробов на хост{NC}")
    _box_sep()

    results = []
    for target in probe_targets:
        host  = target["host"]
        label = target["label"]
        _box_row(f"  Зондирую {CYAN}{label}{NC}  ({DIM}{host}{NC})...")

        mtu = _mtu_probe(host, max_mtu=1500, min_mtu=576)
        if mtu > 0:
            col = GREEN if mtu >= 1400 else YELLOW if mtu >= 1200 else RED
            _box_row(f"    {col}MTU = {mtu}{NC}  {DIM}(MSS = {mtu-40}){NC}")
            results.append(mtu)
        else:
            _box_row(f"    {RED}Недоступен / ICMP заблокирован{NC}")

    _box_sep()

    if not results:
        _box_warn("Ни один хост не ответил на ICMP DF-probe.")
        _box_row(f"  {DIM}Возможные причины: файрволл блокирует ICMP на стороне хоста{NC}")
        _box_row(f"  {DIM}Рекомендуется использовать стандартный MTU 1420 для VPN-туннелей{NC}")
        optimal = 1420
    else:
        # Берём минимальный из всех нод — гарантирует отсутствие фрагментации
        optimal = min(results)
        _box_row(f"  Результаты: {DIM}{results}{NC}")

    _box_row(f"  {BOLD}Оптимальный MTU: {GREEN}{optimal}{NC}  {DIM}(MSS = {optimal - 40}){NC}")

    if ch == "2":
        # Только показ, без применения
        _box_row()
        _box_row(f"  {DIM}Режим «только зондирование» — изменения не применены{NC}")
        _box_row(f"  {DIM}Для применения выберите пункт [1]{NC}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── Применение ───────────────────────────────────────────────────────────
    _box_row()
    _box_row(f"  Применяю MTU {CYAN}{optimal}{NC} на интерфейс {CYAN}{iface}{NC}...")
    _mtu_apply(iface, optimal, nodes if nodes else [])

    # Делаем изменение постоянным через /etc/network/interfaces или netplan
    _mtu_persist(iface, optimal)

    # Сохраняем в state
    _mtu_state_save({
        "applied_mtu":   optimal,
        "interface":     iface,
        "mss":           optimal - 40,
        "probed_hosts":  [t["host"] for t in probe_targets],
        "probe_results": results,
        "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

    _box_ok(f"MTU {iface} = {optimal}  |  MSS clamping = {optimal - 40}")
    _box_row(f"  {DIM}Изменение сохранено в {_MTU_STATE_FILE}{NC}")
    _box_bottom()

    log_to_file("INFO", f"MTU tuning: iface={iface}, mtu={optimal}, mss={optimal-40}, hosts={[t['host'] for t in probe_targets]}")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _mtu_persist(iface: str, mtu: int) -> None:
    """
    Сохраняет MTU постоянно:
    - netplan (Ubuntu 18+): /etc/netplan/*.yaml
    - /etc/network/interfaces (Debian/Ubuntu без netplan)
    - rc.local fallback
    """
    # Пробуем netplan
    netplan_dir = Path("/etc/netplan")
    if netplan_dir.exists():
        yamls = list(netplan_dir.glob("*.yaml")) + list(netplan_dir.glob("*.yml"))
        for yf in yamls:
            try:
                txt = yf.read_text()
                if iface in txt and "mtu" not in txt:
                    # Добавляем mtu под блок интерфейса
                    import re as _re2
                    new_txt = _re2.sub(
                        r'((?:ethernets|wifis|bonds|vlans):\s*\n\s+' + re.escape(iface) + r':.*?\n)',
                        lambda m: m.group(0) + f"      mtu: {mtu}\n",
                        txt, flags=re.DOTALL
                    )
                    if new_txt != txt:
                        yf.write_text(new_txt)
                        _run(["netplan", "apply"], check=False, quiet=True)
                        return
            except Exception:
                pass

    # /etc/network/interfaces
    interfaces_file = Path("/etc/network/interfaces")
    if interfaces_file.exists():
        try:
            txt = interfaces_file.read_text()
            if f"iface {iface}" in txt and "mtu" not in txt:
                import re as _re3
                # Заменяем строку "iface <iface> ..." целиком,
                # добавляя mtu на следующей строке с отступом.
                # Корректно для Debian 12/13: iface ens3 inet static → +mtu строка
                new_txt = _re3.sub(
                    r'(iface ' + re.escape(iface) + r'[^\n]*)',
                    lambda m: m.group(0) + f"\n    mtu {mtu}",
                    txt,
                )
                if new_txt != txt:
                    interfaces_file.write_text(new_txt)
                    return
        except Exception:
            pass

    # rc.local fallback
    rc = Path("/etc/rc.local")
    cmd_line = f"ip link set {iface} mtu {mtu}\n"
    try:
        existing = rc.read_text() if rc.exists() else "#!/bin/bash\nexit 0\n"
        if cmd_line.strip() not in existing:
            new_rc = existing.replace("exit 0", cmd_line + "exit 0")
            rc.write_text(new_rc)
            rc.chmod(0o755)
    except Exception:
        pass



# =============================================================================
#  CLOUDFLARE WARP — МОДУЛЬ
#  Поддерживает 3 режима маршрутизации:
#    full      — весь трафик через WARP (SSH-клиент исключается автоматически)
#    selective — только указанные пользователем IP/домены через WARP
#    runet     — заблокированные РФ ресурсы (списки runetfreedom)
#  SSH изолирован через network namespace (SSH Namespace) — SSH никогда не
#  попадает в WARP-туннель, даже в режиме full.
# =============================================================================

WARP_SSH_NAMESPACE   = "ssh_ns"          # имя netns для SSH-трафика
WARP_SSH_VETH_HOST   = "veth-ssh-host"   # veth-пара: сторона хоста
WARP_SSH_VETH_NS     = "veth-ssh-ns"     # veth-пара: сторона netns
WARP_SSH_NS_IP       = "10.200.200.1"    # IP в namespace (sshd слушает здесь тоже)
WARP_SSH_HOST_IP     = "10.200.200.2"    # IP хоста внутри пары
WARP_SSH_NS_NET      = "10.200.200.0/30"
WARP_SERVICE_FILE    = Path("/etc/systemd/system/warp-svc.service")
# warp — перенесено в vless_installer/modules/warp.py
def check_exit_geo(silent: bool = False) -> None:
    """
    Проверяет реальный GeoIP выходного IP через ip-api.com.
    Предупреждает если страна = RU (трафик не обходит блокировки).
    При silent=False открывает собственный бокс (вызов напрямую из меню).
    При silent=True — рисует только содержимое (вызов из do_full_diagnostic).
    """
    if not silent:
        _box_top(f"Геопроверка выходного IP")

    _box_row()

    try:
        r = _run(
            ["curl", "-s", "--max-time", "10",
             "http://ip-api.com/json?fields=status,country,countryCode,city,isp,query"],
            capture=True, check=False
        )
        if r.returncode != 0 or not r.stdout.strip():
            _box_warn("Не удалось получить GeoIP — нет ответа от ip-api.com")
            return
        data = json.loads(r.stdout.strip())
    except Exception as e:
        _box_warn(f"Ошибка GeoIP запроса: {e}")
        return

    if data.get("status") != "success":
        _box_warn("ip-api.com вернул ошибку — попробуйте позже")
        return

    ip         = data.get("query", "?")
    country    = data.get("country", "?")
    country_cc = data.get("countryCode", "?")
    city       = data.get("city", "?")
    isp        = data.get("isp", "?")

    _flag_cc  = country_flag_emoji(country_cc)
    _cty_tr   = country[:24]
    _city_tr  = city[:24]
    _isp_tr   = isp[:34]
    # ── Блок IP/ISP внутри рамки, затем рамка закрывается ──
    _box_row(f"  IP:      {CYAN}{ip}{NC}")
    _box_row(f"  ISP:     {CYAN}{_isp_tr}{NC}")
    _box_bottom()
    # Флаг + страна + город — вне рамки
    print(f"  {_flag_cc}  {CYAN}{_cty_tr} ({country_cc}){NC}  {DIM}{_city_tr}{NC}")
    print()

    # ── Статус в отдельном боксе ──
    if country_cc == "RU":
        _box_top()
        _box_row(f"  {RED}⚠  ВНИМАНИЕ: выходной IP находится в России!{NC}")
        _box_row(f"  {YELLOW}   Трафик может НЕ обходить российские блокировки.{NC}")
        _box_row(f"  {YELLOW}   Проверьте настройки exit-ноды (Режим B) или WARP.{NC}")
        _box_bottom()
        log_to_file("WARN", f"GeoIP: выходной IP {ip} в России ({isp})")
    else:
        _box_top()
        _box_row(f"  {GREEN}✓  Выходной IP за пределами России — блокировки обходятся{NC}")
        _box_bottom()
        log_to_file("INFO", f"GeoIP: выходной IP {ip} ({country}, {isp})")

    # Дополнительно — проверка через Cloudflare trace если WARP активен
    try:
        rc = _run(["warp-cli", "--version"], capture=True, check=False)
        if rc.returncode == 0:
            rt = _run(["curl", "-s", "--max-time", "8",
                       "https://www.cloudflare.com/cdn-cgi/trace"],
                      capture=True, check=False)
            warp_on = "warp=on" in rt.stdout
            warp_str = f"{GREEN}ON{NC}" if warp_on else f"{YELLOW}OFF{NC}"
            print()
            _box_top()
            _box_row(f"  WARP:    {warp_str} (Cloudflare trace)")
            _box_bottom()
    except Exception:
        pass


# ---------------------------------------------------------------------------
#  4. МЕНЕДЖЕР МНОЖЕСТВЕННЫХ ПОЛЬЗОВАТЕЛЕЙ
# ---------------------------------------------------------------------------
USERS_FILE = CONFIG_DIR / "users.json"


def _fmt_bytes_ru(n: int) -> str:
    if n < 1024:        return f"{n} Б"
    if n < 1024 ** 2:   return f"{n/1024:.1f} КБ"
    if n < 1024 ** 3:   return f"{n/1024**2:.1f} МБ"
    return f"{n/1024**3:.2f} ГБ"


def _gradient_bar(val: int, total: int, width: int = 20, force_color: str = "") -> str:
    """Блочный прогресс-бар с градиентом цвета по заполненности.
    Использует символы ▓ (заполнено) и ░ (пусто).
    Цвет зависит от процента: <40% зелёный, 40-70% голубой, >70% жёлтый, 100% белый.
    force_color — если задан, использует этот цвет вместо градиента."""
    if total == 0:
        return f"{DIM}{'░' * width}{NC}"
    pct = val / total
    filled = max(0, min(width, int(pct * width)))
    empty  = width - filled
    if force_color:
        col = force_color
    else:
        if pct >= 1.0:      col = WHITE
        elif pct >= 0.70:   col = YELLOW
        elif pct >= 0.40:   col = CYAN
        else:               col = GREEN
    return f"{col}{'▓' * filled}{NC}{DIM}{'░' * empty}{NC}"


def _bar_mini(val: int, total: int, width: int = 20, force_color: str = "") -> str:
    """Блочный прогресс-бар для использования внутри _box_row."""
    return _gradient_bar(val, total, width, force_color)


def _device_icon(label: str) -> str:
    """
    Возвращает ASCII/Emoji-иконку по метке устройства.
    Xray-статистика в терминале: emoji поддерживаются в большинстве современных SSH-клиентов.
    """
    if not label:
        return "  "
    low = label.lower()
    if any(k in low for k in ("iphone", "ios", "phone", "mobile", "смартфон")):
        return "📱"
    if any(k in low for k in ("ipad", "tablet", "планшет")):
        return "📲"
    if any(k in low for k in ("macbook", "laptop", "ноутбук", "notebook")):
        return "💻"
    if any(k in low for k in ("pc", "desktop", "work", "home", "пк", "компьютер")):
        return "🖥️"
    if any(k in low for k in ("router", "routeur", "маршрутизатор")):
        return "📡"
    if any(k in low for k in ("tv", "смарт", "smart", "appletv", "firetv")):
        return "📺"
    if any(k in low for k in ("watch", "часы")):
        return "⌚"
    if any(k in low for k in ("android", "samsung", "pixel", "xiaomi", "huawei")):
        return "📱"
    if any(k in low for k in ("mac", "apple")):
        return "🍎"
    if any(k in low for k in ("win", "windows")):
        return "🪟"
    if any(k in low for k in ("linux", "ubuntu", "debian")):
        return "🐧"
    return "📦"


def _do_export_users_zip(users: list, install_mode: str) -> None:
    """
    Экспортирует всех пользователей в ZIP-архив:
    - каждый пользователь: ссылка (.txt) + QR-код (.png)
    - README.txt с инструкцией
    Архив сохраняется в /root/vless_users_export_<дата>.zip
    """
    import zipfile, tempfile
    from datetime import datetime as _dt

    qrencode = shutil.which("qrencode")
    if not qrencode:
        warn("qrencode не найден — QR-коды не будут созданы. Установите: apt install qrencode")

    print()
    _box_top("Экспорт пользователей в ZIP")
    _box_row(f"  Пользователей: {CYAN}{len(users)}{NC}")
    _box_sep()

    # Загружаем параметры сервера
    _state = {}
    if STATE_FILE.exists():
        try:
            _state = json.loads(STATE_FILE.read_text())
        except Exception:
            pass

    _, _, _flag = get_server_country_cached()

    zip_name = f"/root/vless_users_export_{_dt.now().strftime('%Y%m%d_%H%M%S')}.zip"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        readme_lines = [
            "VLESS VPN — Ссылки для подключения",
            "=" * 40,
            f"Сервер: {_state.get('domain', '?')}",
            f"Протокол: {_state.get('protocol_mode', 'reality').upper()}",
            f"Страна: {_flag} {_state.get('domain', '')}",
            f"Дата экспорта: {_dt.now().strftime('%d.%m.%Y %H:%M')}",
            "",
            "Как подключиться:",
            "  1. Откройте v2rayNG / Hiddify / Nekobox",
            "  2. Нажмите '+' → Сканировать QR или Импорт из буфера",
            "  3. Вставьте ссылку из .txt файла или отсканируйте QR",
            "",
            "Файлы:",
        ]

        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
            for u in users:
                if u.get("disabled"):
                    continue
                email    = u.get("email", "user")
                name     = u.get("name", email)
                label    = u.get("device_label") or name
                name_safe = re.sub(r"[^\w\-.]", "_", email)

                # Генерируем ссылку
                link = None
                try:
                    link = _gen_vless_link(
                        host      = _state.get("domain", ""),
                        uuid_str  = u["uuid"],
                        pbk       = _state.get("public_key", ""),
                        sid       = _state.get("short_id", ""),
                        domain    = _state.get("domain", ""),
                        proto     = _state.get("protocol_mode", "reality"),
                        xhttp_path= _state.get("xhttp_path", "/"),
                        xhttp_mode= _state.get("xhttp_mode", "streamup"),
                        port      = _state.get("server_port", 443),
                    )
                except Exception as ex:
                    _box_warn(f"  Не удалось сгенерировать ссылку для {email}: {ex}")
                    continue

                # .txt с ссылкой
                txt_name = f"{name_safe}.txt"
                txt_content = (
                    f"Пользователь: {name}\n"
                    f"Email: {email}\n"
                    f"Устройство: {label}\n\n"
                    f"Ссылка для подключения:\n{link}\n"
                )
                zf.writestr(txt_name, txt_content)
                readme_lines.append(f"  {name_safe}.txt / {name_safe}.png  →  {name} ({label})")

                # QR PNG
                if qrencode:
                    png_tmp = str(tmp / f"{name_safe}.png")
                    r = _run([qrencode, "-t", "PNG", "-o", png_tmp,
                               "-s", "8", "-m", "4", link],
                              check=False, quiet=True)
                    if r.returncode == 0:
                        zf.write(png_tmp, f"{name_safe}.png")

                _box_row(f"  {GREEN}✓{NC}  {name:<20}  {DIM}{email}{NC}")

            # README
            zf.writestr("README.txt", "\n".join(readme_lines))

    _box_sep()
    _box_ok(f"Архив сохранён: {zip_name}")
    _box_row(f"  {DIM}Скачайте через: scp root@<сервер>:{zip_name} ./{NC}")
    _box_bottom()


# do_unified_user_manager deleted in favor of subscription system
# ---------------------------------------------------------------------------
#  5. АВТООБНОВЛЕНИЕ GEOIP/GEOSITE (независимо от split tunnel)
# ---------------------------------------------------------------------------
def _backup_encrypt(archive_path: Path, password: str) -> Path | None:
    """
    Шифрует tar.gz архив через openssl AES-256-CBC → .tar.gz.enc
    Возвращает путь к зашифрованному файлу или None при ошибке.
    """
    enc_path = archive_path.with_suffix(".gz.enc")
    r = _run([
        "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "310000",
        "-in",  str(archive_path),
        "-out", str(enc_path),
        "-pass", f"pass:{password}",
    ], capture=True, check=False)
    if r.returncode != 0:
        warn(f"openssl enc завершился с ошибкой: {r.stderr[:200]}")
        return None
    enc_path.chmod(0o600)
    return enc_path


def _backup_decrypt(enc_path: Path, password: str, out_path: Path) -> bool:
    """
    Расшифровывает .tar.gz.enc → tar.gz через openssl.
    Возвращает True при успехе.
    """
    r = _run([
        "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "310000",
        "-in",  str(enc_path),
        "-out", str(out_path),
        "-pass", f"pass:{password}",
    ], capture=True, check=False)
    if r.returncode != 0:
        warn(f"Расшифровка не удалась: {r.stderr[:200]}")
        return False
    return True


def do_manage_backup() -> None:
    """Меню экспорта/импорта конфигурации."""
    while True:
        os.system("clear")
        _box_top(f"Экспорт / Импорт конфигурации")

        # Список существующих бэкапов
        backups = sorted(
            list(Path("/root").glob("hydra-backup-*.tar.gz"))
            + list(Path("/root").glob("xray-backup-*.tar.gz")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if backups:
            _box_row(f"  {BOLD}Существующие архивы в /root/:{NC}")
            for bp in backups[:5]:
                sz = bp.stat().st_size // 1024
                _box_row(f"    {DIM}{bp.name}{NC}  ({sz} КБ)")
        else:
            _box_row(f"  {DIM}Архивов в /root/ не найдено{NC}")

        _box_item("1", f"📦 Экспортировать конфигурацию (создать архив)")
        _box_item("2", f"🔐 Экспортировать с шифрованием  {DIM}(AES-256-CBC){NC}")
        _box_item("3", f"📂 Импортировать конфигурацию HYDRA")
        _box_item("4", f"🗑️  Удалить старые архивы (оставить последние 3)")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            do_hydra_export_backup(encrypt=False)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            do_hydra_export_backup(encrypt=True)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            # Поддержка .enc файлов — расшифровываем перед импортом
            archive_raw = input(f"  Путь к архиву (.tar.gz или .gz.enc): ").strip()
            ap = Path(archive_raw)
            if not ap.exists():
                warn(f"Файл не найден: {ap}")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            if ap.suffix == ".enc":
                import getpass as _getpass
                try:
                    pwd = _getpass.getpass("  Пароль для расшифровки: ")
                except Exception:
                    pwd = input("  Пароль для расшифровки: ").strip()
                dec_path = ap.with_suffix("").with_suffix(".tar.gz")
                if not _backup_decrypt(ap, pwd, dec_path):
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                info(f"Расшифровано → {dec_path}")
                ap = dec_path
            do_hydra_import_backup()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            patterns = ("hydra-backup-*", "xray-backup-*")
            all_arch = []
            for pat in patterns:
                all_arch.extend(Path("/root").glob(pat))
            to_del = sorted(all_arch, key=lambda p: p.stat().st_mtime, reverse=True)[3:]
            if not to_del:
                info("Нечего удалять (архивов ≤ 3)")
            else:
                for f in to_del:
                    f.unlink()
                    dim(f"  Удалён: {f.name}")
                success(f"Удалено {len(to_del)} старых архивов")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)



# ---------------------------------------------------------------------------
#  АВТОМАТИЧЕСКИЙ БЭКАП ПО РАСПИСАНИЮ
# ---------------------------------------------------------------------------
_SCHEDULED_BACKUP_CRON = Path("/etc/cron.d/xray-backup")

def _scheduled_backup_run() -> None:
    """Cron: архив state и конфигов HYDRA."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(f"/root/hydra-backup-{ts}.tar.gz")
    items = _hydra_collect_backup_paths()
    if not items:
        log_to_file("WARN", "Scheduled backup: no HYDRA files found")
        return
    import tarfile
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for src, arcname in items:
            dst = tmpdir / arcname
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        with tarfile.open(out, "w:gz") as tar:
            for f in tmpdir.rglob("*"):
                if f.is_file():
                    tar.add(f, arcname=f.relative_to(tmpdir).as_posix())
    sz = out.stat().st_size // 1024
    log_to_file("SUCCESS", f"Scheduled backup created: {out} ({sz} КБ)")
    all_archives = sorted(
        list(Path("/root").glob("hydra-backup-*.tar.gz"))
        + list(Path("/root").glob("xray-backup-*.tar.gz")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in all_archives[7:]:
        try:
            old.unlink()
            log_to_file("INFO", f"Scheduled backup rotated (removed): {old.name}")
        except Exception:
            pass


def do_manage_scheduled_backup() -> None:
    """Меню настройки автоматического бэкапа по расписанию."""
    _BACKUP_SCRIPT = Path(sys.argv[0]).resolve()

    def _current_schedule() -> str | None:
        if not _SCHEDULED_BACKUP_CRON.exists():
            return None
        for line in _SCHEDULED_BACKUP_CRON.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
        return None

    while True:
        os.system("clear")
        print()
        _box_top("📦  АВТОМАТИЧЕСКИЙ БЭКАП ПО РАСПИСАНИЮ")
        _box_row()
        cur = _current_schedule()
        if cur:
            _box_row(f"  Статус:     {GREEN}включён{NC}")
            _box_row(f"  Cron:       {DIM}{cur}{NC}")
        else:
            _box_row(f"  Статус:     {DIM}выключен{NC}")
        _box_row()
        all_archives = sorted(Path("/root").glob("xray-backup-*.tar.gz"), reverse=True)
        if all_archives:
            _box_row(f"  Последние архивы (из /root/):")
            for bp in all_archives[:5]:
                sz = bp.stat().st_size // 1024
                _box_row(f"    {DIM}{bp.name}{NC}  ({sz} КБ)")
        else:
            _box_row(f"  {DIM}Архивов пока нет{NC}")
        _box_sep()
        _box_item("1", f"Включить / изменить расписание  {DIM}(каждые N ночей){NC}")
        _box_item("2", f"Выключить автобэкап")
        _box_item("3", f"Запустить бэкап прямо сейчас")
        _box_item("Q", f"Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if ch == "1":
            print()
            print(f"  {DIM}Введите интервал в днях (1 = каждую ночь, 7 = раз в неделю).{NC}")
            try:
                days_s = input(f"  Интервал [1-30, по умолчанию 1]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            days = 1
            if days_s.isdigit() and 1 <= int(days_s) <= 30:
                days = int(days_s)
            try:
                hour_s = input(f"  Час ночного запуска [0-5, по умолчанию 3]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            hour = 3
            if hour_s.isdigit() and 0 <= int(hour_s) <= 5:
                hour = int(hour_s)

            # Генерируем cron-строку
            # Каждую ночь: 0 3 * * *
            # Каждые N ночей: 0 3 */N * *  (стандартный шаг по дням месяца)
            day_field = "*" if days == 1 else f"*/{days}"
            cron_line = (
                f"# Xray scheduled backup (every {days} day(s) at {hour}:00)\n"
                f"0 {hour} {day_field} * * root"
                f" python3 {_BACKUP_SCRIPT} --scheduled-backup"
                f" >> /var/log/xray-scheduled-backup.log 2>&1\n"
            )
            _SCHEDULED_BACKUP_CRON.write_text(cron_line)
            _SCHEDULED_BACKUP_CRON.chmod(0o644)
            success(f"Автобэкап включён: каждые {days} д. в {hour:02d}:00")
            dim(f"  Файл: {_SCHEDULED_BACKUP_CRON}")
            dim(f"  Лог:  /var/log/xray-scheduled-backup.log")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if _SCHEDULED_BACKUP_CRON.exists():
                _SCHEDULED_BACKUP_CRON.unlink()
                success("Автобэкап выключен")
            else:
                info("Автобэкап уже выключен")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            info("Запуск бэкапа...")
            try:
                _scheduled_backup_run()
                new_arch = sorted(Path("/root").glob("xray-backup-*.tar.gz"), reverse=True)
                if new_arch:
                    sz = new_arch[0].stat().st_size // 1024
                    success(f"Готово: {new_arch[0].name} ({sz} КБ)")
                else:
                    warn("Архив не создан — проверьте права на /root/")
            except Exception as e:
                warn(f"Ошибка бэкапа: {e}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# ---------------------------------------------------------------------------
#  7. ТЕСТ СКОРОСТИ ЧЕРЕЗ EXIT-НОДЫ (все ноды по очереди)
# ---------------------------------------------------------------------------
# =============================================================================
#  МАТРИЦА СОСТОЯНИЯ EXIT-НОД
# =============================================================================

def _access_log_bytes_per_node(nodes: list[dict], hours: int = 24) -> dict[str, int]:
    """
    Парсит /var/log/xray/access.log за последние `hours` часов.
    Возвращает dict: host → суммарные байты (upload+download).
    Сопоставление: ищем тег «chain-exit-N» в записях routing и связываем
    с нодой по индексу (chain-exit-1 → nodes[0], chain-exit-2 → nodes[1] …).
    """
    result: dict[str, int] = {nd["host"]: 0 for nd in nodes}
    if not DIAG_ACCESS_LOG.exists():
        return result

    cutoff = time.time() - hours * 3600

    # Паттерны байт (те же что в _diag_check_access_log)
    pat_ts      = re.compile(r'^(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})')
    pat_bytes_a = re.compile(
        r'\[([^\]]+)\]\s+(\d+)\s+bytes?\s+upload,?\s+(\d+)\s+bytes?\s+download',
        re.IGNORECASE)
    pat_bytes_b = re.compile(r'>>\s+([\w\-]+)\s+\|\s+(\d+)\s+(\d+)\s+\|')
    pat_bytes_c = re.compile(r'\[([^\]]+)\s*->\s*([^\]]+)\]\s+(\d+)\s+(\d+)')
    pat_bytes_d = re.compile(r'(chain-exit-\d+)\s+\|\s+(\d+)\s+\|\s+(\d+)')

    # Индекс нод: "chain-exit-1" → nodes[0]
    tag_to_host: dict[str, str] = {}
    for i, nd in enumerate(nodes):
        tag_to_host[f"chain-exit-{i+1}"] = nd["host"]
        # Балансировщик часто пишет просто "balancer" или "chain-balancer"
        tag_to_host["balancer"]       = nd["host"]
        tag_to_host["chain-balancer"] = nd["host"]

    try:
        lines = DIAG_ACCESS_LOG.read_text(errors="replace").splitlines()[-60000:]
    except Exception:
        return result

    for line in lines:
        # Фильтр по времени
        ts_m = pat_ts.match(line)
        if ts_m:
            try:
                ts = datetime.strptime(
                    f"{ts_m.group(1)} {ts_m.group(2)}", "%Y/%m/%d %H:%M:%S"
                ).timestamp()
                if ts < cutoff:
                    continue
            except Exception:
                pass

        def _add(tag: str, up: int, dn: int) -> None:
            host = tag_to_host.get(tag)
            if host and host in result:
                result[host] += up + dn

        m = pat_bytes_a.search(line)
        if m:
            tag = m.group(1).split("->")[-1].strip()
            _add(tag, int(m.group(2)), int(m.group(3)))
            continue
        m = pat_bytes_b.search(line)
        if m:
            _add(m.group(1).strip(), int(m.group(2)), int(m.group(3)))
            continue
        m = pat_bytes_c.search(line)
        if m:
            _add(m.group(2).strip(), int(m.group(3)), int(m.group(4)))
            continue
        m = pat_bytes_d.search(line)
        if m:
            _add(m.group(1).strip(), int(m.group(2)), int(m.group(3)))

    return result


def do_node_health_matrix() -> None:
    """
    Матрица состояния всех exit-нод (Режим B / каскад).
    Для каждой ноды в одной таблице:
      • TCP ping (прямое подключение с этого сервера)
      • HTTP latency через ноду (curl --connect-to)
      • Трафик за 24ч (из access.log)
      • Роль: pinned / balancer / dead
    """
    os.system("clear")
    print()
    _box_top("🗺️   МАТРИЦА СОСТОЯНИЯ EXIT-НОД")
    _box_row(f"  {DIM}Проверяет все ноды каскада параллельно и выводит сводную таблицу.{NC}")
    _box_row()

    # ── Загрузка нод из state ────────────────────────────────────────────────
    nodes: list[dict] = []
    pinned_idx  = -1
    install_mode = "A"
    try:
        if STATE_FILE.exists():
            st = json.loads(STATE_FILE.read_text())
            nodes        = st.get("chain_nodes", [])
            pinned_idx   = st.get("chain_pinned_node_index", -1)
            install_mode = st.get("install_mode", "A")
    except Exception:
        pass

    if install_mode != "B" or not nodes:
        # Проверяем, не AWG-режим ли это
        _awg_on = False
        try:
            if STATE_FILE.exists():
                _awg_on = json.loads(STATE_FILE.read_text()).get("awg_exit_enabled", False)
        except Exception:
            pass
        if _awg_on:
            _box_info("  Режим AWG: матрица нод недоступна — выход через туннель awg0")
            _box_row(f"  {DIM}В режиме AWG нет VLESS exit-нод. Используйте AWG Watchdog{NC}")
            _box_row(f"  {DIM}(Меню → Безопасность → [W] AWG Tunnel Watchdog){NC}")
            # Покажем статус awg0 интерфейса
            _r_awg = _run(["ip", "link", "show", "awg0"], capture=True, check=False)
            if _r_awg.returncode == 0:
                _box_row(f"  {GREEN}● awg0 интерфейс активен{NC}")
            else:
                _box_row(f"  {RED}✗ awg0 не найден — туннель не поднят!{NC}")
            _r_rule = _run(["ip", "rule", "show"], capture=True, check=False)
            _fwmark_ok = str(AWG_FWMARK) in (_r_rule.stdout or "")
            if _fwmark_ok:
                _box_row(f"  {GREEN}● ip rule fwmark {AWG_FWMARK} присутствует{NC}")
            else:
                _box_row(f"  {RED}✗ ip rule fwmark {AWG_FWMARK} ОТСУТСТВУЕТ{NC}")
        else:
            _box_warn("Режим B (каскад) не настроен — нет exit-нод для проверки")
            _box_row(f"  {DIM}Матрица доступна только в Режиме B (chain-proxy).{NC}")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    _box_row(f"  Нод в каскаде: {CYAN}{len(nodes)}{NC}  |  "
             f"Pinned: {CYAN}{'нода #'+str(pinned_idx+1) if pinned_idx >= 0 else 'нет (балансировщик)'}{NC}")
    _box_row()
    _box_info(f"Проверяем {len(nodes)} нод(у)...")

    # ── Динамические ширины колонок ──────────────────────────────────────────
    # "  " + № + " " + Host + " " + TCP + " " + HTTP + " " + Traffic + " " + Role
    _W_NUM     = 3
    _W_TCP     = 9   # "999 мс" / "таймаут"
    _W_HTTP    = 9
    _W_TRAFFIC = 9   # "1023 МБ"
    _W_ROLE    = 10  # "pinned" / "balancer" / "dead"
    _W_HOST    = (_BOX_W
                  - 2              # indent "  "
                  - _W_NUM - 1    # № + пробел
                  - _W_TCP - 1    # TCP + пробел
                  - _W_HTTP - 1   # HTTP + пробел
                  - _W_TRAFFIC - 1  # 24ч + пробел
                  - _W_ROLE - 1   # Роль + ведущий пробел
                  )
    _W_HOST    = max(16, _W_HOST)

    def _fmt_bytes(b: int) -> str:
        if b == 0:
            return f"{DIM}—{NC}"
        if b < 1024:
            return f"{b} Б"
        if b < 1024 ** 2:
            return f"{b//1024} КБ"
        if b < 1024 ** 3:
            return f"{b//1024**2} МБ"
        return f"{b//1024**3:.1f} ГБ"

    def _tcp_ms(host: str, port: int) -> tuple[int, str]:
        """Возвращает (ms_int, formatted_str). ms=-1 при недоступности."""
        try:
            t0 = time.time()
            ip = socket.gethostbyname(host)
            s  = socket.create_connection((ip, port), timeout=5)
            s.close()
            ms = int((time.time() - t0) * 1000)
            col = GREEN if ms < 150 else YELLOW if ms < 400 else RED
            return ms, f"{col}{ms} мс{NC}"
        except Exception:
            return -1, f"{RED}▼ down{NC}"

    def _http_ms(host: str, port: int) -> str:
        """HTTP latency через curl --connect-to (имитирует реальный клиент)."""
        try:
            r = _run([
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{time_connect}",
                "--max-time", "8",
                "--connect-to", f"{host}:{port}:{host}:{port}",
                f"https://{host}:{port}/",
            ], capture=True, check=False)
            if r.returncode != 0 or not r.stdout.strip():
                return f"{DIM}—{NC}"
            ms = int(float(r.stdout.strip()) * 1000)
            col = GREEN if ms < 200 else YELLOW if ms < 500 else RED
            return f"{col}{ms} мс{NC}"
        except Exception:
            return f"{DIM}—{NC}"

    # ── Параллельный сбор данных ─────────────────────────────────────────────
    import threading

    n = len(nodes)
    tcp_results:  list[tuple[int, str]] = [(-1, "")] * n
    http_results: list[str]             = [""] * n

    def _probe(i: int, nd: dict) -> None:
        host = nd.get("host", "")
        port = int(nd.get("port", 443))
        tcp_results[i]  = _tcp_ms(host, port)
        http_results[i] = _http_ms(host, port)

    threads = [threading.Thread(target=_probe, args=(i, nd), daemon=True)
               for i, nd in enumerate(nodes)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=12)

    # Трафик из access.log (24ч)
    bytes_per_host = _access_log_bytes_per_node(nodes, hours=24)

    # ── Вывод таблицы ────────────────────────────────────────────────────────
    _box_row()
    _box_sep()

    # Заголовок
    hdr = (f"  {'№':{_W_NUM}}"
           f" {'Хост':{_W_HOST}}"
           f" {'TCP':>{_W_TCP}}"
           f" {'HTTP':>{_W_HTTP}}"
           f" {'24ч':>{_W_TRAFFIC}}"
           f" {'Роль':{_W_ROLE}}")
    _box_row(f"{BOLD}{hdr}{NC}")
    sep = (f"  {'─'*_W_NUM} {'─'*_W_HOST}"
           f" {'─'*_W_TCP} {'─'*_W_HTTP}"
           f" {'─'*_W_TRAFFIC} {'─'*_W_ROLE}")
    _box_row(sep)

    dead_count = 0
    for i, nd in enumerate(nodes):
        host     = nd.get("host", "?")
        port     = int(nd.get("port", 443))
        tcp_ms_v, tcp_str = tcp_results[i]
        http_str          = http_results[i]
        traffic_b         = bytes_per_host.get(host, 0)
        traffic_str       = _fmt_bytes(traffic_b)

        # Роль ноды
        is_dead   = tcp_ms_v < 0
        is_pinned = (i == pinned_idx)
        if is_dead:
            dead_count += 1
            role_str = f"{RED}dead{NC}"
        elif is_pinned:
            role_str = f"{CYAN}pinned{NC}"
        else:
            role_str = f"{DIM}balancer{NC}"

        host_disp = host if len(host) <= _W_HOST else host[:_W_HOST - 1] + "…"

        def _pad_ansi(s: str, width: int) -> str:
            """Дополняет строку с ANSI до видимой ширины width."""
            return s + " " * max(0, width - _wcslen(s))

        line = (f"  {BOLD}{i+1:>{_W_NUM}}{NC}"
                f" {CYAN if not is_dead else DIM}{host_disp:{_W_HOST}}{NC}"
                f" {_pad_ansi(tcp_str,  _W_TCP)}"
                f" {_pad_ansi(http_str, _W_HTTP)}"
                f" {_pad_ansi(traffic_str, _W_TRAFFIC)}"
                f" {_pad_ansi(role_str, _W_ROLE)}")
        _box_row(line)

    _box_row(sep)

    # ── Итог ─────────────────────────────────────────────────────────────────
    alive = len(nodes) - dead_count
    _box_row()
    if dead_count == 0:
        _box_row(f"  {GREEN}✓ Все {len(nodes)} нод(а) доступны{NC}")
    elif alive == 0:
        _box_row(f"  {RED}✗ Все ноды недоступны! Xray не может использовать каскад{NC}")
    else:
        _box_row(f"  {YELLOW}⚠  Доступно: {alive}/{len(nodes)}  |  "
                 f"Недоступно: {dead_count}/{len(nodes)}{NC}")

    log_bytes = sum(bytes_per_host.values())
    if log_bytes > 0:
        _box_row(f"  {DIM}Трафик за 24ч (из access.log): {_fmt_bytes(log_bytes)} суммарно{NC}")
    else:
        _box_row(f"  {DIM}Трафик: нет данных в access.log (нужен loglevel=info){NC}")

    _box_row()
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ОБНАРУЖЕНИЕ БЛОКИРОВКИ ПОРТА ПРОВАЙДЕРОМ (ВНЕШНЯЯ ПРОВЕРКА)
# =============================================================================

def do_port_block_detect() -> None:
    """
    Проверяет доступность порта сервера снаружи через check-host.net API.
    Запрашивает TCP-check с нескольких точек (RU, EU, Asia) одновременно,
    ждёт результата и показывает таблицу: точка → доступен/нет.

    Отвечает на вопрос «видит ли меня Россия/Европа?» — то, что нельзя
    проверить изнутри сервера.
    """
    global _BOX_W
    _BOX_W = _get_box_width()   # пересчитываем под актуальный размер терминала
    os.system("clear")
    print()
    _box_top("🔌  ПРОВЕРКА ДОСТУПНОСТИ ПОРТА СНАРУЖИ")
    _box_row(f"  {DIM}Проверяет, не заблокирован ли ваш порт российским провайдером.{NC}")
    _box_row(f"  {DIM}Запросы идут с внешних нод check-host.net (RU, EU, Asia).{NC}")
    _box_row()

    # ── Получаем домен и порт из state ──────────────────────────────────────
    domain = ""
    port   = 443
    try:
        if STATE_FILE.exists():
            st     = json.loads(STATE_FILE.read_text())
            domain = st.get("domain", "")
            port   = int(st.get("server_port", 443))
    except Exception:
        pass

    if not domain:
        domain = _box_input("Домен или IP сервера", reopen=True)
    if not domain:
        _box_warn("Домен не указан")
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # Разрешаем порт интерактивно если нужно
    raw_port = _box_input(f"Порт [{port}]", default=str(port), reopen=False)
    if raw_port.isdigit():
        port = int(raw_port)

    # Бокс уже закрыт после _box_input(reopen=False)
    print()

    # ── Узлы check-host.net для проверки ─────────────────────────────────────
    # Выбираем узлы: приоритет на RU (главный вопрос), плюс EU и Asia для картины
    CHECK_NODES = [
        # RU — ключевые (блокировки обычно только в России)
        ("ru1.node.check-host.net",  "RU Москва"),
        ("ru2.node.check-host.net",  "RU Москва-2"),
        ("ru3.node.check-host.net",  "RU СПб"),
        ("ru4.node.check-host.net",  "RU Екатеринбург"),
        ("ru5.node.check-host.net",  "RU Новосибирск"),
        # EU
        ("de1.node.check-host.net",  "DE Франкфурт"),
        ("nl1.node.check-host.net",  "NL Амстердам"),
        ("fi1.node.check-host.net",  "FI Хельсинки"),
        ("pl1.node.check-host.net",  "PL Варшава"),
        # Asia / other
        ("tr2.node.check-host.net",  "TR Стамбул"),
        ("il1.node.check-host.net",  "IL Тель-Авив"),
        ("us1.node.check-host.net",  "US Ашберн"),
    ]

    CH_API   = "https://check-host.net"
    CH_HDR   = ["Accept: application/json"]

    # Открываем второй бокс — результаты (сразу, до запроса)
    _box_top(f"Результаты TCP-проверки {domain}:{port}")
    _box_info(f"Отправляем запрос на {len(CHECK_NODES)} нод check-host.net...")

    # Шаг 1: создаём задачу (request_id)
    nodes_param = "&".join(f"node={n}" for n, _ in CHECK_NODES)
    check_url   = (f"{CH_API}/check-tcp"
                   f"?host={domain}&port={port}&max_nodes={len(CHECK_NODES)}"
                   f"&{nodes_param}")
    r_init = _run(
        ["curl", "-s", "--max-time", "20",
         "-H", "Accept: application/json",
         check_url],
        capture=True, check=False
    )

    request_id = ""
    if r_init.returncode == 0 and r_init.stdout.strip().startswith("{"):
        try:
            init_data  = json.loads(r_init.stdout.strip())
            request_id = init_data.get("request_id", "")
        except Exception:
            pass

    if not request_id:
        _box_warn("check-host.net не ответил — проверяем запасным методом")
        _port_block_fallback(domain, port, CHECK_NODES)
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    _box_row(f"  {DIM}request_id: {request_id}{NC}")
    _box_info("Ждём результатов (до 15 сек)...")

    # Шаг 2: поллинг результатов (до 30 сек — дальним нодам нужно больше времени)
    result_data: dict = {}
    for attempt in range(10):
        time.sleep(3)
        r_res = _run(
            ["curl", "-s", "--max-time", "15",
             "-H", "Accept: application/json",
             f"{CH_API}/check-result/{request_id}"],
            capture=True, check=False
        )
        if r_res.returncode == 0 and r_res.stdout.strip().startswith("{"):
            try:
                raw = json.loads(r_res.stdout.strip())
                # API может вернуть {"ok":1, "nodes":{...}} или сразу плоский dict
                if isinstance(raw, dict) and "nodes" in raw:
                    result_data = raw["nodes"]
                else:
                    result_data = raw
                ready = sum(1 for v in result_data.values() if v is not None)
                if ready >= len(CHECK_NODES) // 2:
                    break
            except Exception:
                pass

    if not result_data:
        _box_warn("Не удалось получить результаты — используем резервный метод")
        _port_block_fallback(domain, port, CHECK_NODES)
        _box_bottom()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # ── Вывод таблицы результатов ─────────────────────────────────────────────
    # Ширины: "  " + Label + " " + Status + " " + Latency
    # "заблокирован" = 12 символов → _W_STAT=12
    _W_STAT  = 12
    _W_LABEL = min(22, _BOX_W - 2 - 1 - _W_STAT - 1 - 6)
    _W_LAT   = _BOX_W - 2 - _W_LABEL - 1 - _W_STAT - 1

    # Вспомогательные функции с ANSI-aware padding
    def _tr(s: str, w: int) -> str:
        return s + " " * max(0, w - _wcslen(s))

    def _tl(s: str, w: int) -> str:
        return " " * max(0, w - _wcslen(s)) + s

    _box_row()
    # Заголовок — через _tr/_tl чтобы BOLD/NC не ломали питоновский :{w}
    _box_row(f"  {_tr(BOLD+'Точка'+NC, _W_LABEL)} {_tl(BOLD+'Статус'+NC, _W_STAT)} {_tl(BOLD+'Задержка'+NC, _W_LAT)}")
    _box_row(f"  {'─'*_W_LABEL} {'─'*_W_STAT} {'─'*_W_LAT}")

    ru_ok    = 0
    ru_total = 0
    eu_ok    = 0
    eu_total = 0

    # node_id → label: check-host может вернуть полное имя или короткое
    node_label: dict[str, str] = {}
    for n, lbl in CHECK_NODES:
        node_label[n] = lbl
        node_label[n.split(".")[0]] = lbl

    for node_id, res_list in result_data.items():
        short_id = node_id.split(".")[0]
        label    = node_label.get(node_id) or node_label.get(short_id) or short_id.upper()
        is_ru    = short_id.startswith("ru")
        is_eu    = any(short_id.startswith(c) for c in ("de", "nl", "fi", "pl"))

        if res_list is None:
            stat_str = f"{DIM}ожидание{NC}"
            lat_str  = f"{DIM}—{NC}"
        else:
            # [[1, "ip", latency_s]] — успех; [[0, "ip", null]] — отклонено; [null] — таймаут
            first = res_list[0] if isinstance(res_list, list) and res_list else None
            if first and isinstance(first, list) and len(first) >= 1:
                try:
                    code = int(first[0])
                except (TypeError, ValueError):
                    code = 0
                lat_s = first[2] if len(first) > 2 and first[2] else None
                ok    = (code == 1)
                stat_str = f"{GREEN}открыт{NC}" if ok else f"{RED}заблокирован{NC}"
                try:
                    lat_str = f"{int(float(lat_s)*1000)} мс" if lat_s else f"{DIM}—{NC}"
                except (TypeError, ValueError):
                    lat_str = f"{DIM}—{NC}"
                if is_ru:
                    ru_total += 1
                    if ok: ru_ok += 1
                if is_eu:
                    eu_total += 1
                    if ok: eu_ok += 1
            else:
                # таймаут [null] — считаем как недоступен
                stat_str = f"{YELLOW}нет ответа{NC}"
                lat_str  = f"{DIM}—{NC}"
                if is_ru: ru_total += 1
                if is_eu: eu_total += 1

        _box_row(f"  {_tr(label[:_W_LABEL], _W_LABEL)}"
                 f" {_tr(stat_str, _W_STAT)}"
                 f" {_tl(lat_str, _W_LAT)}")

    _box_row(f"  {'─'*_W_LABEL} {'─'*_W_STAT} {'─'*_W_LAT}")
    _box_row()

    # ── Вердикт ──────────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}Итог:{NC}")
    _box_row()

    if ru_total > 0:
        if ru_ok == ru_total:
            _box_row(f"  {GREEN}✓ Порт {port} открыт из России ({ru_ok}/{ru_total} нод){NC}")
        elif ru_ok == 0:
            _box_row(f"  {RED}✗ Порт {port} ЗАБЛОКИРОВАН из России (0/{ru_total} нод){NC}")
            _box_row(f"  {YELLOW}  Рекомендации:{NC}")
            _box_row(f"  {YELLOW}  • Смените порт (443 → 8443 или 2053){NC}")
            _box_row(f"  {YELLOW}  • Проверьте UFW / iptables на этом сервере{NC}")
            _box_row(f"  {YELLOW}  • Уточните у хостера, не блокирует ли он входящие{NC}")
        else:
            _box_row(f"  {YELLOW}⚠  Частичная блокировка из России: "
                  f"{ru_ok}/{ru_total} нод видят порт{NC}")
            _box_row(f"  {DIM}  Возможна нестабильная работа у части пользователей{NC}")
    else:
        _box_row(f"  {YELLOW}⚠  Нет данных от российских нод — проверьте результаты EU{NC}")

    if eu_total > 0:
        eu_str = f"{GREEN}открыт{NC}" if eu_ok == eu_total else f"{YELLOW}частично{NC}"
        _box_row(f"  {DIM}Из Европы: {eu_str} ({eu_ok}/{eu_total} нод){NC}")

    log_to_file("INFO",
        f"port-block-detect: {domain}:{port} → RU {ru_ok}/{ru_total} OK, "
        f"EU {eu_ok}/{eu_total} OK")

    _box_row()
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _port_block_fallback(domain: str, port: int,
                         check_nodes: list[tuple[str, str]]) -> None:
    """
    Резервный метод когда check-host.net API недоступен:
    прямые TCP-пробы с текущего сервера (показывает только «изнутри»,
    но хоть что-то лучше пустого экрана).
    """
    _box_sep()
    _box_row(f"  {YELLOW}Резервный метод: TCP-пробы с этого сервера (не снаружи){NC}")
    _box_row()

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = domain

    for attempt in range(3):
        try:
            t0 = time.time()
            s  = socket.create_connection((ip, port), timeout=5)
            s.close()
            ms = int((time.time() - t0) * 1000)
            _box_row(f"  {GREEN}✓ TCP {domain}:{port} доступен с сервера ({ms} ms){NC}")
            _box_row(f"  {DIM}  Если клиенты не подключаются — проблема на стороне их провайдера{NC}")
            return
        except Exception:
            time.sleep(1)

    _box_row(f"  {RED}✗ TCP {domain}:{port} недоступен даже с самого сервера{NC}")
    _box_row(f"  {RED}  Проверьте UFW (ufw status) и что Xray запущен{NC}")


# =============================================================================
#  [R] СМЕНА ДОМЕНА/ПОРТА БЕЗ ПЕРЕУСТАНОВКИ
# =============================================================================
# =============================================================================
#  [H] SSH HARDENING
# =============================================================================
_SSHD_CONFIG = Path("/etc/ssh/sshd_config")
_SSHD_BACKUP = Path("/root/sshd_config.bak")


def _ssh_2fa_install() -> bool:
    """
    Устанавливает google-authenticator (libpam-google-authenticator),
    настраивает PAM и sshd для TOTP 2FA.
    Возвращает True если успешно настроено.
    """
    # Установка пакета
    if not command_exists("google-authenticator"):
        info("Устанавливаем libpam-google-authenticator…")
        r = _run(["apt-get", "install", "-y", "libpam-google-authenticator"],
                 capture=True, check=False)
        if r.returncode != 0 or not command_exists("google-authenticator"):
            warn("Не удалось установить libpam-google-authenticator")
            return False

    # Патч /etc/pam.d/sshd — добавляем google-authenticator если ещё нет
    pam_sshd = Path("/etc/pam.d/sshd")
    if pam_sshd.exists():
        pam_text = pam_sshd.read_text()
        ga_line = "auth required pam_google_authenticator.so nullok"
        if ga_line not in pam_text:
            # Вставляем в начало (перед остальными auth строками)
            pam_text = ga_line + "\n" + pam_text
            pam_sshd.write_text(pam_text)
            info("PAM /etc/pam.d/sshd обновлён")
    else:
        warn("/etc/pam.d/sshd не найден — PAM не настроен")
        return False

    # Патч sshd_config: включаем ChallengeResponseAuthentication и UsePAM
    sshd_cfg = _SSHD_CONFIG
    sshd_text = sshd_cfg.read_text()

    def _set(param: str, val: str) -> str:
        p = rf"^\s*#?\s*{re.escape(param)}\s+.*"
        line = f"{param} {val}"
        if re.search(p, sshd_text, re.MULTILINE):
            return re.sub(p, line, sshd_text, flags=re.MULTILINE)
        return sshd_text + f"\n{line}\n"

    sshd_text = _set("ChallengeResponseAuthentication", "yes")
    sshd_text = _set("AuthenticationMethods", "publickey,keyboard-interactive")
    sshd_text = _set("UsePAM", "yes")
    sshd_cfg.write_text(sshd_text)

    # Валидация конфига
    r = _run(["sshd", "-t"], capture=True, check=False)
    if r.returncode != 0:
        warn("sshd -t ошибка после правки для 2FA — откатываем")
        shutil.copy2(_SSHD_BACKUP, sshd_cfg)
        return False

    _run(["systemctl", "reload", "sshd"], check=False, quiet=True)

    print()
    _box_row(f"  {GREEN}✓ 2FA PAM настроен{NC}")
    _box_row()
    _box_row(f"  {BOLD}Последний шаг — сгенерируйте TOTP-секрет для root:{NC}")
    _box_row(f"  {CYAN}  google-authenticator -t -d -f -r 3 -R 30 -w 3{NC}")
    _box_row()
    _box_row(f"  {DIM}Отсканируйте QR-код в Google Authenticator / Aegis / Authy.{NC}")
    _box_row(f"  {YELLOW}  Не закрывайте текущую сессию, пока не проверите вход!{NC}")
    _box_row()
    ans = input(f"  Запустить google-authenticator сейчас? [Y/n]: ").strip().lower()
    if ans != "n":
        _run(["google-authenticator", "-t", "-d", "-f", "-r", "3", "-R", "30", "-w", "3"],
             check=False, quiet=False)

    log_to_file("INFO", "SSH 2FA (TOTP) настроен через google-authenticator")
    return True


def do_ssh_hardening() -> None:
    """Интерактивное укрепление SSH: смена порта, отключение паролей, AllowUsers, 2FA."""
    print()
    print()
    _box_top(f"SSH Hardening")

    if not _SSHD_CONFIG.exists():
        _box_warn("/etc/ssh/sshd_config не найден")
        return

    # --- Показываем последние SSH-входы перед изменением конфига ---
    _box_sep()
    _box_row(f"  {BOLD}Последние SSH-входы на сервер:{NC}")
    try:
        _r_last = _run(
            ["journalctl", "-u", "ssh", "-u", "sshd",
             "--no-pager", "-n", "8",
             "--output=short", "--grep", "Accepted"],
            capture=True, check=False, quiet=True
        )
        _lines = [l for l in _r_last.stdout.strip().splitlines() if l.strip()]
        if _lines:
            for _l in _lines[-8:]:
                _box_row(f"    {DIM}{_l[:100]}{NC}")
        else:
            _r_last2 = _run(["last", "-n", "5", "-F"], capture=True, check=False, quiet=True)
            for _l in _r_last2.stdout.strip().splitlines()[:5]:
                _box_row(f"    {DIM}{_l[:100]}{NC}")
    except Exception:
        _box_row(f"    {DIM}Не удалось получить данные{NC}")
    _box_sep()

    # --- Проверяем наличие SSH-ключа ---
    auth_keys = Path("/root/.ssh/authorized_keys")
    has_key = auth_keys.exists() and len(auth_keys.read_text().strip().splitlines()) > 0
    if has_key:
        _box_ok("SSH-ключ обнаружен в /root/.ssh/authorized_keys")
    else:
        _box_warn("SSH-ключ НЕ найден в /root/.ssh/authorized_keys")
        _box_warn("Отключение паролей без ключа заблокирует вас на сервере!")

    # Статус 2FA
    ga_installed = command_exists("google-authenticator")
    ga_pam_active = False
    pam_sshd = Path("/etc/pam.d/sshd")
    if pam_sshd.exists():
        ga_pam_active = "pam_google_authenticator" in pam_sshd.read_text()
    ga_str = (f"{GREEN}активна{NC}" if ga_pam_active
              else f"{YELLOW}не настроена{NC}" if ga_installed
              else f"{DIM}не установлена{NC}")
    _box_row(f"  2FA (TOTP):  {ga_str}")

    # --- Бэкап ---
    try:
        shutil.copy2(_SSHD_CONFIG, _SSHD_BACKUP)
        _box_info(f"Бэкап sshd_config → {_SSHD_BACKUP}")
    except Exception as e:
        _box_warn(f"Не удалось создать бэкап: {e}")

    sshd_text = _SSHD_CONFIG.read_text()

    cur_port = 22
    m = re.search(r"^\s*Port\s+(\d+)", sshd_text, re.MULTILINE)
    if m:
        cur_port = int(m.group(1))
    _box_row(f"  Текущий SSH-порт: {CYAN}{cur_port}{NC}")

    _box_item("1", f"Сменить порт SSH")
    _box_item("2", f"Отключить парольную аутентификацию "
              f"{RED if not has_key else GREEN}"
              f"{'(нет ключа — опасно!)' if not has_key else '(ключ есть — безопасно)'}{NC}")
    _box_item("3", f"Включить AllowUsers + MaxAuthTries=3")
    _box_item("4", f"Применить всё сразу (безопасный набор)")
    _box_item("5", f"🔐 Включить 2FA (TOTP) через Google Authenticator  "
              f"{DIM}{'(уже активна)' if ga_pam_active else ''}{NC}")
    _box_item("Q", f"Назад")
    _box_bottom()
    ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

    if ch == "q" or not ch:
        return

    # --- 2FA — отдельная ветка, не затрагивает sshd_text ---
    if ch == "5":
        if ga_pam_active:
            warn("2FA уже активна. Для перегенерации секрета запустите: google-authenticator -t -d -f -r 3 -R 30 -w 3")
            input(f"{BLUE}Нажмите Enter...{NC}")
            return
        if not has_key:
            print(f"  {RED}⚠  Для 2FA необходим SSH-ключ (иначе вы можете потерять доступ).{NC}")
            ans = input(f"  Продолжить без ключа? [y/N]: ").strip().lower()
            if ans != "y":
                warn("Отменено")
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
        ok = _ssh_2fa_install()
        if ok:
            success("SSH 2FA (TOTP) включена")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    changes = []

    def _sshd_set(param: str, value: str) -> None:
        nonlocal sshd_text
        pattern = rf"^\s*#?\s*{re.escape(param)}\s+.*"
        new_line = f"{param} {value}"
        if re.search(pattern, sshd_text, re.MULTILINE):
            sshd_text = re.sub(pattern, new_line, sshd_text, flags=re.MULTILINE)
        else:
            sshd_text += f"\n{new_line}\n"
        changes.append(f"{param} = {value}")

    new_ssh_port = cur_port

    if ch in ("1", "4"):
        raw = input(f"  Новый SSH-порт [{cur_port}]: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            new_ssh_port = int(raw)
            _sshd_set("Port", str(new_ssh_port))
        else:
            warn("Порт не изменён")

    if ch in ("2", "4"):
        if not has_key:
            ans = input(f"  {RED}Ключ не найден! Всё равно отключить пароли? [y/N]:{NC} ").strip().lower()
            if ans != "y":
                warn("Отключение паролей пропущено")
            else:
                _sshd_set("PasswordAuthentication", "no")
                _sshd_set("ChallengeResponseAuthentication", "no")
                _sshd_set("UsePAM", "no")
        else:
            _sshd_set("PasswordAuthentication", "no")
            _sshd_set("ChallengeResponseAuthentication", "no")
            _sshd_set("UsePAM", "no")

    if ch in ("3", "4"):
        raw_user = input("  AllowUsers (через пробел, Enter = root): ").strip() or "root"
        _sshd_set("AllowUsers", raw_user)
        _sshd_set("MaxAuthTries", "3")
        _sshd_set("LoginGraceTime", "30")
        _sshd_set("PermitRootLogin", "prohibit-password")

    if not changes:
        warn("Нет изменений для применения")
        return

    print()
    print(f"  {BOLD}Будут применены следующие изменения:{NC}")
    for c in changes:
        print(f"    • {c}")
    print()
    ans = input(f"  Подтвердить? [y/N]: ").strip().lower()
    if ans != "y":
        warn("Отменено")
        return

    _SSHD_CONFIG.write_text(sshd_text)

    r = _run(["sshd", "-t"], capture=True, check=False)
    if r.returncode != 0:
        warn("sshd -t вернул ошибку — восстанавливаем бэкап!")
        warn(r.stderr[:300])
        shutil.copy2(_SSHD_BACKUP, _SSHD_CONFIG)
        return

    if new_ssh_port != cur_port:
        _run(["ufw", "allow", str(new_ssh_port), "comment", "SSH hardening"],
             check=False, quiet=True)
        _run(["ufw", "delete", "allow", str(cur_port)],
             check=False, quiet=True)

    _run(["systemctl", "reload", "sshd"], check=False, quiet=True)
    success("SSH Hardening применён и sshd перезагружен")
    if new_ssh_port != cur_port:
        print(f"  {RED}⚠  Новый SSH-порт: {new_ssh_port} — не закрывайте текущую сессию!{NC}")
    print(f"  Бэкап оригинального конфига: {_SSHD_BACKUP}")
    log_to_file("INFO", f"SSH Hardening: {changes}")


# =============================================================================
#  UUID РОТАЦИЯ ПО РАСПИСАНИЮ
# =============================================================================
_UUID_CRON_TAG    = "xray-uuid-rotate"
_UUID_CRON_SCRIPT = Path("/usr/local/bin/xray-uuid-rotate.sh")


# =============================================================================
#  РОТАЦИЯ REALITY-КЛЮЧЕЙ
# =============================================================================

# =============================================================================
#  WATCHDOG — АВТОРЕСТАРТ XRAY
# =============================================================================
_WATCHDOG_TIMER   = Path("/etc/systemd/system/xray-watchdog.timer")
_WATCHDOG_SERVICE = Path("/etc/systemd/system/xray-watchdog.service")
_WATCHDOG_SCRIPT  = Path("/usr/local/bin/xray-watchdog.sh")


# =============================================================================
#  [8] РАСШИРЕННЫЙ ПРОСМОТР ЛОГОВ
# =============================================================================
def do_view_logs() -> None:
    """Интерактивный просмотр логов с выбором источника, фильтром и follow-режимом."""
    import re as _re_log

    LOG_SOURCES = {
        "1": ("Xray access",    Path("/var/log/xray/access.log")),
        "2": ("Xray error",     Path("/var/log/xray/error.log")),
        "3": ("Nginx access",   Path("/var/log/nginx/access.log")),
        "4": ("Nginx error",    Path("/var/log/nginx/error.log")),
        "5": ("Fail2ban",       Path("/var/log/fail2ban.log")),
        "6": ("Установщик",     LOG_FILE),
        "7": ("Autoupdate",     Path("/var/log/xray-autoupdate.log")),
        "8": ("Watchdog",       Path("/var/log/xray-watchdog.log")),
        "9": ("UUID rotate",    Path("/var/log/xray-uuid-rotate.log")),
    }

    # Ширина контента внутри рамки: _BOX_W минус 2 символа отступа слева ("  ")
    _LOG_INNER = _BOX_W - 2

    # ── Подсветка дат/времени ярко-белым ─────────────────────────────────────
    # Паттерны: 2024-01-15 12:34:56 | Jan 15 12:34:56 | 15/Jan/2024:12:34:56 +0000
    # | [15/Jan/2024:12:34:56 +0000] | 2024/01/15 12:34:56 | T12:34:56
    _DATETIME_RE = _re_log.compile(
        r'(\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{4}|Z)?'
        r'|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
        r'|\d{1,2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?'
        r'|\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'
    )

    def _highlight_datetime(line: str) -> str:
        """Оборачивает все вхождения дат/времени в ярко-белый BOLD."""
        return _DATETIME_RE.sub(lambda m: f"{WHITE}{BOLD}{m.group(0)}{NC}", line)

    def _log_box_row(line: str) -> None:
        """
        Выводит одну строку лога внутри рамки.
        Если видимая ширина > _LOG_INNER — разбивает на несколько строк
        с отступом-продолжением "  ↳ ".
        Подсвечивает даты/время перед выводом.
        """
        INDENT_CONT = "     "   # отступ строк-продолжений (5 символов)
        CONT_W = len(INDENT_CONT)

        # Применяем подсветку дат (до подсчёта ширины — ANSI невидимы для _wcslen)
        highlighted = _highlight_datetime(line)

        # Если строка влезает целиком — просто выводим
        if _wcslen(line) <= _LOG_INNER:
            _box_row(f"  {highlighted}")
            return

        # Разбиваем оригинальную строку (без ANSI) по пробелам,
        # попутно восстанавливая подсветку через re.sub на каждом фрагменте
        words = line.split(" ")
        current_plain = ""   # текущий накопленный кусок (без ANSI для замера)
        current_parts: list[str] = []  # слова текущей строки (оригинал, без подсветки)
        first_line = True
        max_w = _LOG_INNER
        cont_max_w = _LOG_INNER - CONT_W

        def _flush(parts: list[str], is_first: bool) -> None:
            chunk = " ".join(parts)
            chunk_hi = _highlight_datetime(chunk)
            if is_first:
                _box_row(f"  {chunk_hi}")
            else:
                _box_row(f"  {INDENT_CONT}{chunk_hi}")

        for word in words:
            word_w = _wcslen(word)
            sep_w = 1 if current_plain else 0
            avail = max_w if first_line else cont_max_w
            if _wcslen(current_plain) + sep_w + word_w <= avail:
                if current_plain:
                    current_plain += " " + word
                else:
                    current_plain = word
                current_parts.append(word)
            else:
                if current_parts:
                    _flush(current_parts, first_line)
                    first_line = False
                # Если одно слово длиннее строки — режем жёстко по символам
                while _wcslen(word) > cont_max_w:
                    cut = ""
                    cut_w = 0
                    for ch in word:
                        cw = _wcslen(ch)
                        if cut_w + cw > cont_max_w:
                            break
                        cut += ch
                        cut_w += cw
                    cut_hi = _highlight_datetime(cut)
                    _box_row(f"  {INDENT_CONT}{cut_hi}")
                    word = word[len(cut):]
                    first_line = False
                current_plain = word
                current_parts = [word]

        if current_parts:
            _flush(current_parts, first_line)

    # ── Меню выбора лога ──────────────────────────────────────────────────────
    os.system("clear")
    print()
    _box_top("Просмотр логов")
    for k, (name, path) in LOG_SOURCES.items():
        exists = f"{GREEN}✓{NC}" if path.exists() else f"{RED}✗{NC}"
        # Путь может быть длинным — выводим имя и путь в одну строку,
        # но если не влезает — путь на строку ниже с отступом
        label_plain = f"✓ {name}  {path}" if path.exists() else f"✗ {name}  {path}"
        # Ключ занимает: "  [k]  " = 7 символов видимых
        KEY_OVERHEAD = 7
        if len(label_plain) + KEY_OVERHEAD <= _BOX_W:
            _box_item(f"{k}", f"{exists} {name}  {DIM}{path}{NC}")
        else:
            _box_item(f"{k}", f"{exists} {name}")
            _box_row(f"       {DIM}{path}{NC}")
    _box_bottom()

    ch = input(f"  Выбор лога [1]: ").strip() or "1"
    if ch not in LOG_SOURCES:
        warn("Неверный выбор")
        return

    name, log_path = LOG_SOURCES[ch]
    if not log_path.exists():
        warn(f"Файл не найден: {log_path}")
        return

    # Количество строк
    raw_lines = input(f"  Строк [50]: ").strip() or "50"
    n_lines = int(raw_lines) if raw_lines.isdigit() else 50

    # Фильтр
    flt = input(f"  Фильтр (grep-слово, Enter = без фильтра): ").strip()

    # Режим follow
    follow = input(f"  Режим follow (tail -f)? [y/N]: ").strip().lower() == "y"

    print()
    # Заголовок: имя лога + путь — с переносом если не влезает
    title_plain = f"{name}  {log_path}"
    if _wcslen(title_plain) <= _BOX_W - 4:
        _box_top(f"{name}  {DIM}{log_path}{NC}")
    else:
        _box_top(f"{name}")
        _box_row(f"  {DIM}{log_path}{NC}")
        _box_sep()
    _box_row()

    if follow:
        _box_row(f"  {DIM}(Ctrl+C для выхода){NC}")
        _box_row()
        cmd = ["tail", f"-{n_lines}", "-f", str(log_path)]
        if flt:
            try:
                p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                p2 = subprocess.Popen(
                    ["grep", "--line-buffered", flt],
                    stdin=p1.stdout, stdout=None
                )
                p1.stdout.close()
                p2.wait()
            except KeyboardInterrupt:
                pass
            finally:
                try:
                    p1.terminate()
                except Exception:
                    pass
        else:
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                pass
    else:
        lines = log_path.read_text(errors="replace").splitlines()
        if flt:
            lines = [l for l in lines if flt.lower() in l.lower()]
        lines = lines[-n_lines:]
        for _l in lines:
            _log_box_row(_l)
        _box_row()
        _box_row(f"  {DIM}Показано {len(lines)} строк{NC}")
        _box_row()
        _box_bottom()


# =============================================================================
#  ПРОВЕРКА ДОСТУПНОСТИ ДОМЕНА СНАРУЖИ
# =============================================================================
def do_check_domain_external() -> None:
    """
    Проверяет DNS-резолвинг, HTTP, HTTPS и доступность VLESS-порта снаружи.
    """
    _box_row()

    # Берём домен из state или спрашиваем
    domain = ""
    port   = 443
    try:
        if STATE_FILE.exists():
            st = json.loads(STATE_FILE.read_text())
            domain = st.get("domain", "")
            port   = st.get("server_port", 443)
    except Exception:
        pass

    if not domain:
        domain = input("  Домен для проверки: ").strip()
    if not domain:
        _box_warn("Домен не указан")
        return

    _box_row(f"  Домен: {CYAN}{domain}{NC}  |  Порт: {CYAN}{port}{NC}")

    # 1. DNS через Google 8.8.8.8
    _box_info("  [1/4] DNS-резолвинг через 8.8.8.8 ...")
    r = _run(
        ["dig", "+short", f"@8.8.8.8", domain, "A"],
        capture=True, check=False
    )
    if r.returncode == 0 and r.stdout.strip():
        resolved_ip = r.stdout.strip().splitlines()[-1]
        _box_ok(f"  DNS → {resolved_ip}")
    else:
        _box_warn(f"  DNS: домен не резолвится через 8.8.8.8!")
        resolved_ip = ""

    # 2. HTTP /.well-known/
    _box_info("  [2/4] HTTP 200 на /.well-known/ ...")
    r = _run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "10",
         f"http://{domain}/.well-known/"],
        capture=True, check=False
    )
    code = r.stdout.strip()
    if code in ("200", "301", "302", "403", "404"):
        _box_ok(f"  HTTP доступен (код {code})")
    else:
        _box_warn(f"  HTTP недоступен или таймаут (код {code or 'нет ответа'})")

    # 3. HTTPS TLS-рукопожатие
    _box_info("  [3/4] HTTPS TLS-рукопожатие ...")
    r = _run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{ssl_verify_result}",
         "--max-time", "10",
         f"https://{domain}/"],
        capture=True, check=False
    )
    parts = r.stdout.strip().split()
    if r.returncode == 0 and parts:
        tls_code   = parts[0]
        tls_verify = parts[1] if len(parts) > 1 else "?"
        tls_ok = tls_verify == "0"
        colour = GREEN if tls_ok else YELLOW
        _box_row(f"    {colour}HTTPS код: {tls_code}  TLS verify: {'OK' if tls_ok else 'ОШИБКА ('+tls_verify+')'}{NC}")
    else:
        _box_warn(f"  HTTPS недоступен (returncode={r.returncode})")

    # 4. TCP доступность VLESS-порта снаружи
    _box_info(f"  [4/4] TCP доступность порта {port} (через curl --connect-to) ...")
    target_ip = resolved_ip or domain
    r = _run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{errormsg}",
         "--max-time", "8",
         f"--connect-to", f"{domain}:{port}:{target_ip}:{port}",
         f"https://{domain}:{port}/"],
        capture=True, check=False
    )
    # returncode 0 или TLS error — порт открыт; Connection refused/timed out — закрыт
    if r.returncode in (0, 35, 60):  # 35=SSL, 60=cert verify — порт отвечает
        _box_ok(f"  Порт {port} доступен снаружи")
    else:
        errmsg = r.stdout.strip() or r.stderr.strip()
        _box_warn(f"  Порт {port} недоступен: {errmsg or 'нет ответа'}")

    _box_row()
    log_to_file("INFO", f"External domain check: {domain}:{port}, DNS={resolved_ip}")


# =============================================================================
#  FAILOVER СТАТУС EXIT-НОД
# =============================================================================
_FAILOVER_LOG      = Path("/var/log/xray-failover.log")
_FAILOVER_SCRIPT   = Path("/usr/local/bin/xray-failover-watch.sh")
_FAILOVER_CRON     = Path("/etc/cron.d/xray-failover-watch")
_FAILOVER_STATE    = Path("/var/lib/xray-installer/failover.json")


# =============================================================================
#  ГЕНЕРАЦИЯ CLASH META / SING-BOX КОНФИГА
# =============================================================================
def do_generate_client_config() -> None:
    """Генерирует готовый YAML для Clash Meta и JSON для Sing-box из state.json."""
    print()
    print()
    _box_top(f"Генерация клиентских конфигов")

    if not STATE_FILE.exists():
        _box_warn("state.json не найден — сначала выполните установку")
        return

    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _box_warn(f"Не удалось прочитать state.json: {e}")
        return

    domain    = state.get("domain", "")
    port      = state.get("server_port", 443)
    vuuid     = state.get("uuid", "")
    pub_key   = state.get("public_key", "")
    short_id  = state.get("short_id", "")
    proto     = state.get("protocol_mode", "reality")
    fp        = state.get("fingerprint", "chrome")
    # === FIX 2: SNI строго из reality_dest (AWG/REALITY) или domain (классика/xHTTP) ===
    # Ключ "sni" не сохраняется в state.json — state.get("sni", domain) всегда давал domain.
    # Важно: reality_dest и awg_exit_enabled сохраняются ТОЛЬКО при INSTALL_MODE="B" (AWG/chain).
    # При Mode A эти ключи отсутствуют → дефолты False/"" → sni = domain. Это верно.
    _install_mode = state.get("install_mode", "A")
    _awg_exit = state.get("awg_exit_enabled", False) and _install_mode == "B"
    _reality_dest = state.get("reality_dest", "")
    if proto == "reality" and _awg_exit and _reality_dest:
        sni = _reality_dest   # Mode B + AWG: SNI = домен маскировки (чужой сайт)
    elif proto == "reality":
        sni = domain          # Mode A классика или Mode B chain: SNI = собственный домен
    else:
        sni = domain          # xHTTP TLS: SNI = собственный домен
    # === END FIX 2 ===
    xhttp_path = state.get("xhttp_path", "/")
    mode      = state.get("install_mode", "A")
    xtls_flow_val = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    if not domain or not vuuid:
        _box_warn("Домен или UUID не найдены в state.json")
        return

    # --- Clash Meta YAML ---
    if proto == "reality":
        clash_proxy = textwrap.dedent(f"""\
            proxies:
              - name: VLESS-Reality
                type: vless
                server: {domain}
                port: {port}
                uuid: {vuuid}
                network: tcp
                tls: true
                udp: true
                flow: {xtls_flow_val}
                reality-opts:
                  public-key: {pub_key}
                  short-id: {short_id}
                client-fingerprint: {fp}
                servername: {sni}

            proxy-groups:
              - name: Proxy
                type: select
                proxies:
                  - VLESS-Reality

            rules:
              - MATCH,Proxy
        """)
    else:  # xhttp
        clash_proxy = textwrap.dedent(f"""\
            proxies:
              - name: VLESS-xHTTP
                type: vless
                server: {domain}
                port: {port}
                uuid: {vuuid}
                network: http
                tls: true
                udp: false
                http-opts:
                  path: [{xhttp_path}]
                client-fingerprint: {fp}
                servername: {domain}

            proxy-groups:
              - name: Proxy
                type: select
                proxies:
                  - VLESS-xHTTP

            rules:
              - MATCH,Proxy
        """)

    # --- Sing-box JSON ---
    if proto == "reality":
        singbox = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": vuuid,
                **( {"flow": xtls_flow_val} if xtls_flow_val else {} ),
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": fp},
                    "reality": {
                        "enabled": True,
                        "public_key": pub_key,
                        "short_id": short_id,
                    }
                }
            }]
        }
    else:
        singbox = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": vuuid,
                "transport": {"type": "http", "path": xhttp_path},
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": fp},
                }
            }]
        }

    # Сохраняем файлы
    out_dir = Path("/root/xray-client-configs")
    out_dir.mkdir(exist_ok=True)
    clash_file   = out_dir / "clash-meta.yaml"
    singbox_file = out_dir / "sing-box.json"

    clash_file.write_text(clash_proxy)
    singbox_file.write_text(json.dumps(singbox, indent=2, ensure_ascii=False))

    _box_ok(f"Clash Meta → {clash_file}")
    _box_ok(f"Sing-box   → {singbox_file}")
    _box_row()
    _box_row(f"  {DIM}Скопируйте файлы на клиентское устройство:{NC}")
    _box_row(f"    {CYAN}scp root@{domain}:{clash_file} .{NC}")
    _box_row(f"    {CYAN}scp root@{domain}:{singbox_file} .{NC}")
    _box_bottom()
    log_to_file("INFO", f"Client configs generated: {clash_file}, {singbox_file}")


# =============================================================================
#  ДАШБОРД СИСТЕМНЫХ РЕСУРСОВ
# =============================================================================
def do_system_dashboard() -> None:
    """Дашборд CPU / RAM / Disk / Uptime / Сервисы — обновляется каждые 3 с."""
    print(f"  {DIM}(Ctrl+C для выхода){NC}")
    time.sleep(0.5)

    def _read_cpu() -> float:
        try:
            lines = Path("/proc/stat").read_text().splitlines()
            vals = list(map(int, lines[0].split()[1:]))
            idle = vals[3]
            total = sum(vals)
            return idle, total
        except Exception:
            return 0, 1

    prev_idle, prev_total = _read_cpu()
    time.sleep(0.5)

    try:
        while True:
            os.system("clear")
            now = datetime.now().strftime("%H:%M:%S")

            # CPU
            cur_idle, cur_total = _read_cpu()
            diff_idle  = cur_idle  - prev_idle
            diff_total = cur_total - prev_total
            cpu_pct = 100.0 * (1 - diff_idle / max(diff_total, 1))
            prev_idle, prev_total = cur_idle, cur_total

            # RAM
            ram_pct = 0.0
            ram_used_mb = 0
            ram_total_mb = 0
            try:
                meminfo = {}
                for line in Path("/proc/meminfo").read_text().splitlines():
                    k, v = line.split(":", 1)
                    meminfo[k.strip()] = int(v.strip().split()[0])
                ram_total_mb = meminfo.get("MemTotal", 0) // 1024
                ram_avail_mb = meminfo.get("MemAvailable", 0) // 1024
                ram_used_mb  = ram_total_mb - ram_avail_mb
                ram_pct = 100.0 * ram_used_mb / max(ram_total_mb, 1)
            except Exception:
                pass

            # Disk
            disk_pct = 0.0
            try:
                r = _run(["df", "-h", "/"], capture=True, check=False)
                parts = r.stdout.splitlines()[-1].split()
                disk_pct = float(parts[4].replace("%", "")) if len(parts) >= 5 else 0
                disk_used  = parts[2]
                disk_total = parts[1]
            except Exception:
                disk_used = disk_total = "?"

            # Uptime
            try:
                up_s = float(Path("/proc/uptime").read_text().split()[0])
                up_h = int(up_s // 3600)
                up_m = int((up_s % 3600) // 60)
                uptime_str = f"{up_h}ч {up_m}м"
            except Exception:
                uptime_str = "?"

            # Активные соединения Xray
            xray_conns = "?"
            try:
                r = _run(["ss", "-tnp"], capture=True, check=False)
                xray_conns = str(sum(1 for l in r.stdout.splitlines() if "xray" in l))
            except Exception:
                pass

            def _bar(pct: float, width: int = 30) -> str:
                filled = max(0, min(width, int(pct * width / 100)))
                empty  = width - filled
                colour = GREEN if pct < 60 else YELLOW if pct < 85 else RED
                return f"{colour}{'▓' * filled}{NC}{DIM}{'░' * empty}{NC} {pct:.1f}%"

            print()
            _box_top(f"Системный дашборд  {now}")
            _box_row(f"  CPU:      {_bar(cpu_pct)}")
            _box_row(f"  RAM:      {_bar(ram_pct)}  {DIM}({ram_used_mb}/{ram_total_mb} МБ){NC}")
            _box_row(f"  Disk /:   {_bar(disk_pct)}  {DIM}({disk_used}/{disk_total}){NC}")
            _box_row(f"  Uptime:   {CYAN}{uptime_str}{NC}")
            _box_row(f"  Xray соединений: {CYAN}{xray_conns}{NC}")

            # Статус сервисов
            for svc in ("caddy-naive", "mita", "hydra-sub-server", "dnscrypt-proxy"):
                r = _run(["systemctl", "is-active", svc], capture=True, check=False)
                st = r.stdout.strip()
                colour = GREEN if st == "active" else YELLOW
                _box_row(f"  {svc:<20} {colour}{st}{NC}")

            _box_row(f"  {DIM}Обновление каждые 3с  |  Ctrl+C для выхода{NC}")
            _box_bottom()
            time.sleep(3)

    except KeyboardInterrupt:
        print()


# =============================================================================
#  МАСТЕР ПОЛНОЙ ДИАГНОСТИКИ
# =============================================================================
# =============================================================================

TRAFFIC_LIMITS_FILE = Path("/var/lib/xray-installer/traffic_limits.json")
TTL_FILE = Path("/var/lib/xray-installer/ttl_users.json")

def _get_subscription_users_list() -> list[dict]:
    """Возвращает список пользователей из системы подписок (state.json)."""
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    users_db = state.get("users", {})
    if not users_db:
        # Fallback to sub_tokens for migration
        sub_tokens = state.get("sub_tokens", {})
        users_db = {}
        for email, token in sub_tokens.items():
            users_db[email] = {"token": token}
    
    users = []
    for email, udata in users_db.items():
        users.append({
            "email": email,
            "uuid": udata.get("token", ""),
            "name": email,
            "limit_gb": udata.get("limit_gb", 0),
            "expires_at": udata.get("expires_at", ""),
            "is_blocked": udata.get("is_blocked", False),
            "block_reason": udata.get("block_reason", "")
        })
    return users


def install_sync_agent() -> None:
    """Устанавливает oneshot-службу и таймер systemd для проверки лимитов и TTL."""
    try:
        agent_src = Path("/opt/vless-ultimate/vless_installer/modules/hydra_sync_agent.py")
        agent_dst = Path("/usr/local/bin/hydra-sync-agent.py")
        
        # 1. Копируем скрипт агента
        if agent_src.exists():
            import shutil
            shutil.copy2(agent_src, agent_dst)
            agent_dst.chmod(0o755)
            
        # 2. Пишем systemd service
        service_content = textwrap.dedent("""\
            [Unit]
            Description=Hydra User Traffic & TTL Sync Agent
            After=network.target

            [Service]
            Type=oneshot
            ExecStart=/usr/bin/python3 /usr/local/bin/hydra-sync-agent.py
            StandardOutput=journal
            StandardError=journal
        """)
        Path("/etc/systemd/system/hydra-sync-agent.service").write_text(service_content)
        
        # 3. Пишем systemd timer
        timer_content = textwrap.dedent("""\
            [Unit]
            Description=Run Hydra User Traffic & TTL Sync Agent every 5 minutes

            [Timer]
            OnBootSec=1min
            OnUnitActiveSec=5min
            Unit=hydra-sync-agent.service

            [Install]
            WantedBy=timers.target
        """)
        Path("/etc/systemd/system/hydra-sync-agent.timer").write_text(timer_content)
        
        # 4. Перезагружаем демоны и запускаем
        _run(["systemctl", "daemon-reload"], check=False, quiet=True)
        _run(["systemctl", "enable", "hydra-sync-agent.timer"], check=False, quiet=True)
        _run(["systemctl", "start", "hydra-sync-agent.timer"], check=False, quiet=True)
        
        # 5. Чистим старый крон
        Path("/etc/cron.d/xray-traffic-limits").unlink(missing_ok=True)
        Path("/usr/local/bin/xray-traffic-limits.sh").unlink(missing_ok=True)
        Path("/etc/cron.d/xray-ttl-check").unlink(missing_ok=True)
        Path("/usr/local/bin/xray-ttl-check.sh").unlink(missing_ok=True)
        
        success("Systemd-таймер фоновой проверки лимитов установлен (каждые 5 мин)")
    except Exception as e:
        warn(f"Ошибка установки sync-агента: {e}")


def uninstall_sync_agent() -> None:
    """Удаляет systemd службу и таймер sync-агента."""
    try:
        _run(["systemctl", "stop", "hydra-sync-agent.timer"], check=False, quiet=True)
        _run(["systemctl", "disable", "hydra-sync-agent.timer"], check=False, quiet=True)
        
        Path("/etc/systemd/system/hydra-sync-agent.timer").unlink(missing_ok=True)
        Path("/etc/systemd/system/hydra-sync-agent.service").unlink(missing_ok=True)
        Path("/usr/local/bin/hydra-sync-agent.py").unlink(missing_ok=True)
        
        _run(["systemctl", "daemon-reload"], check=False, quiet=True)
        success("Systemd-таймер фоновой проверки лимитов удален")
    except Exception as e:
        warn(f"Ошибка удаления sync-агента: {e}")


def sync_agent_active() -> bool:
    """Проверяет активен ли таймер sync-агента."""
    return Path("/etc/systemd/system/hydra-sync-agent.timer").exists()


def do_manage_traffic_limits() -> None:
    """Меню управления лимитами трафика пользователей."""
    from vless_installer.modules.user_lifecycle import get_user_cumulative_traffic, check_and_sync_all_users_limits, sync_user_lifecycle
    while True:
        os.system("clear")
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
        users_db = state.setdefault("users", {})
        users = _get_subscription_users_list()

        print()
        _box_top(f"Лимиты трафика пользователей")

        active = sync_agent_active()
        _box_row(f"  Systemd-таймер: {''+GREEN+'ВКЛЮЧЕН (каждые 5 мин)'+NC if active else ''+YELLOW+'ОТКЛЮЧЕН'+NC}")

        if not users:
            _box_row(f"  {DIM}Пользователей нет{NC}")
        else:
            _EM_W = max(16, _BOX_W - 2 - 4 - 12 - 20 - 10 - 4)
            _box_row(f"  {'#':<4} {'Email':<{_EM_W}} {'Лимит':<12} {'Использовано':<20} {'Статус'}")
            _box_row(f"  {'─'*4} {'─'*_EM_W} {'─'*12} {'─'*20} {'─'*10}")
            for i, u in enumerate(users, 1):
                email = u["email"]
                limit_gb = u["limit_gb"]
                
                # Считаем живой накопленный трафик
                used_bytes = get_user_cumulative_traffic(email, state)
                used_gb = used_bytes / 1024 ** 3
                
                disabled = u["is_blocked"]
                email_disp = email if len(email) <= _EM_W else email[:_EM_W - 1] + "…"
                if limit_gb:
                    pct = min(100, used_gb / limit_gb * 100)
                    col = RED if pct >= 90 else YELLOW if pct >= 70 else GREEN
                    lim_str  = f"{limit_gb} ГБ"
                    used_str = f"{col}{used_gb:.2f} ГБ ({pct:.0f}%){NC}"
                    st_str   = f"{RED}ОТКЛЮЧЁН{NC}" if disabled else f"{GREEN}активен{NC}"
                else:
                    lim_str  = f"{DIM}нет{NC}"
                    used_str = f"{col if used_gb > 0 else DIM}{used_gb:.2f} ГБ{NC}"
                    st_str   = f"{RED}ЗАБЛОК{NC}" if disabled else f"{GREEN}активен{NC}"
                _box_row(f"  {i:<4} {email_disp:<{_EM_W}} {lim_str:<12} {used_str:<20} {st_str}")
        _box_item("1", f"Задать/изменить лимит пользователя")
        _box_item("2", f"Снять лимит и восстановить пользователя")
        _box_item("3", f"Сбросить счётчики (новый месяц)")
        _box_item("4", f"{'Отключить' if active else 'Включить'} авто-проверку (systemd timer 5 мин)")
        _box_item("5", f"Проверить лимиты прямо сейчас")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            print()
            if not users:
                warn("Нет пользователей")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            _box_top("Выберите пользователя")
            for i, u in enumerate(users, 1):
                _box_item(f"{i}", f"{u['email']}")
            _box_bottom()
            raw = input("  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(users)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            u = users[int(raw)-1]
            email = u["email"]
            raw_gb = input(f"  Лимит трафика в ГБ (0 = без лимита): ").strip()
            if not raw_gb.isdigit():
                warn("Введите число")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            limit_gb = int(raw_gb)
            
            # Читаем свежий стейт
            state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
            users_db = state.setdefault("users", {})
            user_data = users_db.setdefault(email, {})
            user_data["limit_gb"] = limit_gb
            
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
            
            # Если лимит увеличен/снят и пользователь был заблокирован из-за лимита, разблокируем
            if user_data.get("is_blocked"):
                sync_user_lifecycle(email, "unblock")
            else:
                sync_user_lifecycle(email, "add")
                
            success(f"Лимит {limit_gb} ГБ задан для {email}" if limit_gb else f"Лимит снят для {email}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw = input("  Номер пользователя для восстановления: ").strip()
            target_email = ""
            if raw.isdigit() and 1 <= int(raw) <= len(users):
                target_email = users[int(raw)-1]["email"]
            else:
                target_email = raw
                
            state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
            users_db = state.setdefault("users", {})
            if target_email in users_db:
                # Снимаем лимит
                users_db[target_email]["limit_gb"] = 0
                STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
                sync_user_lifecycle(target_email, "unblock")
                success(f"Пользователь {target_email} восстановлен (лимит сброшен)")
            else:
                warn("Пользователь не найден")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            ans = input(f"  {YELLOW}Сбросить счётчики для всех? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
                users_db = state.setdefault("users", {})
                for email, udata in users_db.items():
                    udata["traffic_accumulated"] = 0
                    udata["traffic_baseline"] = udata.get("previous_live", 0)
                    if udata.get("is_blocked") and "Превышен лимит трафика" in udata.get("block_reason", ""):
                        # Разблокируем
                        sync_user_lifecycle(email, "unblock")
                STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
                success("Счётчики сброшены, пользователи разблокированы")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            if active:
                uninstall_sync_agent()
            else:
                install_sync_agent()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            print()
            info("Проверка лимитов трафика...")
            check_and_sync_all_users_limits()
            success("Проверка завершена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


def _ttl_expires_str(iso: str) -> str:
    """Возвращает строку вида '3д 14ч' до истечения или 'ИСТЁК'."""
    try:
        exp = datetime.fromisoformat(iso)
        now = datetime.now(timezone.utc)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = exp - now
        total = int(delta.total_seconds())
        if total <= 0:
            return "ИСТЁК"
        days  = total // 86400
        hours = (total % 86400) // 3600
        mins  = (total % 3600)  // 60
        if days > 0:
            return f"{days}д {hours}ч"
        if hours > 0:
            return f"{hours}ч {mins}м"
        return f"{mins}м"
    except Exception:
        return "?"


def _ttl_is_expired(iso: str) -> bool:
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp
    except Exception:
        return False


def _ttl_expires_within_hours(iso: str, hours: int) -> bool:
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = (exp - now).total_seconds()
        return 0 < delta <= hours * 3600
    except Exception:
        return False


def do_manage_ttl_users() -> None:
    """
    Меню управления временными пользователями (TTL).
    Интегрируется в подменю пользователей.
    """
    from vless_installer.modules.user_lifecycle import check_and_sync_all_users_limits, sync_user_lifecycle
    from datetime import timedelta
    while True:
        os.system("clear")
        print()
        users = _get_subscription_users_list()
        ttl_users = [u for u in users if u["expires_at"]]

        _box_top("⏱  ВРЕМЕННЫЕ ПОЛЬЗОВАТЕЛИ (TTL)")
        _box_row()

        active = sync_agent_active()
        timer_str = f"{GREEN}ВКЛЮЧЁН (каждые 5 мин){NC}" if active else f"{YELLOW}ОТКЛЮЧЁН{NC}"
        _box_row(f"  Авто-проверка: {timer_str}")
        _box_sep()

        if not ttl_users:
            _box_row(f"  {DIM}Временных пользователей нет{NC}")
        else:
            _box_row(
                f"  {'#':<4} {'Email':<26} {'Истекает':<18} {'Осталось':<10} {'Статус'}"
            )
            _box_row(
                f"  {'─'*4} {'─'*26} {'─'*18} {'─'*10} {'─'*14}"
            )
            for i, u in enumerate(ttl_users, 1):
                email = u["email"]
                iso = u["expires_at"]
                left = _ttl_expires_str(iso)
                expired = _ttl_is_expired(iso)
                warn24 = _ttl_expires_within_hours(iso, 24) and not expired
                is_blocked_now = u["is_blocked"]

                try:
                    exp_dt = datetime.fromisoformat(iso)
                    exp_show = exp_dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    exp_show = iso[:16]

                if is_blocked_now:
                    status = f"{RED}ЗАБЛОКИРОВАН{NC}"
                    left_c = f"{RED}{left}{NC}"
                elif expired:
                    status = f"{RED}ИСТЁК{NC}"
                    left_c = f"{RED}{left}{NC}"
                elif warn24:
                    status = f"{YELLOW}скоро{NC}"
                    left_c = f"{YELLOW}{left}{NC}"
                else:
                    status = f"{GREEN}активен{NC}"
                    left_c = f"{GREEN}{left}{NC}"

                _box_row(
                    f"  {i:<4} {email:<26} {exp_show:<18} {left_c:<10} {status}"
                )

        _box_sep()
        _box_row()
        _box_item("1", f"Назначить TTL пользователю")
        _box_item("2", f"Продлить / изменить срок  {DIM}(автоматически разблокирует){NC}")
        _box_item("3", f"Сделать пользователя постоянным (снять TTL)")
        _box_item("4", f"Проверить истёкших прямо сейчас")
        _box_item("5",
            f"{'Отключить' if active else 'Включить'} авто-проверку (systemd timer 5 мин)"
        )
        _box_item("6", f"🔒 Заблокировать пользователя вручную")
        _box_item("7", f"🔓 Разблокировать пользователя")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            print()
            if not users:
                warn("Нет пользователей. Сначала добавьте через менеджер пользователей.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            no_ttl = [u for u in users if not u["expires_at"]]
            if not no_ttl:
                warn("У всех пользователей уже есть TTL.")
                info("Используйте [2] для продления или [3] чтобы снять ограничение.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _box_top("Выбор пользователя")
            for i, u in enumerate(no_ttl, 1):
                _box_row(
                    f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}"
                    f"  {u.get('name', u['email']):<20}"
                    f"  {DIM}{u['email']}{NC}"
                )
            _box_bottom()
            raw = input(f"  Номер: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(no_ttl)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            target = no_ttl[int(raw) - 1]
            email  = target["email"]

            print()
            presets = {"1": 1, "2": 3, "3": 7, "4": 14, "5": 30, "6": 90}
            _box_top(f"Установить срок действия для: {email}")
            for k, v in presets.items():
                _box_item(k, f"{v} дней")
            _box_item("7", "Ввести своё количество дней")
            _box_bottom()
            raw2 = input(f"  Выбор: ").strip()

            if raw2 in presets:
                days = presets[raw2]
            elif raw2 == "7":
                d = input("  Количество дней (1–3650): ").strip()
                if not (d.isdigit() and 1 <= int(d) <= 3650):
                    warn("Неверное значение")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                days = int(d)
            else:
                warn("Отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
            users_db = state.setdefault("users", {})
            user_data = users_db.setdefault(email, {})
            
            expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            user_data["expires_at"] = expires_at
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))

            if user_data.get("is_blocked"):
                sync_user_lifecycle(email, "unblock")
            else:
                sync_user_lifecycle(email, "add")

            if not active:
                info("Sync-агент ещё не установлен — устанавливаю автоматически...")
                install_sync_agent()

            success(f"TTL назначен: {email} → {days} дней")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            if not ttl_users:
                warn("Нет TTL-пользователей")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _box_top("Выбор пользователя")
            for i, u in enumerate(ttl_users, 1):
                _box_row(f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}  {u['email']:<30}  осталось: {_ttl_expires_str(u['expires_at'])}")
            _box_row()
            _box_bottom()

            raw = input("  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(ttl_users)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            email = ttl_users[int(raw) - 1]["email"]

            print()
            presets = {"1": 1, "2": 3, "3": 7, "4": 14, "5": 30, "6": 90}
            _box_top(f"Новый срок от текущего момента: {email}")
            for k, v in presets.items():
                _box_item(k, f"{v} дней с сейчас")
            _box_item("7", "Ввести количество дней")
            _box_bottom()
            raw2 = input("  Выбор: ").strip()

            if raw2 in presets:
                days = presets[raw2]
            elif raw2 == "7":
                d = input("  Дней (1–3650): ").strip()
                if not (d.isdigit() and 1 <= int(d) <= 3650):
                    warn("Неверное значение")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                days = int(d)
            else:
                warn("Отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
            users_db = state.setdefault("users", {})
            user_data = users_db.setdefault(email, {})
            expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            user_data["expires_at"] = expires_at
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))

            sync_user_lifecycle(email, "unblock")
            success(f"Блокировка снята, срок продлён: {email} → {days} дней")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            if not ttl_users:
                warn("Нет TTL-пользователей")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _box_top("Выбор пользователя")
            for i, u in enumerate(ttl_users, 1):
                blk  = f"  {RED}[заблокирован]{NC}" if u["is_blocked"] else ""
                _box_row(f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}  {u['email']:<30}  осталось: {_ttl_expires_str(u['expires_at'])}{blk}")
            _box_row()
            _box_bottom()

            raw = input("  Номер: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(ttl_users)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            email = ttl_users[int(raw) - 1]["email"]

            ans = input(
                f"  {YELLOW}Сделать '{email}' постоянным (TTL будет снят, блокировка снята)? [y/N]:{NC} "
            ).strip().lower()
            if ans == "y":
                state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
                users_db = state.setdefault("users", {})
                if email in users_db:
                    users_db[email]["expires_at"] = ""
                    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
                    sync_user_lifecycle(email, "unblock")
                    success(f"TTL снят: {email} теперь постоянный пользователь")
            else:
                info("Отмена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            print()
            info("Проверка истёкших TTL-пользователей...")
            check_and_sync_all_users_limits()
            success("Проверка завершена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            print()
            if active:
                uninstall_sync_agent()
            else:
                install_sync_agent()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "6":
            print()
            active_ttl = [u for u in ttl_users if not u["is_blocked"]]
            if not active_ttl:
                warn("Нет активных TTL-пользователей для блокировки")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _box_top("Заблокировать пользователя")
            for i, u in enumerate(active_ttl, 1):
                _box_row(f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}  {u['email']:<30}  осталось: {_ttl_expires_str(u['expires_at'])}")
            _box_row()
            _box_bottom()

            raw = input("  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(active_ttl)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            email = active_ttl[int(raw) - 1]["email"]

            ans = input(
                f"  {YELLOW}Заблокировать '{email}'? [y/N]:{NC} "
            ).strip().lower()
            if ans == "y":
                sync_user_lifecycle(email, "block")
                success(f"Пользователь {email} заблокирован.")
            else:
                info("Отмена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "7":
            print()
            blocked_ttl = [u for u in ttl_users if u["is_blocked"]]
            if not blocked_ttl:
                info("Нет заблокированных пользователей")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _box_top("Разблокировать пользователя")
            for i, u in enumerate(blocked_ttl, 1):
                exp_expired = _ttl_is_expired(u["expires_at"])
                left = _ttl_expires_str(u["expires_at"])
                left_c = f"{RED}{left}{NC}" if exp_expired else f"{YELLOW}{left}{NC}"
                note = f"  {RED}срок истёк — рекомендуется продлить [2]{NC}" if exp_expired else ""
                _box_row(f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}  {u['email']:<30}  {left_c}{note}")
            _box_row()
            _box_bottom()

            raw = input("  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(blocked_ttl)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            email = blocked_ttl[int(raw) - 1]["email"]

            if _ttl_is_expired(blocked_ttl[int(raw) - 1]["expires_at"]):
                warn(f"Срок действия {email} уже истёк. После разблокировки он снова")
                warn("заблокируется при следующей проверке (таймер 5 мин).")
                warn("Рекомендуется продлить срок через [2] или снять TTL через [3].")
                ans = input(
                    f"  {YELLOW}Всё равно разблокировать временно? [y/N]:{NC} "
                ).strip().lower()
            else:
                ans = input(
                    f"  {YELLOW}Разблокировать '{email}'? [y/N]:{NC} "
                ).strip().lower()

            if ans == "y":
                sync_user_lifecycle(email, "unblock")
                success(f"Пользователь {email} разблокирован")
            else:
                info("Отмена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")


def _ttl_check_and_expire() -> int:
    """Обертка для обратной совместимости с main.py --ttl-check."""
    from vless_installer.modules.user_lifecycle import check_and_sync_all_users_limits
    state_before = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    blocked_before = sum(1 for u in state_before.get("users", {}).values() if u.get("is_blocked"))
    
    check_and_sync_all_users_limits()
    
    state_after = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    blocked_after = sum(1 for u in state_after.get("users", {}).values() if u.get("is_blocked"))
    
    return max(0, blocked_after - blocked_before)


def do_share_config_server() -> None:
    """
    Поднимает одноразовый HTTP-сервер на случайном порту с токеном.
    Пользователь заходит с телефона, получает QR и ссылки, сервер завершается.
    """
    print()
    print()
    _box_top(f"Разовая ссылка для передачи конфига")

    if not STATE_FILE.exists():
        _box_warn("state.json не найден — сначала выполните установку")
        return
    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception as e:
        _box_warn(f"Не удалось прочитать state.json: {e}")
        return

    links: list[dict] = []
    try:
        sub_domain = state.get("sub_domain") or state.get("domain", "")
        sub_tokens = state.get("sub_tokens", {})
        for email, token in list(sub_tokens.items())[:8]:
            if sub_domain and token:
                url = f"https://{sub_domain}/sub/{token}"
                links.append({"name": email, "links": [url]})
        if not links and sub_domain:
            links.append({
                "name": "info",
                "links": [f"https://{sub_domain}/ — портал подписок HYDRA"],
            })
    except Exception as e:
        _box_warn(f"Ошибка сборки ссылок: {e}")
        return

    if not links:
        _box_warn("Нет ссылок для передачи")
        return

    token      = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    share_port = random.randint(50000, 59999)
    server_ip  = get_server_ip("4") or "YOUR_SERVER_IP"

    def _make_html() -> str:
        rows = []
        for u_entry in links:
            for lnk in u_entry.get("links", []):
                encoded = urllib.parse.quote(lnk, safe="")
                qr_url  = f"https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={encoded}"
                rows.append(f"""
                <div class="card">
                  <h3>{u_entry['name']}</h3>
                  <img src="{qr_url}" alt="QR" style="border-radius:8px;border:1px solid #ddd"/>
                  <p style="word-break:break-all;font-size:10px;color:#666;margin:8px 0">{lnk}</p>
                  <a href="{lnk}" style="display:inline-block;padding:8px 18px;background:#388e3c;
                     color:#fff;border-radius:6px;text-decoration:none;font-size:14px">
                     Открыть в приложении</a>
                </div>""")
        body = "".join(rows)
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VLESS Config</title>
<style>
 body{{font-family:-apple-system,sans-serif;background:#f0f4f8;padding:16px;margin:0}}
 .card{{background:#fff;border-radius:14px;padding:20px;margin-bottom:16px;
        box-shadow:0 2px 10px rgba(0,0,0,.08);text-align:center}}
 h1{{font-size:20px;color:#333;margin-bottom:4px}}
 h3{{color:#555;margin:0 0 12px}}
 .warn{{color:#c62828;font-size:13px;margin-bottom:16px}}
</style></head>
<body>
<h1>🔐 VLESS Config</h1>
<p class="warn">⚠️ Одноразовая ссылка — страница недоступна после этого просмотра</p>
{body}
<p style="font-size:11px;color:#aaa;text-align:center;margin-top:20px">
 VLESS Ultimate Installer</p>
</body></html>"""

    html_content = _make_html()
    served_once  = [False]
    stop_event   = threading.Event()

    class _OneTimeHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            parsed    = urllib.parse.urlparse(self.path)
            params    = urllib.parse.parse_qs(parsed.query)
            req_token = params.get("t", [""])[0]
            if req_token != token:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"403 Forbidden")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html_content.encode())
            served_once[0] = True
            stop_event.set()

    server = http.server.HTTPServer(("0.0.0.0", share_port), _OneTimeHandler)
    server.timeout = 1
    share_url = f"http://{server_ip}:{share_port}/?t={token}"

    _box_row(f"  {GREEN}Сервер запущен на порту {share_port}{NC}")
    _box_row(f"  Ссылка (5 минут или 1 просмотр):")
    _box_row(f"  {CYAN}{BOLD}{share_url}{NC}")

    _run(["ufw", "allow", str(share_port), "comment", "xray-share-tmp"],
         check=False, quiet=True)
    _box_info("Ожидание подключения (5 минут)...")
    _box_row(f"  {DIM}(Ctrl+C для отмены){NC}")
    _box_bottom()

    deadline = time.time() + 300
    try:
        while not stop_event.is_set() and time.time() < deadline:
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _run(["ufw", "delete", "allow", str(share_port)], check=False, quiet=True)

    if served_once[0]:
        success("Конфиг передан. Сервер закрыт.")
    else:
        warn("Время истекло — сервер закрыт без отдачи страницы.")
    log_to_file("INFO", f"Share config: served={served_once[0]}, port={share_port}")


# =============================================================================
#  МОДУЛЬ 4: ЕЖЕДНЕВНЫЙ HEALTH-ОТЧЁТ (CRON 08:00)
# =============================================================================
def do_health_report(send_tg_flag: bool = True) -> str:
    """Собирает ежедневный health-отчёт, опционально шлёт в Telegram."""
    lines = []
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    hostname = ""
    try:
        hostname = _run(["hostname", "-s"], capture=True, check=False).stdout.strip()
    except Exception:
        pass

    lines.append(f"📋 <b>Daily Health Report [{hostname}]</b>  {ts}")
    lines.append("")

    # Xray
    r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    xray_ok = r.stdout.strip() == "active"
    lines.append(f"{'✅' if xray_ok else '❌'} Xray: {'активен' if xray_ok else 'НЕ АКТИВЕН'}")

    # Nginx
    r = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
    nginx_ok = r.stdout.strip() == "active"
    lines.append(f"{'✅' if nginx_ok else '❌'} Nginx: {'активен' if nginx_ok else 'НЕ АКТИВЕН'}")

    # SSL
    domain = ""
    try:
        if STATE_FILE.exists():
            domain = json.loads(STATE_FILE.read_text()).get("domain", "")
    except Exception:
        pass
    if domain:
        cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        if cert.exists():
            try:
                r  = _run(["openssl", "x509", "-in", str(cert), "-noout", "-enddate"],
                          capture=True, check=False)
                expiry = r.stdout.strip().split("=", 1)[1]
                r2 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
                cert_days = (int(r2.stdout.strip()) - int(time.time())) // 86400
                icon = "✅" if cert_days > 30 else "⚠️"
                lines.append(f"{icon} SSL ({domain}): {cert_days} дн. до истечения")
            except Exception:
                lines.append("⚠️ SSL: не удалось проверить")
        else:
            lines.append("❌ SSL: сертификат не найден")
    else:
        lines.append("ℹ️  SSL: домен не задан")

    # Диск
    try:
        r = _run(["df", "-h", "/"], capture=True, check=False)
        parts = r.stdout.splitlines()[-1].split()
        disk_pct = float(parts[4].replace("%", ""))
        icon = "✅" if disk_pct < 80 else "⚠️" if disk_pct < 90 else "❌"
        lines.append(f"{icon} Диск: {parts[2]}/{parts[1]} ({disk_pct:.0f}%)")
    except Exception:
        lines.append("⚠️ Диск: не удалось проверить")

    # RAM
    try:
        meminfo = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            meminfo[k.strip()] = int(v.strip().split()[0])
        total_mb = meminfo.get("MemTotal", 0) // 1024
        avail_mb = meminfo.get("MemAvailable", 0) // 1024
        used_mb  = total_mb - avail_mb
        pct = used_mb * 100 // max(total_mb, 1)
        icon = "✅" if pct < 80 else "⚠️" if pct < 90 else "❌"
        lines.append(f"{icon} RAM: {used_mb}/{total_mb} МБ ({pct}%)")
    except Exception:
        lines.append("⚠️ RAM: не удалось проверить")

    # Geo-файлы
    for dat in (GEOSITE_DAT, GEOIP_DAT):
        if dat.exists():
            age = (time.time() - dat.stat().st_mtime) / 86400
            icon = "✅" if age < 14 else "⚠️"
            lines.append(f"{icon} {dat.name}: возраст {age:.0f} дн.")
        else:
            lines.append(f"❌ {dat.name}: не найден")

    text = "\n".join(lines)
    log_to_file("INFO", f"Health report generated")

    if send_tg_flag:
        cfg = _tg_load()
        if (cfg.get("token") and cfg.get("chat_id")
                and cfg.get("events", {}).get("health_report", True)):
            tg_send(text, cfg["token"], cfg["chat_id"])

    return text


def _health_report_install_cron() -> None:
    """Устанавливает cron на 08:00 для ежедневного health-отчёта."""
    sh = Path("/usr/local/bin/xray-health-report.sh")
    sh.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        python3 -c "
import json, re, subprocess, sys, time
from pathlib import Path
from datetime import datetime
STATE_FILE = Path('/var/lib/xray-installer/state.json')
TG_CONFIG_FILE = Path('/var/lib/xray-installer/telegram.json')
GEOSITE_DAT = Path('/etc/xray/geosite.dat')
GEOIP_DAT   = Path('/etc/xray/geoip.dat')

def _run(args):
    return subprocess.run(args, capture_output=True, text=True)

def tg_send(msg, token, chat_id):
    subprocess.run(['curl','-s','-o','/dev/null','-m','10',
        f'https://api.telegram.org/bot{{token}}/sendMessage',
        '-d',f'chat_id={{chat_id}}','-d',f'text={{msg}}','-d','parse_mode=HTML'],
        capture_output=True)

cfg = {{}}
try:
    if TG_CONFIG_FILE.exists():
        cfg = json.loads(TG_CONFIG_FILE.read_text())
except: pass
token   = cfg.get('token','')
chat_id = cfg.get('chat_id','')
if not (token and chat_id and cfg.get('events',{{}}).get('health_report',True)):
    sys.exit(0)

hostname = _run(['hostname','-s']).stdout.strip()
ts = datetime.now().strftime('%d.%m.%Y %H:%M')
lines = [f'Daily Health Report [{{hostname}}]  {{ts}}', '']
for svc in ('xray','nginx'):
    ok = _run(['systemctl','is-active',svc]).stdout.strip() == 'active'
    _icon = chr(9989) if ok else chr(10060)
    _status = 'активен' if ok else 'НЕ АКТИВЕН'
    lines.append(f'{{_icon}} {{svc}}: {{_status}}')
domain = ''
try:
    if STATE_FILE.exists():
        domain = json.loads(STATE_FILE.read_text()).get('domain','')
except: pass
if domain:
    cert = Path(f'/etc/letsencrypt/live/{{domain}}/fullchain.pem')
    if cert.exists():
        try:
            r = _run(['openssl','x509','-in',str(cert),'-noout','-enddate'])
            exp = r.stdout.strip().split('=',1)[1]
            epoch = int(_run(['date','-d',exp,'+%s']).stdout.strip())
            days = (epoch - int(time.time())) // 86400
            lines.append(f'{{chr(9989) if days>30 else chr(9888)}} SSL: {{days}} дн. до истечения')
        except: lines.append('SSL: ошибка проверки')
try:
    r = _run(['df','-h','/'])
    p = r.stdout.splitlines()[-1].split()
    pct = float(p[4].replace('%',''))
    lines.append(f'{{chr(9989) if pct<80 else chr(9888)}} Диск: {{p[2]}}/{{p[1]}} ({{pct:.0f}}%)')
except: pass
for dat_name in ('geosite.dat','geoip.dat'):
    dat = Path(f'/etc/xray/{{dat_name}}')
    if dat.exists():
        age = (time.time() - dat.stat().st_mtime) / 86400
        lines.append(f'{{chr(9989) if age<14 else chr(9888)}} {{dat_name}}: возраст {{age:.0f}} дн.')
    else:
        lines.append(f'{{chr(10060)}} {{dat_name}}: не найден')
tg_send(chr(10).join(lines), token, chat_id)
" 2>>/var/log/xray-health-report.log
    """))
    sh.chmod(0o750)
    cron_p = Path("/etc/cron.d/xray-health-report")
    cron_p.write_text(f"0 8 * * * root {sh} >> /var/log/xray-health-report.log 2>&1\n")
    cron_p.chmod(0o644)
    success("Health-отчёт cron установлен (ежедневно 08:00)")


def do_manage_health_report() -> None:
    """Меню управления ежедневным health-отчётом."""
    while True:
        os.system("clear")
        cron_active = Path("/etc/cron.d/xray-health-report").exists()
        print()
        _box_top(f"Ежедневный Health-отчёт")
        _box_row(f"  Cron (08:00): {''+GREEN+'ВКЛЮЧЁН'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЁН'+NC}")
        _box_item("1", f"{'Отключить' if cron_active else 'Включить'} ежедневный отчёт (cron 08:00)")
        _box_item("2", f"Запустить отчёт прямо сейчас")
        _box_item("3", f"Показать лог отчётов")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if cron_active:
                Path("/etc/cron.d/xray-health-report").unlink(missing_ok=True)
                Path("/usr/local/bin/xray-health-report.sh").unlink(missing_ok=True)
                success("Health-отчёт cron отключён")
            else:
                _health_report_install_cron()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            info("Генерация отчёта...")
            report = do_health_report(send_tg_flag=True)
            clean  = re.sub(r'<[^>]+>', '', report)
            print()
            print(clean)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            lp = Path("/var/log/xray-health-report.log")
            if lp.exists():
                lines = lp.read_text().splitlines()[-30:]
                print()
                print('\n'.join(lines))
            else:
                warn("Лог не найден")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  МОДУЛЬ 5: ПОЛНАЯ МИГРАЦИЯ (ЗАШИФРОВАННЫЙ АРХИВ)
# =============================================================================
TG_CONFIG_FILE = Path("/var/lib/xray-installer/telegram.json")


# =============================================================================
#  МОДУЛЬ 6: ИСТОРИЯ ТРАФИКА ПО ДНЯМ (ASCII-ГИСТОГРАММА)
# =============================================================================
TRAFFIC_HISTORY_FILE = Path("/var/lib/xray-installer/traffic_history.json")


def _traffic_snapshot_save() -> None:
    """Сохраняет снимок накопленного трафика пользователей (Naive/Mieru/AWG)."""
    from vless_installer.modules.user_lifecycle import get_user_cumulative_traffic
    users = _users_from_state()
    if not users:
        return
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    now_date = datetime.now().strftime("%Y-%m-%d")
    try:
        history = json.loads(TRAFFIC_HISTORY_FILE.read_text()) if TRAFFIC_HISTORY_FILE.exists() else {}
    except Exception:
        history = {}
    day_data = history.setdefault(now_date, {})
    for u in users:
        email = u.get("email", "")
        if not email:
            continue
        used_bytes = get_user_cumulative_traffic(email, state)
        key = f"{email}_max"
        day_data[key] = max(day_data.get(key, 0), used_bytes)
    # Удаляем данные старше 90 дней
    cutoff = time.time() - 90 * 86400
    history = {
        date: data for date, data in history.items()
        if datetime.strptime(date, "%Y-%m-%d").timestamp() >= cutoff
    }
    TRAFFIC_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    TRAFFIC_HISTORY_FILE.write_text(json.dumps(history, indent=2, ensure_ascii=False))
    TRAFFIC_HISTORY_FILE.chmod(0o600)


def _install_traffic_snapshot_cron() -> None:
    """Cron: снимки трафика через main.py --traffic-snapshot."""
    script = Path(sys.argv[0]).resolve()
    sh = Path("/usr/local/bin/hydra-traffic-snapshot.sh")
    sh.write_text(
        "#!/bin/bash\n"
        f"python3 {script} --traffic-snapshot >> /var/log/hydra-traffic-snapshot.log 2>&1\n"
    )
    sh.chmod(0o750)
    cron_p = Path("/etc/cron.d/hydra-traffic-snapshot")
    cron_p.write_text(f"*/15 * * * * root {sh}\n")
    cron_p.chmod(0o644)
    success("Cron снимков трафика установлен (каждые 15 мин)")




# =============================================================================
#  МОДУЛЬ 7: БЛОКИРОВКА ПО GEOIP (ROUTING RULES В XRAY)
# =============================================================================
# =============================================================================
#  МОДУЛЬ: РФ ПОДСЕТИ (RIPE NCC) → DIRECT  [защита от цензора]
# =============================================================================
RU_SUBNETS_FILE    = Path("/etc/xray/ru_subnets_ripe.txt")
RU_SUBNETS_TIMER   = Path("/etc/systemd/system/xray-ru-subnets.timer")
RU_SUBNETS_SERVICE = Path("/etc/systemd/system/xray-ru-subnets.service")
RIPE_DELEGATED_URL        = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest"
RIPE_DELEGATED_URL_MIRROR = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"
_RU_SUBNET_RULE_COMMENT   = "ru_subnets_ripe"

# =============================================================================
#  ЛОКАЛЬНЫЙ SQLITE-КЭШ ПРЕФИКСОВ ASN
#
#  Кэш хранит:
#    • prefixes_asn  — префиксы конкретного ASN (RIPE Stat API)
#    • prefixes_ru   — делегированные подсети РФ (delegated-ripencc-latest)
#
#  Логика использования:
#    1. При успешной загрузке из RIPE → обновляем кэш.
#    2. При недоступности RIPE → берём данные из кэша (если есть).
#    3. Кэш считается «свежим» если возраст < ASN_CACHE_MAX_AGE_DAYS суток.
#       Устаревший кэш всё равно используется как запасной вариант, но
#       пользователь получает предупреждение с датой последнего обновления.
# =============================================================================
ASN_CACHE_DB      = Path("/var/lib/xray-installer/asn_prefix_cache.sqlite3")
ASN_CACHE_MAX_AGE_DAYS = 30   # предупреждать если кэш старше N дней


def _asn_cache_connect():
    """Открывает (и при необходимости инициализирует) БД кэша. Возвращает sqlite3.Connection."""
    import sqlite3
    ASN_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(ASN_CACHE_DB), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS prefix_cache (
            key        TEXT PRIMARY KEY,   -- 'asn:AS12345' или 'ru_delegated'
            updated_at INTEGER NOT NULL,   -- unix timestamp последнего обновления
            cidrs_json TEXT NOT NULL       -- JSON-массив строк CIDR
        )
    """)
    conn.commit()
    return conn


def _asn_cache_save(key: str, cidrs: list) -> None:
    """Сохраняет список CIDR в кэш под указанным ключом."""
    try:
        import sqlite3
        conn = _asn_cache_connect()
        conn.execute(
            "INSERT OR REPLACE INTO prefix_cache (key, updated_at, cidrs_json) VALUES (?, ?, ?)",
            (key, int(time.time()), json.dumps(cidrs, ensure_ascii=False))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        warn(f"  [кэш ASN] Не удалось сохранить '{key}': {e}")


def _asn_cache_load(key: str) -> tuple:
    """
    Загружает список CIDR из кэша.
    Возвращает (cidrs: list, age_days: float) или ([], None) если записи нет.
    """
    try:
        import sqlite3
        if not ASN_CACHE_DB.exists():
            return [], None
        conn = _asn_cache_connect()
        row = conn.execute(
            "SELECT updated_at, cidrs_json FROM prefix_cache WHERE key = ?", (key,)
        ).fetchone()
        conn.close()
        if row is None:
            return [], None
        updated_at, cidrs_json = row
        age_days = (time.time() - updated_at) / 86400
        cidrs = json.loads(cidrs_json)
        return cidrs, age_days
    except Exception as e:
        warn(f"  [кэш ASN] Не удалось прочитать '{key}': {e}")
        return [], None


def _asn_cache_delete(key: str) -> None:
    """Удаляет запись из кэша (например, при явном сбросе)."""
    try:
        if not ASN_CACHE_DB.exists():
            return
        conn = _asn_cache_connect()
        conn.execute("DELETE FROM prefix_cache WHERE key = ?", (key,))
        conn.commit()
        conn.close()
    except Exception as e:
        warn(f"  [кэш ASN] Не удалось удалить '{key}': {e}")


def _asn_cache_info() -> list:
    """
    Возвращает список dict с информацией о записях кэша:
    [{"key": ..., "count": ..., "age_days": ..., "updated_str": ...}, ...]
    """
    result = []
    try:
        if not ASN_CACHE_DB.exists():
            return result
        import sqlite3, json as _json
        conn = _asn_cache_connect()
        rows = conn.execute(
            "SELECT key, updated_at, cidrs_json FROM prefix_cache ORDER BY key"
        ).fetchall()
        conn.close()
        for key, updated_at, cidrs_json in rows:
            try:
                count = len(_json.loads(cidrs_json))
            except Exception:
                count = 0
            age_days = (time.time() - updated_at) / 86400
            updated_str = datetime.fromtimestamp(updated_at).strftime("%Y-%m-%d %H:%M")
            result.append({
                "key":         key,
                "count":       count,
                "age_days":    age_days,
                "updated_str": updated_str,
            })
    except Exception as e:
        warn(f"  [кэш ASN] Ошибка при чтении списка записей: {e}")
    return result


def _fetch_ru_subnets_from_ripe() -> list:
    """
    Скачивает delegated-ripencc-latest и извлекает IPv4/IPv6 блоки РФ.

    При успехе — обновляет SQLite-кэш ('ru_delegated').
    При недоступности RIPE — возвращает данные из кэша (с предупреждением).
    """
    import urllib.request
    import math

    _CACHE_KEY = "ru_delegated"

    def _download(url):
        req = urllib.request.Request(url, headers={"User-Agent": "xray-installer/3.5"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8", errors="replace")

    raw = ""
    for url in (RIPE_DELEGATED_URL, RIPE_DELEGATED_URL_MIRROR):
        try:
            info(f"Загрузка из RIPE NCC: {url}")
            raw = _download(url)
            if raw:
                break
        except Exception as e:
            warn(f"Ошибка загрузки {url}: {e}")

    if not raw:
        # --- Попытка восстановить данные из SQLite-кэша ---
        cached_cidrs, age_days = _asn_cache_load(_CACHE_KEY)
        if cached_cidrs:
            age_str = f"{age_days:.1f}" if age_days is not None else "?"
            if age_days is not None and age_days > ASN_CACHE_MAX_AGE_DAYS:
                warn(
                    f"RIPE NCC недоступен. Используется УСТАРЕВШИЙ кэш "
                    f"(возраст: {age_str} дней, лимит: {ASN_CACHE_MAX_AGE_DAYS}). "
                    f"Данные могут быть неактуальны."
                )
            else:
                warn(
                    f"RIPE NCC недоступен. Используется локальный кэш "
                    f"(возраст: {age_str} дней, {len(cached_cidrs)} префиксов)."
                )
            return cached_cidrs
        warn("RIPE NCC недоступен и локальный кэш пуст — список РФ подсетей не получен.")
        return []

    cidrs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 6:
            continue
        _, cc, typ, start, value = parts[0], parts[1], parts[2], parts[3], parts[4]
        if cc.upper() != "RU":
            continue
        if typ == "ipv4":
            try:
                prefix = 32 - int(math.log2(int(value)))
                cidrs.append(f"{start}/{prefix}")
            except Exception:
                pass
        elif typ == "ipv6":
            try:
                cidrs.append(f"{start}/{int(value)}")
            except Exception:
                pass

    # --- Обновляем кэш при успешной загрузке ---
    if cidrs:
        _asn_cache_save(_CACHE_KEY, cidrs)
        info(f"  [кэш ASN] Обновлён кэш '{_CACHE_KEY}': {len(cidrs)} префиксов → {ASN_CACHE_DB}")

    return cidrs


# =============================================================================
#  AS-ROUTING MODULE — маршрутизация трафика провайдера/хостера по ASN
#
#  Принцип:  пользователь вводит номер AS (например AS8359 или 8359).
#            Скрипт запрашивает все анонсируемые префиксы этого AS через
#            RIPE Stat API и вставляет их в Xray routing с выбранным действием:
#              direct — напрямую, минуя VPN
#              proxy  — через VPN (основной outbound)
#              block  — заблокировать (blackhole)
#
#  Файлы:    /etc/xray/as_direct_<ASN>.txt  — кеш префиксов для каждого AS
#            /etc/xray/as_direct_list.json  — список активных ASN
#            Формат: [{"asn": "AS8359", "action": "direct"}, ...]
#  Комментарий правила Xray: "as_direct_<ASN>"  (например "as_direct_AS8359")
#  systemd:  xray-as-direct.timer / .service (обновляет все активные AS)
#  CLI-флаг: --update-as-direct
# =============================================================================

AS_DIRECT_DIR       = Path("/etc/xray")
AS_DIRECT_LIST_FILE = Path("/etc/xray/as_direct_list.json")
AS_DIRECT_TIMER     = Path("/etc/systemd/system/xray-as-direct.timer")
AS_DIRECT_SERVICE   = Path("/etc/systemd/system/xray-as-direct.service")

RIPE_STAT_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}&starttime=last"


def _resolve_asn_from_input(raw: str) -> tuple:
    """
    Определяет ASN по IP-адресу или доменному имени.
    Возвращает (asn, org_label) или ("", "") при ошибке.
    Пример: "8.8.8.8" → ("AS15169", "Google LLC")
             "google.com" → ("AS15169", "Google LLC")
    """
    import re as _re
    import socket as _socket

    target = raw.strip()
    # Если это домен — резолвим в IP
    if not _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        try:
            target = _socket.gethostbyname(target)
        except Exception:
            return ("", "")
    # Запрашиваем ASN через ip-api.com
    try:
        import urllib.request as _ur
        url = f"http://ip-api.com/json/{target}?fields=as,org,isp,status"
        req = _ur.Request(url, headers={"User-Agent": "xray-installer/3.99"})
        with _ur.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            as_raw = data.get("as", "")          # "AS12345 FullName"
            asn_num = as_raw.split()[0] if as_raw else ""
            org_label = data.get("isp") or data.get("org", "")
            return (asn_num, org_label)
    except Exception:
        pass
    return ("", "")


def _fetch_prefixes_for_asn(asn: str) -> list:
    """
    Скачивает все IPv4/IPv6 префиксы для ASN через RIPE Stat API.
    Возвращает список строк CIDR: сначала IPv4, затем IPv6.

    Особенности:
    - Retry × 3 с экспоненциальной задержкой (1 с → 2 с → 4 с)
    - Два URL: с параметром starttime и без (резервный)
    - Валидация каждого префикса через ipaddress.ip_network()
    - Раздельный подсчёт и логирование IPv4/IPv6
    - Проверка на пустой ответ API
    - При недоступности RIPE Stat — возврат данных из SQLite-кэша
    """
    import urllib.request
    import ipaddress

    _CACHE_KEY = f"asn:{asn}"

    # Два варианта URL: с фильтром по времени и без (резервный)
    urls = [
        RIPE_STAT_PREFIXES_URL.format(asn=asn),
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}",
    ]

    raw = ""
    for url in urls:
        info(f"  Запрос к RIPE Stat API: {url}")
        for attempt in range(1, 4):   # до 3 попыток на каждый URL
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "xray-installer/4.12.10",
                    "Accept":     "application/json",
                })
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                if raw:
                    break
            except Exception as e:
                delay = 2 ** (attempt - 1)
                if attempt < 3:
                    warn(f"  Попытка {attempt}/3 не удалась ({asn}): {e} — повтор через {delay} с")
                    time.sleep(delay)
                else:
                    warn(f"  Попытка {attempt}/3 не удалась ({asn}): {e}")
        if raw:
            break

    if not raw:
        warn(f"  Не удалось получить данные для {asn} из всех источников")
        # --- Попытка восстановить данные из SQLite-кэша ---
        cached_cidrs, age_days = _asn_cache_load(_CACHE_KEY)
        if cached_cidrs:
            age_str = f"{age_days:.1f}" if age_days is not None else "?"
            if age_days is not None and age_days > ASN_CACHE_MAX_AGE_DAYS:
                warn(
                    f"  RIPE Stat недоступен. Используется УСТАРЕВШИЙ кэш для {asn} "
                    f"(возраст: {age_str} дней, лимит: {ASN_CACHE_MAX_AGE_DAYS}). "
                    f"Данные могут быть неактуальны."
                )
            else:
                warn(
                    f"  RIPE Stat недоступен. Используется локальный кэш для {asn} "
                    f"(возраст: {age_str} дней, {len(cached_cidrs)} префиксов)."
                )
            return cached_cidrs
        warn(f"  RIPE Stat недоступен и кэш для {asn} пуст — префиксы не получены.")
        return []

    # --- Разбор JSON ---
    try:
        data = json.loads(raw)
    except Exception as e:
        warn(f"  Ошибка разбора JSON ({asn}): {e}")
        return []

    # --- Проверка статуса API ---
    status = data.get("status", "")
    if status not in ("ok", "maintenance"):
        warn(f"  RIPE Stat вернул статус: {status!r} для {asn}")
        if not data.get("data"):
            return []

    # --- Извлечение префиксов ---
    api_data     = data.get("data") or {}
    prefixes_raw = api_data.get("prefixes") or []
    # Резервный ключ на случай нестандартного ответа API
    if not prefixes_raw:
        prefixes_raw = (api_data.get("announced_space") or {}).get("prefixes") or []

    if not prefixes_raw:
        warn(f"  {asn}: API вернул пустой список префиксов")
        return []

    # --- Валидация и разделение IPv4 / IPv6 ---
    cidrs_v4, cidrs_v6 = [], []
    skipped = 0
    for entry in prefixes_raw:
        prefix = (entry.get("prefix") or "").strip()
        if not prefix:
            continue
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                cidrs_v4.append(str(net))   # нормализуем (убираем хост-биты)
            else:
                cidrs_v6.append(str(net))
        except ValueError:
            skipped += 1

    total = len(cidrs_v4) + len(cidrs_v6)
    info(f"  {asn}: {total} префиксов "
         f"(IPv4: {len(cidrs_v4)}, IPv6: {len(cidrs_v6)}"
         + (f", пропущено некорректных: {skipped}" if skipped else "") + ")")

    if total == 0:
        warn(f"  {asn}: после валидации не осталось ни одного корректного префикса")

    # IPv4 первыми (более частый случай), потом IPv6
    result = cidrs_v4 + cidrs_v6

    # --- Обновляем кэш при успешной загрузке ---
    if result:
        _asn_cache_save(_CACHE_KEY, result)
        info(f"  [кэш ASN] Обновлён кэш '{_CACHE_KEY}': {total} префиксов → {ASN_CACHE_DB}")

    return result


# =============================================================================
#  МОДУЛЬ 8: АУДИТ ПОДКЛЮЧЕНИЙ
# =============================================================================
def _parse_access_log() -> list:
    """Парсит /var/log/xray/access.log в список dict."""
    log_path = Path("/var/log/xray/access.log")
    if not log_path.exists():
        warn(f"access.log не найден: {log_path}")
        return []

    entries = []
    # Формат Xray: 2024/01/15 12:34:56 accepted tcp:1.2.3.4:1234 ... email:user@domain
    pattern = re.compile(
        r'(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+'
        r'(?:from\s+(?P<from_ip>[^:]+):\d+\s+)?'
        r'(?P<action>\w+)\s+(?P<proto>\w+):(?P<dst_ip>[^:]+):(?P<src_port>\d+)'
        r'(?:\s+(?P<dst>\S+))?(?:\s+\[(?P<tag>[^\]]*)\])?'
        r'(?:.*?email:\s*(?P<email>\S+))?'
    )
    try:
        lines = log_path.read_text(errors="replace").splitlines()
        for line in lines[-10000:]:
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            dt_str  = ""
            dt      = None
            action  = ""
            src_ip  = ""
            email   = ""
            if m:
                dt_str = f"{m.group('date')} {m.group('time')}"
                try:
                    dt = datetime.strptime(dt_str, "%Y/%m/%d %H:%M:%S")
                except Exception:
                    pass
                action = m.group("action") or ""
                src_ip = m.group("from_ip") or m.group("dst_ip") or ""
                email  = m.group("email")  or ""
            else:
                m2 = re.match(r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\w+)', line)
                if m2:
                    dt_str = f"{m2.group(1)} {m2.group(2)}"
                    try:
                        dt = datetime.strptime(dt_str, "%Y/%m/%d %H:%M:%S")
                    except Exception:
                        pass
                    action = m2.group(3)
                    ip_m   = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}):\d+', line)
                    src_ip = ip_m.group(1) if ip_m else ""
                    em_m   = re.search(r'email:(\S+)', line)
                    email  = em_m.group(1) if em_m else ""
                else:
                    continue
            entries.append({
                "dt": dt, "dt_str": dt_str, "action": action,
                "src_ip": src_ip, "email": email, "raw": line,
                "dst": m.group("dst") if m else "",
            })
    except Exception as e:
        warn(f"Ошибка чтения access.log: {e}")
    return entries


def _audit_user_summary() -> None:
    print()
    info("Анализ access.log...")
    all_entries = _parse_access_log()
    entries = [e for e in all_entries if e.get("action", "").lower() == "accepted"]
    if not entries:
        log_path = Path("/var/log/xray/access.log")
        if not log_path.exists():
            warn("access.log не найден — xray не запущен или путь не задан в config.json")
        elif log_path.stat().st_size == 0:
            warn("access.log пустой — xray запущен с loglevel=warning")
            info("Для аудита подключений нужен loglevel=info в config.json → перезапустите xray")
        elif not all_entries:
            warn("access.log есть, но записи не распознаны — нестандартный формат")
        else:
            warn("access.log есть, но записи 'accepted' не найдены")
            info("Причина: loglevel=warning — xray не пишет подключения при таком уровне")
            info("Для аудита: config.json → log.loglevel = 'info', затем перезапустите xray")
        return

    from collections import defaultdict
    stats: dict = defaultdict(lambda: {"connections": 0, "ips": set(), "first": None, "last": None})

    for e in entries:
        key    = e.get("email") or "[без email]"
        src_ip = e.get("src_ip", "")
        dt     = e.get("dt")
        s      = stats[key]
        s["connections"] += 1
        if src_ip:
            s["ips"].add(src_ip)
        if dt:
            if s["first"] is None or dt < s["first"]: s["first"] = dt
            if s["last"]  is None or dt > s["last"]:  s["last"]  = dt

    _box_top("Сводка по пользователям")
    _box_row(f"  {BOLD}{'Пользователь':<30} {'Соед.':<8} {'IP':<8} {'Первое':<18} {'Последнее'}{NC}")
    _box_sep()
    for email, s in sorted(stats.items(), key=lambda x: -x[1]["connections"]):
        first_str = s["first"].strftime("%d.%m %H:%M") if s["first"] else "—"
        last_str  = s["last"].strftime("%d.%m %H:%M")  if s["last"]  else "—"
        col = CYAN if email != "[без email]" else DIM
        _box_row(f"  {col}{email:<30}{NC} {s['connections']:<8} {len(s['ips']):<8} {first_str:<18} {last_str}")
    _box_sep()
    _box_row(f"  {DIM}Всего записей: {len(entries)}{NC}")
    _box_row()
    _box_bottom()


def _audit_recent_connections(n: int = 50) -> None:
    print()
    info(f"Последние {n} записей access.log:")
    entries = _parse_access_log()
    if not entries:
        warn("Нет данных")
        return
    _box_top(f"Последние {n} подключений")
    _box_row(f"  {BOLD}{'Время':<20} {'Действие':<10} {'IP-клиента':<18} {'Email'}{NC}")
    _box_sep()
    for e in entries[-n:]:
        action = e.get("action", "")
        col = GREEN if action == "accepted" else RED if "reject" in action.lower() else DIM
        _box_row(
            f"  {e['dt_str']:<20} "
            f"{col}{action:<10}{NC} "
            f"{e['src_ip']:<18} "
            f"{(e['email'] or '—')}"
        )
    _box_row()
    _box_bottom()


def _audit_suspicious() -> None:
    print()
    info("Анализ подозрительной активности...")
    entries = _parse_access_log()
    suspicious = [
        e for e in entries
        if any(kw in (e.get("action","") + e.get("raw","")).lower()
               for kw in ("reject", "error", "failed", "denied",
                          "invalid", "timeout", "handshake"))
    ]

    error_log = Path("/var/log/xray/error.log")
    error_lines = []
    if error_log.exists():
        error_lines = error_log.read_text(errors="replace").splitlines()[-100:]

    if not suspicious and not error_lines:
        success("Подозрительных событий не обнаружено")
        return

    _box_top("Подозрительная активность")
    if suspicious:
        from collections import Counter
        ip_counter = Counter(e.get("src_ip","") for e in suspicious if e.get("src_ip"))
        _box_row(f"  {BOLD}{RED}Подозрительные события в access.log: {len(suspicious)}{NC}")
        _box_row()
        _box_row(f"  {BOLD}Топ IP по числу ошибок:{NC}")
        for ip, cnt in ip_counter.most_common(10):
            col = RED if cnt >= 5 else YELLOW
            _box_row(f"    {col}{ip:<22}{NC} {cnt} событий")
        _box_sep()
        _box_row(f"  {BOLD}Последние подозрительные строки:{NC}")
        for e in suspicious[-15:]:
            _box_row(f"  {DIM}{e['dt_str']:<20}{NC} {RED}{e['action']:<10}{NC} {e['src_ip']:<18} {e['raw'][:50]}")

    if error_lines:
        _box_sep()
        _box_row(f"  {BOLD}Последние строки error.log:{NC}")
        for line in error_lines[-10:]:
            _box_row(f"  {DIM}{line[:100]}{NC}")
    _box_row()
    _box_bottom()


def _audit_active_now() -> None:
    print()
    info("Активные соединения Xray:")
    try:
        r = _run(["ss", "-tnp", "state", "established"], capture=True, check=False)
        lines = [l for l in r.stdout.splitlines() if "xray" in l]
        if not lines:
            info("Нет активных соединений с процессом xray")
            return
        _box_top("Активные соединения Xray")
        _box_row(f"  {BOLD}{'Локал. адрес':<26} {'Удал. адрес':<26} {'Процесс'}{NC}")
        _box_sep()
        for line in lines[:30]:
            parts = line.split()
            if len(parts) >= 5:
                _box_row(f"  {CYAN}{parts[3]:<26}{NC} {GREEN}{parts[4]:<26}{NC} {DIM}{(parts[-1] if len(parts)>5 else '')[:30]}{NC}")
        _box_sep()
        _box_row(f"  {DIM}Всего: {len(lines)} соединений{NC}")
        _box_row()
        _box_bottom()
    except Exception as e:
        warn(f"Ошибка ss: {e}")

# =============================================================================
#  ФИЧА 1: АВТО-БАН IP ПО ОШИБКАМ TLS HANDSHAKE (без Fail2ban)
# =============================================================================
_XRAY_BAN_STATE   = Path("/var/lib/xray-installer/autoban.json")
_XRAY_BAN_CRON    = Path("/etc/cron.d/xray-autoban")
_XRAY_BAN_SCRIPT  = Path("/usr/local/bin/xray-autoban.sh")
_XRAY_BAN_LOG     = Path("/var/log/xray-autoban.log")
_XRAY_BAN_REPORT  = Path("/var/log/xray-ban-report.txt")   # читаемый отчёт (7 дней)

# Пороги по умолчанию (сохраняются в state autoban.json)
_BAN_THRESHOLD_DEFAULT   = 10   # ошибок за период
_BAN_WINDOW_MINUTES      = 10   # минут для подсчёта
_BAN_WHITELIST_DEFAULT   = ["127.0.0.1", "::1"]


_asn_cache: dict = {}  # кеш: ip -> {"asn": "AS12345", "org": "...", "isp": "..."}


def _lookup_asn(ip: str) -> dict:
    """
    Запрашивает ASN и провайдера для IP через ip-api.com (бесплатно, без ключа).
    Возвращает словарь с ключами asn, org, isp.
    При ошибке возвращает пустой словарь.
    Кеширует результаты в _asn_cache.
    """
    if ip in _asn_cache:
        return _asn_cache[ip]
    result: dict = {}
    try:
        import urllib.request as _ur
        import urllib.error as _ue
        url = f"http://ip-api.com/json/{ip}?fields=as,org,isp,status"
        req = _ur.Request(url, headers={"User-Agent": "xray-installer/3.99"})
        with _ur.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {
                "asn": data.get("as", ""),    # "AS12345 SomeName"
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
            }
    except Exception:
        pass
    _asn_cache[ip] = result
    return result


def _fmt_asn_short(info: dict) -> str:
    """Форматирует ASN-инфо в короткую строку для отображения в рамке.
    Пример: AS12345 · Cloudflare Inc."""
    if not info:
        return ""
    asn_raw = info.get("asn", "")            # "AS12345 FullName"
    isp     = info.get("isp", "")
    # Берём только номер ASN (первое слово)
    asn_num = asn_raw.split()[0] if asn_raw else ""
    label   = isp or info.get("org", "")
    if asn_num and label:
        return f"{asn_num} · {label}"
    return asn_num or label or ""


# ---------------------------------------------------------------------------
#  BAN REPORT FILE — /var/log/xray-ban-report.txt
#  Накапливает читаемый отчёт в течение 7 дней, затем ротируется.
# ---------------------------------------------------------------------------
_BAN_REPORT_TTL_DAYS = 7


def _ban_report_rotate() -> None:
    """Если файл старше 7 дней — удаляем (создастся заново при следующей записи)."""
    try:
        if _XRAY_BAN_REPORT.exists():
            age_days = (time.time() - _XRAY_BAN_REPORT.stat().st_mtime) / 86400
            if age_days >= _BAN_REPORT_TTL_DAYS:
                _XRAY_BAN_REPORT.unlink()
    except Exception:
        pass


def _ban_report_append(ip: str, count: int, reason: str, asn_info: dict) -> None:
    """
    Дописывает одну запись о бане в текстовый отчёт.
    Сначала проверяет ротацию (7-дневный TTL).
    Формат блока:
    ────────────────────────────────────────────────────────────
    [2026-05-04 02:15:00]  ЗАБЛОКИРОВАН: 66.132.172.140
      Ошибок:    6  (DPI [HTTP на TLS-порту])
      ASN:       AS7922 · Comcast Cable Communications
      Провайдер: Comcast Cable Communications, LLC
      Организация: Comcast Cable Communications, LLC
    ────────────────────────────────────────────────────────────
    """
    _ban_report_rotate()
    try:
        _XRAY_BAN_REPORT.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sep = "─" * 64
        asn_raw = asn_info.get("asn", "—")
        isp     = asn_info.get("isp", "—")
        org     = asn_info.get("org", "—")
        # Форматируем ASN: убираем дублирование если asn == org
        asn_num = asn_raw.split()[0] if asn_raw and asn_raw != "—" else "—"
        block = (
            f"\n{sep}\n"
            f"[{ts}]  ЗАБЛОКИРОВАН: {ip}\n"
            f"  Ошибок:      {count}  ({reason})\n"
            f"  ASN:         {asn_num}\n"
            f"  Провайдер:   {isp}\n"
            f"  Организация: {org}\n"
        )
        with _XRAY_BAN_REPORT.open("a", encoding="utf-8") as f:
            f.write(block)
    except Exception:
        pass


def _ban_report_show_in_box() -> None:
    """
    Читает _XRAY_BAN_REPORT и выводит его содержимое под таблицей истории банов.
    Если файла нет — ничего не выводит.
    Длинные строки переносятся по ширине рамки.
    """
    if not _XRAY_BAN_REPORT.exists():
        return
    try:
        text = _XRAY_BAN_REPORT.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    if not text.strip():
        return

    _ban_report_rotate()  # проверяем TTL перед показом
    if not _XRAY_BAN_REPORT.exists():
        return

    try:
        age_days = (time.time() - _XRAY_BAN_REPORT.stat().st_mtime) / 86400
        age_str = f"{age_days:.1f} дн."
        file_size = _XRAY_BAN_REPORT.stat().st_size
        size_str = (f"{file_size // 1024} КБ" if file_size >= 1024
                    else f"{file_size} Б")
    except Exception:
        age_str = "?"
        size_str = "?"

    print()
    # Заголовок секции
    _box_line_top()
    _hdr = f"📋 Детальный отчёт о банах (файл, 7 дней)"
    _pl  = _wcslen(_hdr)
    _lp  = (_BOX_W - _pl) // 2
    _rp  = _BOX_W - _pl - _lp
    print(f"{CYAN}║{NC}{' ' * _lp}{BOLD}{WHITE}{_hdr}{NC}{' ' * _rp}{CYAN}║{NC}")
    _box_line_sep()
    _meta = f"  Файл: {_XRAY_BAN_REPORT}  │  Размер: {size_str}  │  Возраст: {age_str}"
    _box_row(f"{DIM}{_meta}{NC}")
    _meta2 = f"  Ротация: автоматически через {_BAN_REPORT_TTL_DAYS} дней с момента создания"
    _box_row(f"{DIM}{_meta2}{NC}")
    _box_line_sep()

    # Печатаем строки файла, перенося длинные
    max_w = _BOX_W - 2
    for raw_line in text.splitlines():
        # Убираем символы рамки из самого файла (─) — они пройдут как есть
        if len(raw_line) > max_w:
            # Жёсткий перенос по max_w
            while raw_line:
                chunk = raw_line[:max_w]
                raw_line = raw_line[max_w:]
                _box_row(f" {chunk}")
        else:
            _box_row(f" {raw_line}")

    _box_bottom()


def _autoban_load() -> dict:
    try:
        if _XRAY_BAN_STATE.exists():
            return json.loads(_XRAY_BAN_STATE.read_text())
    except Exception:
        pass
    return {"enabled": False, "threshold": _BAN_THRESHOLD_DEFAULT,
            "window_min": _BAN_WINDOW_MINUTES, "whitelist": list(_BAN_WHITELIST_DEFAULT),
            "banned": {}}


def _autoban_save(data: dict) -> None:
    _XRAY_BAN_STATE.parent.mkdir(parents=True, exist_ok=True)
    # Гарантируем наличие секции ban_history
    if "ban_history" not in data:
        data["ban_history"] = []
    _XRAY_BAN_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _XRAY_BAN_STATE.chmod(0o600)


def _autoban_get_chain_ips() -> list[str]:
    """Возвращает список IP всех нод из state.json (entry + exit) для автоматического whitelist.
    При AWG 2.0 включает IP exit-VPS туннеля."""
    ips: list[str] = []
    try:
        if not STATE_FILE.exists():
            return ips
        state = json.loads(STATE_FILE.read_text())
        # Exit-ноды каскада (Режим B, VLESS)
        for node in state.get("chain_nodes", []):
            host = node.get("host", "")
            if host and not host.replace(".", "").replace(":", "").isalnum() is False:
                # Если host выглядит как IP — добавляем напрямую
                import re as _re
                if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                    ips.append(host)
                else:
                    # Резолвим домен
                    try:
                        import socket as _sock
                        resolved = _sock.gethostbyname(host)
                        if resolved:
                            ips.append(resolved)
                    except Exception:
                        pass
        # Legacy одиночная нода
        legacy_host = state.get("chain_exit_host", "")
        if legacy_host:
            import re as _re
            if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', legacy_host):
                if legacy_host not in ips:
                    ips.append(legacy_host)
            else:
                try:
                    import socket as _sock
                    resolved = _sock.gethostbyname(legacy_host)
                    if resolved and resolved not in ips:
                        ips.append(resolved)
                except Exception:
                    pass
        # AWG 2.0: добавляем IP exit-VPS в whitelist чтобы он не получил автобан
        if state.get("awg_exit_enabled") and state.get("install_mode") == "B":
            awg_host = state.get("awg_exit_host", "")
            if awg_host:
                import re as _re, socket as _sock
                if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', awg_host):
                    if awg_host not in ips:
                        ips.append(awg_host)
                else:
                    try:
                        resolved = _sock.gethostbyname(awg_host)
                        if resolved and resolved not in ips:
                            ips.append(resolved)
                    except Exception:
                        pass
    except Exception:
        pass
    return ips


def _fw_ban(ip: str) -> bool:
    """Банит IP через ufw если доступен, иначе через iptables. Возвращает True при успехе."""
    import shutil as _shutil
    if _shutil.which("ufw"):
        r = _run(["ufw", "deny", "from", ip, "to", "any", "comment", "xray-autoban"],
                 check=False, quiet=True)
        return r.returncode == 0
    # Fallback: iptables (Debian 13 / nftables системы без ufw)
    r = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
              "-m", "comment", "--comment", "xray-autoban"],
             check=False, quiet=True)
    return r.returncode == 0


def _fw_unban(ip: str) -> bool:
    """Разбанивает IP через ufw или iptables."""
    import shutil as _shutil
    if _shutil.which("ufw"):
        r = _run(["ufw", "delete", "deny", "from", ip, "to", "any"],
                 check=False, quiet=True)
        return r.returncode == 0
    r = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
              "-m", "comment", "--comment", "xray-autoban"],
             check=False, quiet=True)
    return r.returncode == 0


def _autoban_run_once() -> int:
    """
    Сканирует error.log за последние N минут, считает TLS-ошибки по IP.
    При превышении порога добавляет UFW deny. Возвращает число новых банов.
    """
    cfg       = _autoban_load()
    threshold = cfg.get("threshold", _BAN_THRESHOLD_DEFAULT)
    window    = cfg.get("window_min", _BAN_WINDOW_MINUTES)
    whitelist = set(cfg.get("whitelist", _BAN_WHITELIST_DEFAULT))
    # Автоматически исключаем IP нод из цепочки — они появляются в error.log
    # как источники TLS-соединений и НЕ должны баниться
    for chain_ip in _autoban_get_chain_ips():
        whitelist.add(chain_ip)
    banned    = cfg.get("banned", {})

    error_log = Path("/var/log/xray/error.log")
    if not error_log.exists():
        return 0

    cutoff = time.time() - window * 60
    ip_errors: dict = {}

    # Паттерны TLS-ошибок в error.log Xray
    tls_patterns = re.compile(
        r'(tls: (?:handshake|no supported versions|no cipher)'
        r'|failed to read'
        r'|invalid header'
        r'|connection reset'
        r'|broken pipe)',
        re.IGNORECASE
    )
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    try:
        lines = error_log.read_text(errors="replace").splitlines()[-5000:]
        for line in lines:
            # Фильтруем по времени — Xray пишет: 2024/04/22 18:45:01
            dt_m = re.match(r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})', line)
            if dt_m:
                try:
                    ts = datetime.strptime(
                        f"{dt_m.group(1)} {dt_m.group(2)}", "%Y/%m/%d %H:%M:%S"
                    ).timestamp()
                    if ts < cutoff:
                        continue
                except Exception:
                    pass
            if not tls_patterns.search(line):
                continue
            ip_m = ip_pattern.search(line)
            if not ip_m:
                continue
            ip = ip_m.group(1)
            if ip in whitelist:
                continue
            ip_errors[ip] = ip_errors.get(ip, 0) + 1
    except Exception:
        return 0

    new_bans = 0
    for ip, count in ip_errors.items():
        if count >= threshold and ip not in banned:
            # Баним через UFW
            if _fw_ban(ip):
                _ban_ts = datetime.now().isoformat()
                banned[ip] = {
                    "count":     count,
                    "banned_at": _ban_ts,
                    "reason":    f"{count} TLS errors in {window}min",
                }
                # Записываем в историю (запись не удаляется при разбане)
                cfg.setdefault("ban_history", []).append({
                    "ip":          ip,
                    "banned_at":   _ban_ts,
                    "unbanned_at": None,
                    "count":       count,
                    "reason":      f"{count} TLS errors in {window}min",
                })
                if len(cfg["ban_history"]) > 500:
                    cfg["ban_history"] = cfg["ban_history"][-500:]
                new_bans += 1
                log_to_file("INFO", f"AutoBan: {ip} banned ({count} errors)")
                _tg_notify_event("autoban",
                    f"IP <b>{ip}</b> забанен автоматически: {count} TLS-ошибок за {window} мин")
                try:
                    _XRAY_BAN_LOG.parent.mkdir(parents=True, exist_ok=True)
                    with _XRAY_BAN_LOG.open("a") as f:
                        f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] BAN {ip}: {count} errors\n")
                except Exception:
                    pass
                # Записываем в читаемый отчёт с ASN-данными
                try:
                    _asn = _lookup_asn(ip)
                    _ban_report_append(ip, count, f"{count} TLS errors in {window}min", _asn)
                except Exception:
                    pass

    cfg["banned"] = banned
    _autoban_save(cfg)
    return new_bans


def _autoban_install_cron(threshold: int, window: int) -> None:
    """Устанавливает cron каждые 5 минут."""
    sh = _XRAY_BAN_SCRIPT
    # Используем heredoc + iptables-fallback для совместимости с Debian 13
    # (нет ufw по умолчанию, textwrap.dedent ломает shebang)
    py_body = f"""import json, re, subprocess, sys, time, shutil
from pathlib import Path
from datetime import datetime

BAN_STATE  = Path('/var/lib/xray-installer/autoban.json')
BAN_LOG    = Path('/var/log/xray-autoban.log')
TG_CONFIG  = Path('/var/lib/xray-installer/telegram.json')

def tg(msg):
    try:
        c = json.loads(TG_CONFIG.read_text()) if TG_CONFIG.exists() else {{}}
        t, ch = c.get('token'), c.get('chat_id')
        if t and ch:
            subprocess.run(['curl','-s','-o','/dev/null','-m','10',
                f'https://api.telegram.org/bot{{t}}/sendMessage',
                '-d',f'chat_id={{ch}}','-d',f'text={{msg}}'],capture_output=True)
    except: pass

def fw_ban(ip):
    if shutil.which('ufw'):
        return subprocess.run(['ufw','deny','from',ip,'to','any','comment','xray-autoban'],
            capture_output=True).returncode == 0
    return subprocess.run(['iptables','-I','INPUT','-s',ip,'-j','DROP',
        '-m','comment','--comment','xray-autoban'],
        capture_output=True).returncode == 0

cfg = {{}}
try:
    if BAN_STATE.exists(): cfg = json.loads(BAN_STATE.read_text())
except: pass
threshold = cfg.get('threshold', {threshold})
window    = cfg.get('window_min', {window})
whitelist = set(cfg.get('whitelist', ['127.0.0.1','::1']))
try:
    import socket as _sock
    _state_f = Path('/var/lib/xray-installer/state.json')
    if _state_f.exists():
        _st = json.loads(_state_f.read_text())
        for _nd in _st.get('chain_nodes', []):
            _h = _nd.get('host','')
            if not _h: continue
            import re as _re
            if _re.match(r'^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$', _h):
                whitelist.add(_h)
            else:
                try: whitelist.add(_sock.gethostbyname(_h))
                except: pass
        _lh = _st.get('chain_exit_host','')
        if _lh:
            if _re.match(r'^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$', _lh):
                whitelist.add(_lh)
            else:
                try: whitelist.add(_sock.gethostbyname(_lh))
                except: pass
except: pass
banned = cfg.get('banned', {{}})

error_log = Path('/var/log/xray/error.log')
if not error_log.exists(): sys.exit(0)

cutoff = time.time() - window * 60
ip_errors = {{}}
tls_re = re.compile(r'tls.*handshake|failed to read|invalid header|connection reset|broken pipe', re.I)
ip_re  = re.compile(r'(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}})')
for line in error_log.read_text(errors='replace').splitlines()[-5000:]:
    m = re.match(r'(\\d{{4}}/\\d{{2}}/\\d{{2}})\\s+(\\d{{2}}:\\d{{2}}:\\d{{2}})', line)
    if m:
        try:
            ts = datetime.strptime(f'{{m.group(1)}} {{m.group(2)}}','%Y/%m/%d %H:%M:%S').timestamp()
            if ts < cutoff: continue
        except: pass
    if not tls_re.search(line): continue
    im = ip_re.search(line)
    if not im or im.group(1) in whitelist: continue
    ip_errors[im.group(1)] = ip_errors.get(im.group(1), 0) + 1

for ip, cnt in ip_errors.items():
    if cnt >= threshold and ip not in banned:
        if fw_ban(ip):
            banned[ip] = {{'count':cnt,'banned_at':datetime.now().isoformat()}}
            BAN_LOG.parent.mkdir(parents=True,exist_ok=True)
            with open(BAN_LOG,'a') as f:
                f.write(f'[{{datetime.now():%Y-%m-%d %H:%M:%S}}] BAN {{ip}}: {{cnt}} errors\\n')
            tg(f'AutoBan: {{ip}} banned ({{cnt}} TLS errors in {{window}}min)')

cfg['banned'] = banned
BAN_STATE.parent.mkdir(parents=True,exist_ok=True)
BAN_STATE.write_text(json.dumps(cfg,indent=2))
"""
    lines = ["#!/bin/bash", "python3 - <<'PYEOF'"] + py_body.splitlines() + ["PYEOF"]
    sh.write_text("\n".join(lines) + "\n")
    sh.chmod(0o750)
    _XRAY_BAN_CRON.write_text(
        f"*/5 * * * * root {sh} >> /var/log/xray-autoban.log 2>&1\n"
    )
    _XRAY_BAN_CRON.chmod(0o644)
    success(f"AutoBan cron установлен (каждые 5 мин, порог: {threshold} ошибок за {window} мин)")




def do_manage_autoban() -> None:
    """Меню автоматического бана IP по TLS-ошибкам."""
    while True:
        os.system("clear")
        cfg    = _autoban_load()
        banned = cfg.get("banned", {})
        cron_active = _XRAY_BAN_CRON.exists()

        print()
        _box_top(f"Авто-бан IP (TLS handshake ошибки)")
        _box_row(f"  Cron (5 мин):  {''+GREEN+'ВКЛЮЧЁН'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЁН'+NC}")
        _box_row(f"  Порог:         {CYAN}{cfg.get('threshold', _BAN_THRESHOLD_DEFAULT)}{NC} ошибок "
              f"за {CYAN}{cfg.get('window_min', _BAN_WINDOW_MINUTES)}{NC} мин")
        _box_row(f"  Забанено IP:   {RED if banned else DIM}{len(banned)}{NC}")

        if banned:
            _box_row(f"  {BOLD}Забаненные IP:{NC}")
            for ip, meta in list(banned.items())[-10:]:
                ts  = meta.get("banned_at", "?")[:16].replace("T", " ")
                cnt = meta.get("count", "?")
                # Первая строка: IP + количество ошибок + дата
                line1 = f"    {RED}✗{NC} {ip:<18} {YELLOW}{cnt}{NC} ошибок  {DIM}{ts}{NC}"
                _box_row(line1)
                # Вторая строка: ASN + провайдер (запрашиваем без блокировки)
                asn_info = _lookup_asn(ip)
                asn_str  = _fmt_asn_short(asn_info)
                if asn_str:
                    # Обрезаем если слишком длинно
                    max_asn = _BOX_W - 8
                    if len(asn_str) > max_asn:
                        asn_str = asn_str[:max_asn - 1] + "…"
                    _box_row(f"      {DIM}{asn_str}{NC}")
            if len(banned) > 10:
                _box_row(f"    {DIM}... и ещё {len(banned)-10} IP{NC}")

        _box_item("1", f"{'Отключить' if cron_active else 'Включить'} авто-бан")
        _box_item("2", f"Изменить порог / окно")
        _box_item("3", f"Разбанить IP")
        _box_item("4", f"Запустить проверку прямо сейчас")
        _box_item("5", f"Управление whitelist")
        _box_item("6", f"📜 История банов")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if cron_active:
                _XRAY_BAN_CRON.unlink(missing_ok=True)
                _XRAY_BAN_SCRIPT.unlink(missing_ok=True)
                cfg["enabled"] = False
                _autoban_save(cfg)
                success("Авто-бан отключён")
            else:
                t = cfg.get("threshold", _BAN_THRESHOLD_DEFAULT)
                w = cfg.get("window_min", _BAN_WINDOW_MINUTES)
                _autoban_install_cron(t, w)
                cfg["enabled"] = True
                _autoban_save(cfg)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw_t = input(f"  Порог ошибок [{cfg.get('threshold', _BAN_THRESHOLD_DEFAULT)}]: ").strip()
            raw_w = input(f"  Окно (мин)   [{cfg.get('window_min', _BAN_WINDOW_MINUTES)}]: ").strip()
            if raw_t.isdigit(): cfg["threshold"]  = int(raw_t)
            if raw_w.isdigit(): cfg["window_min"] = int(raw_w)
            _autoban_save(cfg)
            # Переустанавливаем cron с новыми параметрами если был активен
            if cron_active:
                _autoban_install_cron(cfg["threshold"], cfg["window_min"])
            success("Настройки сохранены")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            if not banned:
                warn("Нет забаненных IP")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            print()
            ban_list = list(banned.keys())
            _box_top("Забаненные IP — выберите для разбана")
            for i, ip in enumerate(ban_list, 1):
                meta  = banned[ip]
                ts    = meta.get("banned_at", "?")[:16].replace("T", " ")
                cnt   = meta.get("count", "?")
                _box_row(f"  {CYAN}{i:>3}{NC}  {ip:<18} {YELLOW}{cnt}{NC} ошибок  {DIM}{ts}{NC}")
            _box_row()
            _box_row(f"  {DIM}Примеры ввода:{NC}")
            _box_row(f"  {DIM}  3        — разбанить один IP по номеру{NC}")
            _box_row(f"  {DIM}  1,3,5    — разбанить несколько через запятую{NC}")
            _box_row(f"  {DIM}  2-6      — разбанить диапазон номеров{NC}")
            _box_row(f"  {DIM}  all      — разбанить всех{NC}")
            _box_row(f"  {DIM}  1.2.3.4  — разбанить по IP напрямую{NC}")
            _box_bottom()
            raw = input(f"  {CYAN}Ввод:{NC} ").strip().lower()

            # ── Разбираем ввод → список целевых IP ────────────────────────────
            targets: list[str] = []

            if raw in ("all", "все", "*"):
                targets = list(ban_list)

            elif "-" in raw and not raw.startswith("-") and not raw.replace(".", "").replace("-", "").isdigit() is False:
                # Диапазон номеров: "2-6"
                parts = raw.split("-", 1)
                if parts[0].isdigit() and parts[1].isdigit():
                    lo, hi = int(parts[0]), int(parts[1])
                    lo, hi = min(lo, hi), max(lo, hi)
                    targets = [ban_list[i-1] for i in range(lo, hi+1)
                               if 1 <= i <= len(ban_list)]
                else:
                    warn("Неверный диапазон. Формат: 2-6")

            elif "," in raw:
                # Перечисление: "1,3,5" или "1.2.3.4,5.6.7.8"
                for token in raw.split(","):
                    token = token.strip()
                    if token.isdigit():
                        idx = int(token)
                        if 1 <= idx <= len(ban_list):
                            targets.append(ban_list[idx-1])
                        else:
                            warn(f"Номер {idx} вне диапазона — пропущен")
                    elif token in banned:
                        targets.append(token)
                    else:
                        warn(f"'{token}' не найден — пропущен")

            elif raw.isdigit():
                idx = int(raw)
                if 1 <= idx <= len(ban_list):
                    targets = [ban_list[idx-1]]
                else:
                    warn(f"Номер {idx} вне диапазона")

            elif raw in banned:
                targets = [raw]

            else:
                warn("Не удалось распознать ввод")

            # ── Выполняем разбан ──────────────────────────────────────────────
            if targets:
                _unban_ts = datetime.now().isoformat()
                ok_count  = 0
                for target in targets:
                    _fw_unban(target)
                    banned.pop(target, None)
                    for _hrec in reversed(cfg.get("ban_history", [])):
                        if _hrec.get("ip") == target and _hrec.get("unbanned_at") is None:
                            _hrec["unbanned_at"] = _unban_ts
                            break
                    ok_count += 1
                cfg["banned"] = banned
                _autoban_save(cfg)
                if ok_count == 1:
                    success(f"IP {targets[0]} разбанен")
                else:
                    success(f"Разбанено IP: {ok_count}")

            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            print()
            info("Запуск проверки...")
            n = _autoban_run_once()
            if n:
                success(f"Забанено новых IP: {n}")
            else:
                success("Новых нарушителей не обнаружено")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "6":
            # История банов
            history = cfg.get("ban_history", [])
            os.system("clear")
            print()
            _box_top("📜 История банов (последние 50)")
            if not history:
                _box_row(f"  {DIM}История пуста{NC}")
            else:
                # Заголовок таблицы — две строки чтобы уместиться
                _box_row(f"  {BOLD}{'IP':<18} {'Забанен':<16} {'Разбанен':<16} {'Ош':>3} Причина{NC}")
                _box_row(f"  {'─'*18}  {'─'*16}  {'─'*16}  {'─'*3}  {'─'*15}")
                for rec in reversed(history[-50:]):
                    _ip   = rec.get("ip", "?")
                    _bat  = rec.get("banned_at", "?")[:16].replace("T", " ")
                    _uat  = rec.get("unbanned_at")
                    _uat_s = (_uat[:16].replace("T", " ") if _uat
                              else f"{DIM}активен{NC}")
                    _cnt  = str(rec.get("count", "?"))
                    _rsn  = rec.get("reason", "")
                    # Обрезаем причину чтобы строка влезала
                    # Формула: 2 + 18 + 2 + 16 + 2 + 16 + 2 + 3 + 2 = 63 символа без причины
                    # оставляем на причину _BOX_W - 65 символов
                    _rsn_max = max(_BOX_W - 65, 8)
                    if len(_rsn) > _rsn_max:
                        _rsn = _rsn[:_rsn_max - 1] + "…"
                    _col = DIM if _uat else RED
                    # Строка 1: IP | даты | ошибки | причина
                    _box_row(
                        f"  {_col}{_ip:<18}{NC} {_bat:<16} {_uat_s:<16} "
                        f"{_cnt:>3}  {DIM}{_rsn}{NC}"
                    )
                    # Строка 2: ASN + провайдер
                    asn_info = _lookup_asn(_ip)
                    asn_str  = _fmt_asn_short(asn_info)
                    if asn_str:
                        _asn_max = _BOX_W - 6
                        if len(asn_str) > _asn_max:
                            asn_str = asn_str[:_asn_max - 1] + "…"
                        _box_row(f"    {DIM}↳ {asn_str}{NC}")
            _box_item("C", "Очистить историю")
            _box_bottom()
            # Путь к файлу полного отчёта — вне рамки, всегда виден
            print()
            _report_exists = _XRAY_BAN_REPORT.exists()
            _report_status = (f"{GREEN}существует{NC}" if _report_exists
                              else f"{YELLOW}не создан (появится после первого бана){NC}")
            print(f"  {DIM}Полный лог:{NC} {CYAN}{_XRAY_BAN_REPORT}{NC}  [{_report_status}]")
            if _report_exists:
                try:
                    _rsz   = _XRAY_BAN_REPORT.stat().st_size
                    _rage  = (time.time() - _XRAY_BAN_REPORT.stat().st_mtime) / 86400
                    _rsz_s = f"{_rsz // 1024} КБ" if _rsz >= 1024 else f"{_rsz} Б"
                    _rot_in = max(0.0, _BAN_REPORT_TTL_DAYS - _rage)
                    print(f"  {DIM}Размер: {_rsz_s}  │  Ротация через: {_rot_in:.1f} дн.{NC}")
                except Exception:
                    pass
            print()
            # Вывод детального отчёта из файла (если есть)
            _ban_report_show_in_box()
            _hch = input(f"{CYAN}Выбор [Enter — назад]:{NC} ").strip().lower()
            if _hch == "c":
                ans = input(f"  {RED}Удалить всю историю банов? [y/N]:{NC} ").strip().lower()
                if ans == "y":
                    cfg["ban_history"] = []
                    _autoban_save(cfg)
                    success("История очищена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            wl = cfg.get("whitelist", list(_BAN_WHITELIST_DEFAULT))
            chain_ips = _autoban_get_chain_ips()
            print()
            _box_top("Whitelist (эти IP никогда не баним)")
            for i, ip in enumerate(wl, 1):
                _box_item(f"{i}", f"{ip}")
            if chain_ips:
                _box_sep()
                _box_row(f"  {DIM}Автозащита — IP нод каскада (всегда в whitelist):{NC}")
                for ip in chain_ips:
                    in_wl = "  (уже в whitelist)" if ip in wl else ""
                    _box_row(f"    {DIM}• {ip}{in_wl}{NC}")
            _box_sep()
            _box_item("+", f"Добавить IP")
            _box_item("-", f"Удалить IP")
            _box_bottom()
            act = input("  Действие [+/-/Enter]: ").strip()
            if act == "+":
                new_ip = input("  IP для whitelist: ").strip()
                if new_ip and new_ip not in wl:
                    wl.append(new_ip)
                    cfg["whitelist"] = wl
                    _autoban_save(cfg)
                    success(f"Добавлен в whitelist: {new_ip}")
            elif act == "-":
                raw_n = input("  Номер для удаления: ").strip()
                if raw_n.isdigit() and 1 <= int(raw_n) <= len(wl):
                    removed = wl.pop(int(raw_n)-1)
                    cfg["whitelist"] = wl
                    _autoban_save(cfg)
                    success(f"Удалён из whitelist: {removed}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  ФИЧА 2: МОНИТОРИНГ CERTBOT RENEW + АЛЕРТ
# =============================================================================
_CERTBOT_MONITOR_CRON   = Path("/etc/cron.d/xray-certbot-monitor")
_CERTBOT_MONITOR_SCRIPT = Path("/usr/local/bin/xray-certbot-monitor.sh")


def _certbot_renew_and_notify() -> bool:
    """Запускает certbot renew, при ошибке шлёт Telegram."""
    domain = ""
    try:
        if STATE_FILE.exists():
            domain = json.loads(STATE_FILE.read_text()).get("domain", "")
    except Exception:
        pass

    certbot = next(
        (p for p in (Path("/snap/bin/certbot"), Path("/usr/bin/certbot"))
         if p.exists()), None
    )
    if not certbot:
        warn("certbot не найден")
        return False

    info("Запуск certbot renew...")
    r = _run([str(certbot), "renew", "--quiet", "--non-interactive"],
             check=False, capture=True)
    ok = r.returncode == 0

    if ok:
        # Проверяем сколько дней осталось
        if domain:
            cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
            if cert.exists():
                try:
                    r2 = _run(["openssl", "x509", "-in", str(cert),
                               "-noout", "-enddate"], capture=True, check=False)
                    expiry = r2.stdout.strip().split("=", 1)[1]
                    r3 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
                    days = (int(r3.stdout.strip()) - int(time.time())) // 86400
                    if days > 30:
                        success(f"SSL сертификат действителен: {days} дн.")
                    else:
                        warn(f"SSL истекает через {days} дн.!")
                        _tg_notify_event("cert_expire",
                            f"⚠️ certbot renew OK, но срок истекает через {days} дн.! Домен: {domain}")
                except Exception:
                    pass
        log_to_file("INFO", "certbot renew: success")
        _log_change("certbot_renew", f"SSL сертификат успешно обновлён ({domain})")
    else:
        err = (r.stdout + r.stderr)[:300]
        warn(f"certbot renew завершился с ошибкой:\n{err}")
        log_to_file("ERROR", f"certbot renew failed: {err}")
        _tg_notify_event("cert_expire",
            f"❌ certbot renew <b>FAILED</b>!\nДомен: {domain}\n<code>{err[:200]}</code>")

    return ok


def _certbot_install_monitor_cron() -> None:
    """Cron дважды в день: certbot renew + проверка срока."""
    domain = ""
    try:
        if STATE_FILE.exists():
            domain = json.loads(STATE_FILE.read_text()).get("domain", "")
    except Exception:
        pass

    sh = _CERTBOT_MONITOR_SCRIPT
    sh.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Certbot renew monitor (VLESS Installer)
        LOG="/var/log/xray-certbot-monitor.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        DOMAIN="{domain}"
        TG_CONFIG="/var/lib/xray-installer/telegram.json"

        send_tg() {{
            python3 -c "
import json, subprocess, sys
from pathlib import Path
msg=sys.argv[1]
try:
    cfg=json.loads(Path('$TG_CONFIG').read_text())
    t,c=cfg.get('token'),cfg.get('chat_id')
    if t and c:
        subprocess.run(['curl','-s','-o','/dev/null','-m','10',
            f'https://api.telegram.org/bot{{t}}/sendMessage',
            '-d',f'chat_id={{c}}','-d',f'text={{msg}}'],capture_output=True)
except: pass
" "$1"
        }}

        echo "[$DATE] Running certbot renew..." >> "$LOG"
        if certbot renew --quiet --non-interactive >> "$LOG" 2>&1; then
            echo "[$DATE] certbot renew OK" >> "$LOG"
            # Проверяем срок
            if [ -n "$DOMAIN" ]; then
                CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
                if [ -f "$CERT" ]; then
                    EXPIRY=$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | cut -d= -f2)
                    EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
                    DAYS=$(( (EPOCH - $(date +%s)) / 86400 ))
                    echo "[$DATE] SSL days left: $DAYS" >> "$LOG"
                    if [ "$DAYS" -lt 14 ]; then
                        send_tg "⚠️ SSL сертификат истекает через $DAYS дн.! Домен: $DOMAIN"
                    fi
                fi
            fi
        else
            echo "[$DATE] certbot renew FAILED" >> "$LOG"
            send_tg "❌ certbot renew FAILED для домена $DOMAIN. Проверьте логи!"
        fi
        # Перезагружаем nginx после обновления
        systemctl reload nginx >> "$LOG" 2>&1 || true
    """))
    sh.chmod(0o750)
    # Дважды в день: 03:00 и 15:00
    _CERTBOT_MONITOR_CRON.write_text(
        f"0 3,15 * * * root {sh} >> /var/log/xray-certbot-monitor.log 2>&1\n"
    )
    _CERTBOT_MONITOR_CRON.chmod(0o644)
    success("Certbot monitor cron установлен (03:00 и 15:00 ежедневно)")


def do_manage_certbot_monitor() -> None:
    """Меню управления мониторингом SSL-сертификата."""
    while True:
        os.system("clear")
        cron_active = _CERTBOT_MONITOR_CRON.exists()
        domain = ""
        days_left = 0
        try:
            if STATE_FILE.exists():
                domain = json.loads(STATE_FILE.read_text()).get("domain", "")
            if domain:
                cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
                if cert.exists():
                    r = _run(["openssl", "x509", "-in", str(cert),
                              "-noout", "-enddate"], capture=True, check=False)
                    expiry = r.stdout.strip().split("=", 1)[1]
                    r2 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
                    days_left = (int(r2.stdout.strip()) - int(time.time())) // 86400
        except Exception:
            pass

        print()
        _box_top(f"Мониторинг SSL-сертификата")
        _box_row(f"  Домен:        {CYAN}{domain or '—'}{NC}")
        if days_left:
            col = GREEN if days_left > 30 else YELLOW if days_left > 14 else RED
            _box_row(f"  Срок:         {col}{days_left} дн. до истечения{NC}")
        _box_row(f"  Cron (2×день): {''+GREEN+'ВКЛЮЧЁН'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЁН'+NC}")
        _box_item("1", f"{'Отключить' if cron_active else 'Включить'} авто-мониторинг (03:00 + 15:00)")
        _box_item("2", f"Запустить certbot renew прямо сейчас")
        _box_item("3", f"Показать лог")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if cron_active:
                _CERTBOT_MONITOR_CRON.unlink(missing_ok=True)
                _CERTBOT_MONITOR_SCRIPT.unlink(missing_ok=True)
                success("Certbot monitor отключён")
            else:
                _certbot_install_monitor_cron()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            print()
            _certbot_renew_and_notify()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            lp = Path("/var/log/xray-certbot-monitor.log")
            if lp.exists():
                print()
                print('\n'.join(lp.read_text().splitlines()[-30:]))
            else:
                warn("Лог пуст")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  ФИЧА 3: БЫСТРЫЙ СТАТУС --status (CLI без интерактива)
# =============================================================================
def do_quick_status() -> None:
    """
    Быстрый статус одной командой: python3 install.py --status
    Показывает всё самое важное за ~2 секунды без входа в меню.
    """
    print()
    _box_top("HYDRA Quick Status")
    ts = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    _box_row(f"  {DIM}{ts}{NC}")

    # ── Сервисы ─────────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}Сервисы:{NC}")
    for svc in ("xray", "nginx", "dnscrypt-proxy"):
        r = _run(["systemctl", "is-active", svc], capture=True, check=False)
        st = r.stdout.strip()
        if st == "active":
            _box_row(f"  {GREEN}●{NC} {svc:<22} {GREEN}активен{NC}")
        elif st == "inactive":
            _box_row(f"  {DIM}○{NC} {svc:<22} {DIM}не запущен{NC}")
        else:
            _box_row(f"  {RED}✗{NC} {svc:<22} {RED}{st}{NC}")

    # ── Конфигурация ─────────────────────────────────────────────────────────
    try:
        if STATE_FILE.exists():
            _qs    = json.loads(STATE_FILE.read_text())
            _dom = _qs.get("sub_domain") or _qs.get("domain", "")
            _users_n = len(_qs.get("users", {}))
            _box_row(f"  {BOLD}HYDRA:{NC}")
            _box_row(f"  {CYAN}👥{NC} {'Пользователей:':<22} {_users_n}")
            if _dom:
                _box_row(f"  {CYAN}🌐{NC} {'Домен подписок:':<22} {_dom}")
            _box_row()
    except Exception:
        pass

    # ── Активные соединения ─────────────────────────────────────────────────
    try:
        port = 443
        if STATE_FILE.exists():
            port = json.loads(STATE_FILE.read_text()).get("server_port", 443)
        r = _run(["ss", "-tn", "state", "established"], capture=True, check=False)
        conns = [l for l in r.stdout.splitlines() if f":{port}" in l]
        _box_row(f"  {GREEN}⇄{NC} {'Соединений:':<22} {CYAN}{len(conns)}{NC} на порту {port}")
    except Exception:
        pass

    _box_row()

    # ── SSL ──────────────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}SSL:{NC}")
    domain = ""
    try:
        if STATE_FILE.exists():
            domain = json.loads(STATE_FILE.read_text()).get("domain", "")
    except Exception:
        pass
    if domain:
        cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        if cert.exists():
            try:
                r  = _run(["openssl", "x509", "-in", str(cert),
                           "-noout", "-enddate"], capture=True, check=False)
                ex = r.stdout.strip().split("=", 1)[1]
                r2 = _run(["date", "-d", ex, "+%s"], capture=True, check=False)
                days = (int(r2.stdout.strip()) - int(time.time())) // 86400
                col = GREEN if days > 30 else YELLOW if days > 14 else RED
                _box_row(f"  {col}🔒{NC} {domain:<30} {col}{days} дн.{NC}")
            except Exception:
                _box_row(f"  {DIM}  {domain:<30} (не удалось проверить){NC}")
        else:
            _box_row(f"  {RED}✗{NC} {domain:<30} {RED}сертификат не найден{NC}")
    else:
        _box_row(f"  {DIM}  домен не задан{NC}")


    # ── Трафик за сегодня (из истории) ──────────────────────────────────────
    _box_row(f"  {BOLD}Трафик сегодня:{NC}")
    today = datetime.now().strftime("%Y-%m-%d")
    try:
        if TRAFFIC_HISTORY_FILE.exists():
            hist    = json.loads(TRAFFIC_HISTORY_FILE.read_text())
            day     = hist.get(today, {})
            users   = _users_from_state()
            total_b = 0
            for u in users:
                email = u.get("email", "")
                val   = day.get(f"{email}_max", 0)
                total_b += val
                if val > 0:
                    icon  = _device_icon(u.get("device_label", ""))
                    label = u.get("device_label") or u.get("name", email)
                    _box_row(f"  {icon} {label:<24} {CYAN}{_fmt_bytes_ru(val)}{NC}")
            if not users or total_b == 0:
                _box_row(f"  {DIM}нет данных (включите сбор снимков: > → 1){NC}")
        else:
            _box_row(f"  {DIM}история не ведётся (включите: > → 1){NC}")
    except Exception:
        _box_row(f"  {DIM}не удалось прочитать{NC}")


    # ── Диск и RAM ──────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}Ресурсы:{NC}")
    try:
        r = _run(["df", "-h", "/"], capture=True, check=False)
        p = r.stdout.splitlines()[-1].split()
        pct = float(p[4].replace("%", ""))
        col = GREEN if pct < 80 else YELLOW if pct < 90 else RED
        _box_row(f"  {col}💾{NC} {'Диск /:':<22} {p[2]}/{p[1]} ({col}{pct:.0f}%{NC})")
    except Exception:
        pass
    try:
        mi = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            mi[k.strip()] = int(v.strip().split()[0])
        total_mb = mi.get("MemTotal", 0) // 1024
        used_mb  = total_mb - mi.get("MemAvailable", 0) // 1024
        pct      = used_mb * 100 // max(total_mb, 1)
        col = GREEN if pct < 80 else YELLOW if pct < 90 else RED
        _box_row(f"  {col}🧠{NC} {'RAM:':<22} {used_mb}/{total_mb} МБ ({col}{pct}%{NC})")
    except Exception:
        pass

    _box_row()

    # ── Автобан ──────────────────────────────────────────────────────────────
    try:
        ban_cfg = _autoban_load()
        n_banned = len(ban_cfg.get("banned", {}))
        if n_banned:
            _box_row(f"  {RED}🚫{NC} Забанено IP:           {RED}{n_banned}{NC}")
    except Exception:
        pass

    _box_bottom()


# =============================================================================
#  ФИЧА 4: СОРТИРОВКА В СТАТИСТИКЕ ПОЛЬЗОВАТЕЛЕЙ
# =============================================================================
# (интегрируется в _do_user_stats_screen через аргумент sort_key)
# Реализована как отдельная обёртка, которая вызывается из меню U→4

_STATS_SORT_KEYS = {
    "1": ("traffic", "По трафику ↓"),
    "2": ("last",    "По последнему визиту"),
    "3": ("name",    "По имени"),
    "4": ("label",   "По метке устройства"),
}


# =============================================================================
#  ФИЧА 5: ЭКСПОРТ СТАТИСТИКИ В CSV
# =============================================================================
# =============================================================================
#  ФИЧА 6: ВРЕМЕННОЕ ОТКЛЮЧЕНИЕ ПОЛЬЗОВАТЕЛЯ (БЕЗ УДАЛЕНИЯ)
# =============================================================================
# =============================================================================
#  ФИЧА 7: ТЕСТ КАЧЕСТВА СОЕДИНЕНИЯ ЧЕРЕЗ EXIT-НОДУ (TTFB)
# =============================================================================
_TTFB_TARGETS = [
    ("Cloudflare",  "https://1.1.1.1/cdn-cgi/trace"),
    ("Google",      "https://www.google.com/generate_204"),
    ("Яндекс",      "https://ya.ru"),
    ("GitHub",      "https://github.com"),
]


def do_connection_quality_test() -> None:
    """
    Тест качества соединения: TTFB (время до первого байта) к нескольким сайтам.
    Запускается без прокси (прямое соединение с сервера) — показывает реальную
    задержку для пользователей при split-tunnel или после выхода через exit-ноду.
    """
    os.system("clear")
    print()
    _box_top(f"Тест качества соединения (TTFB)")
    _box_row(f"  {DIM}Измеряет время до первого байта с сервера (реальная задержка для клиентов){NC}")

    results = []
    for name, url in _TTFB_TARGETS:
        _box_info(f"  Тест {name}...")
        ttfb_ms = None
        http_code = "—"
        try:
            r = _run([
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{time_starttransfer}|%{http_code}|%{time_connect}|%{time_namelookup}",
                "--max-time", "10",
                "--connect-timeout", "5",
                url,
            ], capture=True, check=False)
            if r.returncode == 0 and r.stdout.strip():
                parts = r.stdout.strip().split("|")
                ttfb_ms   = int(float(parts[0]) * 1000)
                http_code = parts[1]
                connect_ms = int(float(parts[2]) * 1000)
                dns_ms    = int(float(parts[3]) * 1000)
                results.append((name, url, ttfb_ms, http_code, connect_ms, dns_ms))
            else:
                results.append((name, url, None, "err", 0, 0))
        except Exception as e:
            results.append((name, url, None, "err", 0, 0))

    _box_row()
    _box_row(f"  {BOLD}{'Сайт':<14} {'TTFB':>8} {'Подключение':>12} {'DNS':>8} {'HTTP':>6}{NC}")
    _box_row(f"  {'─'*14} {'─'*8} {'─'*12} {'─'*8} {'─'*6}")

    for name, url, ttfb, code, conn, dns in results:
        if ttfb is None:
            _box_row(f"  {name:<14} {RED}{'недост.':>8}{NC} {'—':>12} {'—':>8} {RED}{code:>6}{NC}")
        else:
            t_col = GREEN if ttfb < 200 else YELLOW if ttfb < 500 else RED
            c_col = GREEN if conn < 100 else YELLOW if conn < 300 else RED
            _box_row(f"  {name:<14} "
                  f"{t_col}{ttfb:>6} мс{NC} "
                  f"{c_col}{conn:>10} мс{NC} "
                  f"{DIM}{dns:>6} мс{NC} "
                  f"{GREEN if code in ('200','204') else YELLOW}{code:>6}{NC}")

    # Итог
    valid = [r for r in results if r[2] is not None]
    if valid:
        avg_ttfb = sum(r[2] for r in valid) // len(valid)
        _box_row()
        col = GREEN if avg_ttfb < 200 else YELLOW if avg_ttfb < 500 else RED
        _box_row(f"  {BOLD}Средний TTFB: {NC}{col}{avg_ttfb} ms{NC}")
        if avg_ttfb < 150:
            _box_row(f"  {GREEN}✓ Отличное качество соединения{NC}")
        elif avg_ttfb < 300:
            _box_row(f"  {YELLOW}~ Хорошее качество, небольшая задержка{NC}")
        elif avg_ttfb < 600:
            _box_row(f"  {YELLOW}⚠ Повышенная задержка — проверьте нагрузку сервера{NC}")
        else:
            _box_row(f"  {RED}✗ Высокая задержка — возможны проблемы{NC}")
        _box_row()
        _box_bottom()

    log_to_file("INFO", f"TTFB test: avg={avg_ttfb if valid else 'n/a'} ms")
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ФИЧА 8: ЛОГ ИЗМЕНЕНИЙ КОНФИГА
# =============================================================================
CHANGES_LOG_FILE = Path("/var/log/xray-changes.log")
CHANGES_DB_FILE  = Path("/var/lib/xray-installer/changes.json")


def _log_change(action: str, detail: str, user: str = "root") -> None:
    """
    Записывает изменение конфигурации в лог и JSON-базу.
    Вызывается из любого места скрипта при изменении настроек.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Текстовый лог
    try:
        CHANGES_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with CHANGES_LOG_FILE.open("a") as f:
            f.write(f"[{ts}] [{action.upper():<20}] {detail}\n")
        CHANGES_LOG_FILE.chmod(0o640)
    except Exception:
        pass
    # JSON-база (последние 500 записей)
    try:
        CHANGES_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            db = json.loads(CHANGES_DB_FILE.read_text()) if CHANGES_DB_FILE.exists() else []
        except Exception:
            db = []
        db.append({"ts": ts, "action": action, "detail": detail, "user": user})
        # Ротация: оставляем последние 500
        db = db[-500:]
        CHANGES_DB_FILE.write_text(json.dumps(db, indent=2, ensure_ascii=False))
        CHANGES_DB_FILE.chmod(0o600)
    except Exception:
        pass


def do_view_changes_log() -> None:
    """Интерактивный просмотр лога изменений конфигурации."""
    while True:
        os.system("clear")
        print()
        _box_top(f"Лог изменений конфигурации")

        try:
            db = json.loads(CHANGES_DB_FILE.read_text()) if CHANGES_DB_FILE.exists() else []
        except Exception:
            db = []

        if not db:
            _box_row(f"  {DIM}Изменений пока не записано.{NC}")
            _box_row(f"  {DIM}Лог заполняется автоматически при изменении конфига.{NC}")
        else:
            _box_row(f"  Всего записей: {CYAN}{len(db)}{NC}")
            # Иконки по типу действия
            icons = {
                "user_add":       "👤+",
                "user_del":       "👤-",
                "user_toggle":    "👤⏸",
                "certbot_renew":  "🔒",
                "stats_export":   "📊",
                "geoip":          "🛡️",
                "tg":             "📬",
                "uuid_rotate":    "🔑",
                "reconfigure":    "🔄",
                "install":        "🚀",
                "ssh_hardening":  "🔒",
                "migration":      "📦",
                "as_routing":     "🔀",
            }
            # Группировка по дате
            by_date: dict = {}
            for entry in db:
                date = entry["ts"][:10]
                by_date.setdefault(date, []).append(entry)

            dates = sorted(by_date.keys(), reverse=True)
            for date in dates[:7]:  # последние 7 дней
                entries = by_date[date]
                _box_row(f"  {BOLD}{CYAN}{date}{NC}  {DIM}({len(entries)} изменений){NC}")
                for e in reversed(entries[-20:]):  # последние 20 за день
                    action = e.get("action", "")
                    icon   = next((v for k, v in icons.items()
                                   if k in action.lower()), "⚙️")
                    ts_short = e["ts"][11:16]
                    detail   = e.get("detail", "")[:60]
                    _box_row(f"  {DIM}{ts_short}{NC}  {icon}  {detail}")

        _box_item("1", f"Показать полный лог (tail)")
        _box_item("2", f"Фильтр по типу действия")
        _box_item("3", f"Очистить лог")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if CHANGES_LOG_FILE.exists():
                lines = CHANGES_LOG_FILE.read_text().splitlines()[-50:]
                print()
                for line in lines:
                    print(f"  {DIM}{line}{NC}")
            else:
                warn("Лог-файл пуст")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw_filter = input("  Тип действия (например: user, cert, geoip): ").strip().lower()
            if raw_filter and db:
                filtered = [e for e in db if raw_filter in e.get("action", "").lower()
                            or raw_filter in e.get("detail", "").lower()]
                print()
                for e in filtered[-30:]:
                    print(f"  {DIM}{e['ts']}{NC}  [{e['action']}]  {e['detail'][:60]}")
                if not filtered:
                    warn("Ничего не найдено")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            ans = input(f"  {YELLOW}Очистить лог изменений? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                CHANGES_LOG_FILE.unlink(missing_ok=True)
                CHANGES_DB_FILE.unlink(missing_ok=True)
                success("Лог очищен")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


#  ГЛАВНОЕ МЕНЮ
# =============================================================================

# =============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ: ОТРИСОВКА МЕНЮ В СТИЛЕ БАННЕРА VLESS
# box_renderer — перенесено в vless_installer/modules/box_renderer.py
# =============================================================================
#  ПОДМЕНЮ: 1 — УСТАНОВКА И СИСТЕМА
# =============================================================================
def _menu_install_system() -> None:
    while True:
        os.system("clear")
        print()
        _box_top("⚙️  УСТАНОВКА И СИСТЕМА")
        _box_row()
        _box_item("1", f"🚀 Установить HYDRA  {DIM}(мастер: Naive / Mieru / AWG / фон){NC}")
        _box_item("2", f"📦 Миграция  {DIM}(Экспорт / Импорт конфигурации){NC}")
        _box_item("3", f"⚡ Оптимизация системы  {DIM}(Sysctl / Limits){NC}")
        _box_item("4", "🗑️  Удалить установку")
        _box_item("5", "🧪 Запустить unit-тесты")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            from vless_installer.modules.hydra_setup import do_hydra_setup_wizard
            do_hydra_setup_wizard()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            _menu_migration()
        elif ch == "3":
            info("Применение оптимизаций sysctl/limits...")
            apply_sysctl_and_limits()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            ans = input(f"{RED}Удалить установку HYDRA? [y/N]:{NC} ").strip().lower()
            if ans == 'y':
                do_uninstall()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            run_unit_tests()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


def _menu_migration() -> None:
    """Подменю миграции (экспорт/импорт)."""
    while True:
        os.system("clear")
        print()
        _box_top("📦  МИГРАЦИЯ КОНФИГУРАЦИИ")
        _box_row()
        _box_item("1", f"📤 Экспорт  {DIM}(зашифрованный архив){NC}")
        _box_item("2", f"📥 Импорт  {DIM}(восстановить из .tar.gz или .tar.gz.enc){NC}")
        _box_item("3", f"📄 Стандартный экспорт  {DIM}(без шифрования){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_hydra_export_backup(encrypt=True)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            do_hydra_import_backup()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            do_hydra_export_backup(encrypt=False)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ПОДМЕНЮ: 2 — УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# =============================================================================
# _menu_users deleted in favor of subscription system

# =============================================================================
#  ПОДМЕНЮ: 3 — НАСТРОЙКИ СЕТИ
# =============================================================================

# =============================================================================
#  УПРАВЛЕНИЕ XTLS-FLOW (Vision / Splice / none)
# =============================================================================
def configure_system_dns_for_dnscrypt(enable: bool) -> None:
    """Настраивает system-wide DNS для использования DNSCrypt-proxy."""
    # 1. Настройка systemd-resolved
    resolved_conf = Path("/etc/systemd/resolved.conf")
    if resolved_conf.exists():
        try:
            content = resolved_conf.read_text(encoding="utf-8")
            lines = []
            for line in content.splitlines():
                if not line.strip().startswith("DNS=") and not line.strip().startswith("Domains="):
                    lines.append(line)
            
            if enable:
                new_lines = []
                for line in lines:
                    new_lines.append(line)
                    if line.strip() == "[Resolve]":
                        new_lines.append(f"DNS=127.0.0.1:{DNSCRYPT_LISTEN_PORT}")
                        new_lines.append("Domains=~.")
                content = "\n".join(new_lines)
            else:
                content = "\n".join(lines)
                
            resolved_conf.write_text(content, encoding="utf-8")
            _run(["systemctl", "restart", "systemd-resolved"], check=False, quiet=True)
            if enable:
                success("systemd-resolved настроен на использование DNSCrypt-proxy")
            else:
                success("systemd-resolved возвращен к стандартным настройкам")
        except Exception as e:
            warn(f"Ошибка настройки systemd-resolved: {e}")

    # 2. Настройка правил перенаправления DNS (iptables NAT REDIRECT) для внутренних подсетей (Docker, VPN, Tunnels)
    try:
        if enable:
            for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
                # UDP
                r = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-s", subnet, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNSCRYPT_LISTEN_PORT)], check=False, quiet=True)
                if r.returncode != 0:
                    _run(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", subnet, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNSCRYPT_LISTEN_PORT)], check=False, quiet=True)
                # TCP
                r_tcp = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-s", subnet, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNSCRYPT_LISTEN_PORT)], check=False, quiet=True)
                if r_tcp.returncode != 0:
                    _run(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", subnet, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNSCRYPT_LISTEN_PORT)], check=False, quiet=True)
            success("Правила iptables NAT REDIRECT для DNS настроены")
        else:
            for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
                while True:
                    r = _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", subnet, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNSCRYPT_LISTEN_PORT)], check=False, quiet=True)
                    if r.returncode != 0:
                        break
                while True:
                    r = _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", subnet, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNSCRYPT_LISTEN_PORT)], check=False, quiet=True)
                    if r.returncode != 0:
                        break
            success("Правила iptables NAT REDIRECT для DNS удалены")

        # Сохранение правил iptables
        if Path("/etc/iptables").exists():
            r4 = _run(["iptables-save"], capture=True, check=False)
            Path("/etc/iptables/rules.v4").write_text(r4.stdout)
    except Exception as e:
        warn(f"Ошибка настройки iptables NAT для DNS: {e}")


def _save_global_state(data: dict) -> None:
    try:
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
        state.update(data)
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"Не удалось обновить state.json: {e}")


def do_manage_dnscrypt() -> None:
    global PARAM_USE_DNSCRYPT
    while True:
        os.system("clear")
        _load_state_into_globals()
        
        # Проверяем статус службы
        r_active = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
        active_status = r_active.stdout.strip()
        status_color = GREEN if active_status == "active" else RED
        
        # Получаем список выбранных резолверов
        server_names = []
        if DNSCRYPT_CONF.exists():
            try:
                content = DNSCRYPT_CONF.read_text(encoding="utf-8")
                m = re.search(r'^server_names\s*=\s*(.+)$', content, re.MULTILINE)
                if m:
                    server_names = json.loads(m.group(1).replace("'", '"'))
            except Exception:
                pass
        
        print()
        _box_top("🔒 УПРАВЛЕНИЕ DNSCRYPT-PROXY")
        _box_row(f"  Статус системы:   {'Используется' if PARAM_USE_DNSCRYPT else 'Отключена'}")
        _box_row(f"  Статус службы:    {status_color}{active_status.upper()}{NC}")
        _box_row(f"  Порт прослушивания: {DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}")
        if server_names:
            _box_row(f"  Выбранные DNS:    {CYAN}{', '.join(server_names)}{NC}")
        else:
            _box_row(f"  Выбранные DNS:    {DIM}автовыбор (все доступные){NC}")
        _box_sep()
        _box_row()
        if PARAM_USE_DNSCRYPT:
            _box_item("1", f"{RED}Отключить DNSCrypt-proxy системно{NC}")
        else:
            _box_item("1", f"{GREEN}Включить DNSCrypt-proxy системно{NC}")
        _box_item("2", "⚡ Выбрать быстрые резолверы (latency RTT тест)")
        _box_item("3", "🔄 Переустановить / Обновить DNSCrypt-proxy")
        _box_row()
        _box_back()
        _box_bottom()
        
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
            
        if ch in ("0", "q", "Q", ""):
            break
        elif ch == "1":
            if PARAM_USE_DNSCRYPT:
                info("Отключение DNSCrypt-proxy системно...")
                PARAM_USE_DNSCRYPT = False
                _save_global_state({"use_dnscrypt": False})
                configure_system_dns_for_dnscrypt(False)
                _run(["systemctl", "stop", "dnscrypt-proxy"], check=False, quiet=True)
                success("DNSCrypt-proxy отключен")
            else:
                 info("Включение DNSCrypt-proxy системно...")
                 PARAM_USE_DNSCRYPT = True
                 _save_global_state({"use_dnscrypt": True})
                 if not DNSCRYPT_BIN.exists():
                     install_dnscrypt(force=True)
                 else:
                     _run(["systemctl", "start", "dnscrypt-proxy"], check=False, quiet=True)
                 configure_system_dns_for_dnscrypt(True)
                 success("DNSCrypt-proxy включен")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            if not DNSCRYPT_BIN.exists():
                warn("Сначала установите и включите DNSCrypt-proxy")
                time.sleep(2)
                continue
            try:
                do_dnscrypt_selector_menu()
            except Exception as e:
                warn(f"Ошибка селектора: {e}")
                time.sleep(2)
        elif ch == "3":
            ans = input(f"{YELLOW}Переустановить DNSCrypt-proxy? [y/N]:{NC} ").strip().lower()
            if ans == 'y':
                try:
                    DNSCRYPT_BIN.unlink(missing_ok=True)
                except Exception:
                    pass
                install_dnscrypt(force=True)
                if PARAM_USE_DNSCRYPT:
                    configure_system_dns_for_dnscrypt(True)
            input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_network() -> None:
    while True:
        os.system("clear")
        _load_state_into_globals()
        print()
        _box_top("🌐  НАСТРОЙКИ СЕТИ")
        _box_row()
        _box_item("1", f"☁️  Cloudflare WARP  {DIM}(управление туннелем){NC}")
        _box_item("2", "🌐 Внешняя проверка домена / порта")
        _box_item("3", "🌐 Геопроверка выходного IP")
        _box_item("4", f"🔒 DNSCrypt-proxy  {DIM}(управление и latency тест){NC}")
        _box_sep()
        _box_item("M", f"📏 MTU/MSS автотюнинг  {DIM}(оптимизация uplink){NC}")
        _box_item("5", f"🔬 Диагностика сети HYDRA  {DIM}(стек AWG/WARP/DNS){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_manage_warp()
        elif ch == "2":
            _box_top("Внешняя проверка домена")
            do_check_domain_external()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            check_exit_geo(silent=False)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            do_manage_dnscrypt()
        elif ch.lower() == "m":
            do_mtu_tuning()
        elif ch == "5":
            from vless_installer.modules.network_mtu import do_network_diagnostics_menu
            do_network_diagnostics_menu()
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


def do_dns_leak_test() -> None:
    """
    DNS Leak Test — проверяет, через какие DNS-серверы уходят запросы.

    Логика теста:
      1. Генерирует уникальный токен и делает серию DNS-запросов к
         <token>.dns-leak.com и whoami.akamai.net через dig / nslookup.
      2. Параллельно запрашивает публичные API (dnsleaktest.com, ipleak.net,
         browserleaks.com/dns) — каждый возвращает IP DNS-резолверов,
         которые до них «дошли».
      3. Определяет GeoIP каждого найденного резолвера через ip-api.com (batch).
      4. Сравнивает страны резолверов с ожидаемой (страна exit-ноды или
         страна сервера если Режим A).
      5. Если найден резолвер в RU — предупреждение об утечке.
      6. Проверяет что настроенный DNS (DNSCrypt / AdGuard / 1.1.1.1) совпадает
         с реально используемым резолвером.

    Не требует клиента — всё выполняется на стороне сервера.
    """
    os.system("clear")
    print()
    _box_top("🔍  DNS LEAK TEST")
    _box_row(f"  {DIM}Проверяет, через какие DNS-серверы уходят запросы с этого сервера.{NC}")
    _box_row(f"  {DIM}Утечка DNS = запросы попадают к провайдеру / российским серверам.{NC}")
    _box_row()

    resolvers_found: list[dict] = []  # {ip, source, country, cc, isp}

    # ── Метод 1: dnsleaktest.com API ─────────────────────────────────────────
    _box_info("Метод 1/4: dnsleaktest.com API...")
    try:
        import uuid as _uuid
        token = _uuid.uuid4().hex[:12]
        # Шаг 1 — инициализация сессии (получаем id)
        r_init = _run(
            ["curl", "-s", "--max-time", "10",
             f"https://www.dnsleaktest.com/"],
            capture=True, check=False
        )
        # Прямой запрос к API endpoint
        r_api = _run(
            ["curl", "-s", "--max-time", "15",
             "-H", "Accept: application/json",
             "https://www.dnsleaktest.com/api/v1/leak-test/start"],
            capture=True, check=False
        )
        if r_api.returncode == 0 and r_api.stdout.strip().startswith("{"):
            api_data = json.loads(r_api.stdout.strip())
            test_id = api_data.get("id") or api_data.get("test_id", "")
            if test_id:
                time.sleep(3)
                r_res = _run(
                    ["curl", "-s", "--max-time", "15",
                     f"https://www.dnsleaktest.com/api/v1/leak-test/{test_id}/results"],
                    capture=True, check=False
                )
                if r_res.returncode == 0 and r_res.stdout.strip():
                    try:
                        res_data = json.loads(r_res.stdout.strip())
                        servers = res_data if isinstance(res_data, list) else res_data.get("servers", [])
                        for srv in servers:
                            ip = srv.get("ip", "")
                            if ip:
                                resolvers_found.append({
                                    "ip": ip,
                                    "source": "dnsleaktest.com",
                                    "country": srv.get("country", "?"),
                                    "cc": srv.get("country_code", "?"),
                                    "isp": srv.get("isp", "?"),
                                })
                        if resolvers_found:
                            _box_row(f"  {GREEN}✓ dnsleaktest.com: найдено {len(resolvers_found)} резолвер(ов){NC}")
                    except Exception:
                        pass
    except Exception:
        pass
    if not any(r["source"] == "dnsleaktest.com" for r in resolvers_found):
        _box_row(f"  {DIM}dnsleaktest.com API недоступен — пропускаем{NC}")

    # ── Метод 2: ipleak.net API ───────────────────────────────────────────────
    _box_info("Метод 2/4: ipleak.net...")
    try:
        r2 = _run(
            ["curl", "-s", "--max-time", "12",
             "https://ipleak.net/json/"],
            capture=True, check=False
        )
        if r2.returncode == 0 and r2.stdout.strip():
            d2 = json.loads(r2.stdout.strip())
            # ipleak.net возвращает один объект с полем dns_servers или inline IP
            dns_list = d2.get("dns_servers") or d2.get("dns") or []
            if isinstance(dns_list, list):
                for entry in dns_list:
                    ip = entry if isinstance(entry, str) else entry.get("ip", "")
                    if ip and not any(r["ip"] == ip for r in resolvers_found):
                        resolvers_found.append({
                            "ip": ip,
                            "source": "ipleak.net",
                            "country": "?",
                            "cc": "?",
                            "isp": "?",
                        })
            # Иногда возвращает только один IP — тоже берём
            elif d2.get("ip"):
                ip = d2["ip"]
                if not any(r["ip"] == ip for r in resolvers_found):
                    resolvers_found.append({
                        "ip": ip,
                        "source": "ipleak.net (query IP)",
                        "country": d2.get("country_name", "?"),
                        "cc": d2.get("country_code", "?"),
                        "isp": d2.get("isp", d2.get("org", "?")),
                    })
            _box_row(f"  {GREEN}✓ ipleak.net: данные получены{NC}")
    except Exception:
        _box_row(f"  {DIM}ipleak.net недоступен{NC}")

    # ── Метод 3: dig / nslookup к whoami-резолверам ───────────────────────────
    _box_info("Метод 3/4: dig whoami-запросы (локальный резолвер)...")
    _whoami_targets = [
        ("whoami.akamai.net",  "akamai"),
        ("whoami.ipv4.akamai.net", "akamai-v4"),
        ("o-o.myaddr.l.google.com", "google-myaddr"),
    ]

    dig_ips: set[str] = set()
    for fqdn, label in _whoami_targets:
        # dig TXT возвращает IP клиента (= наш резолвер)
        for rec_type in ("TXT", "A"):
            r_dig = _run(
                ["dig", "+short", rec_type, fqdn],
                capture=True, check=False
            )
            if r_dig.returncode == 0 and r_dig.stdout.strip():
                for raw in r_dig.stdout.strip().splitlines():
                    # TXT-запись приходит в кавычках: "1.2.3.4"
                    candidate = raw.strip().strip('"')
                    ip_m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', candidate)
                    if ip_m:
                        dig_ips.add(ip_m.group(1))
            if dig_ips:
                break  # нашли через TXT — не нужен A

    for ip in dig_ips:
        if not any(r["ip"] == ip for r in resolvers_found):
            resolvers_found.append({
                "ip": ip,
                "source": "dig/whoami",
                "country": "?",
                "cc": "?",
                "isp": "?",
            })
    if dig_ips:
        _box_row(f"  {GREEN}✓ dig: найден(ы) резолвер(ы): {', '.join(dig_ips)}{NC}")
    else:
        # Fallback: nslookup
        r_ns = _run(["nslookup", "whoami.akamai.net"], capture=True, check=False)
        if r_ns.returncode == 0:
            for line in r_ns.stdout.splitlines():
                ip_m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_m and "Server" not in line and "Address" in line:
                    ip = ip_m.group(1)
                    if not any(r["ip"] == ip for r in resolvers_found):
                        resolvers_found.append({
                            "ip": ip,
                            "source": "nslookup/whoami",
                            "country": "?",
                            "cc": "?",
                            "isp": "?",
                        })
        _box_row(f"  {DIM}dig не дал результата — использован nslookup{NC}")

    # ── Метод 4: /etc/resolv.conf — что сервер считает своим DNS ─────────────
    _box_info("Метод 4/4: /etc/resolv.conf + systemd-resolved...")
    configured_resolvers: list[str] = []
    try:
        resolv = Path("/etc/resolv.conf").read_text(errors="replace")
        for line in resolv.splitlines():
            if line.strip().startswith("nameserver"):
                ns_ip = line.split()[-1].strip()
                configured_resolvers.append(ns_ip)
    except Exception:
        pass
    # systemd-resolved
    r_sd = _run(["resolvectl", "status"], capture=True, check=False)
    if r_sd.returncode == 0:
        for line in r_sd.stdout.splitlines():
            if "DNS Servers" in line or "Current DNS Server" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    for tok in parts[1].split():
                        ip_m = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', tok.strip())
                        if ip_m and ip_m.group(1) not in configured_resolvers:
                            configured_resolvers.append(ip_m.group(1))

    if configured_resolvers:
        _box_row(f"  {DIM}Настроен DNS: {', '.join(configured_resolvers)}{NC}")
    else:
        _box_row(f"  {DIM}Не удалось определить настроенный DNS{NC}")

    # ── GeoIP для резолверов без страны ──────────────────────────────────────
    needs_geo = [r for r in resolvers_found if r["cc"] == "?"]
    if needs_geo:
        _box_info(f"Определяем GeoIP для {len(needs_geo)} резолвер(ов)...")
        # ip-api.com batch: до 100 IP за раз
        batch_ips = [r["ip"] for r in needs_geo[:50]]
        try:
            batch_payload = json.dumps([
                {"query": ip, "fields": "status,query,country,countryCode,isp"}
                for ip in batch_ips
            ])
            r_geo = _run(
                ["curl", "-s", "--max-time", "15",
                 "-X", "POST",
                 "-H", "Content-Type: application/json",
                 "-d", batch_payload,
                 "http://ip-api.com/batch"],
                capture=True, check=False
            )
            if r_geo.returncode == 0 and r_geo.stdout.strip().startswith("["):
                geo_list = json.loads(r_geo.stdout.strip())
                geo_map = {g["query"]: g for g in geo_list if g.get("status") == "success"}
                for r in resolvers_found:
                    if r["ip"] in geo_map:
                        g = geo_map[r["ip"]]
                        r["country"] = g.get("country", "?")
                        r["cc"]      = g.get("countryCode", "?")
                        r["isp"]     = g.get("isp", "?")
        except Exception:
            pass

    # ── Вывод результатов ────────────────────────────────────────────────────
    # Закрываем верхний бокс (INFO-лог) перед таблицей
    _box_bottom()
    print()

    if not resolvers_found:
        _box_top("Найденные DNS-резолверы")
        _box_warn("Не удалось определить DNS-резолверы — проверьте доступность сети")
        _box_bottom()
        print()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    leak_detected    = False
    ru_resolvers     = []
    foreign_resolvers = []

    # ── Вычисляем ширины колонок динамически под _BOX_W ──────────────────────
    # Структура строки: "  " + IP + " " + Страна + " " + ISP + " " + Источник
    # Левый отступ = 2, разделители между колонками = 1 каждый (3 штуки)
    # Итого служебных: 2 + 3 = 5
    _TBL_INDENT = 2
    _TBL_SEPS   = 3
    _avail = _BOX_W - _TBL_INDENT - _TBL_SEPS   # доступно для данных

    # Фиксированные ширины: IP=15, Источник=14 (max "nslookup/whoami")
    _W_IP  = 15
    _W_SRC = 14
    # Остаток делим: 40% Страна, 60% ISP
    _rem = _avail - _W_IP - _W_SRC
    _W_CC  = max(10, _rem * 38 // 100)
    _W_ISP = _avail - _W_IP - _W_SRC - _W_CC

    def _tbl_row(ip_s: str, cc_s: str, isp_s: str, src_s: str,
                 ip_col: str = "", cc_col: str = "", isp_col: str = "",
                 src_col: str = "") -> None:
        """Печатает строку таблицы внутри рамки через _box_row — правая граница ║ выровнена точно."""
        def _pad(raw: str, col: str, width: int) -> str:
            visible = _wcslen(raw)
            pad = max(0, width - visible)
            return f"{col}{raw}{NC}{' ' * pad}" if col else f"{raw}{' ' * pad}"

        line = (
            " " * _TBL_INDENT
            + _pad(ip_s,  ip_col,  _W_IP)
            + " "
            + _pad(cc_s,  cc_col,  _W_CC)
            + " "
            + _pad(isp_s, isp_col, _W_ISP)
            + " "
            + _pad(src_s, src_col, _W_SRC)
        )
        _box_row(line)

    # ── Заголовок таблицы — в боксе (IP / Страна / ISP / Источник) ──────────
    _box_top("Найденные DNS-резолверы")
    _box_row(f"  {BOLD}{'IP':<{_W_IP}} {'Страна':<{_W_CC}} {'ISP':<{_W_ISP}} {'Источник':<{_W_SRC}}{NC}")
    _sep_line = "  " + "─" * _W_IP + " " + "─" * _W_CC + " " + "─" * _W_ISP + " " + "─" * _W_SRC
    _box_row(_sep_line)
    _box_bottom()
    print()

    # ── Строки резолверов — вне рамки (plain print), флаги не ломают границы ─
    for r in resolvers_found:
        ip      = r["ip"]
        cc      = r["cc"]
        country = r["country"]
        isp     = r["isp"]
        source  = r["source"]

        flag = country_flag_emoji(cc) if cc not in ("?", "") else ""
        # Обрезаем country чтобы уместить флаг(2) + " "(1) + country + " (CC)"(5) в _W_CC
        _cc_label    = f" ({cc})"                      # " (FI)" = 5 символов
        _flag_prefix = f"{flag} " if flag else "   "   # флаг+пробел = 3 или 3 пробела
        _cty_max     = _W_CC - len(_flag_prefix) - len(_cc_label)
        country_trunc = country[:max(0, _cty_max)] if country != "?" else "?"
        _cc_field    = f"{_flag_prefix}{country_trunc}{_cc_label}"
        # Паддинг поля Страна до _W_CC (флаг = 2 кол, Python len = 2 для пары RI)
        _cc_pad      = max(0, _W_CC - len(_flag_prefix) - len(country_trunc) - len(_cc_label))

        isp_trunc = isp[:_W_ISP] if isp != "?" else "?"
        src_trunc = source[:_W_SRC]

        if cc == "RU":
            leak_detected = True
            ru_resolvers.append(r)
            row_col = RED
        elif cc in ("?", ""):
            row_col = YELLOW
        else:
            foreign_resolvers.append(r)
            row_col = GREEN

        # Строка с теми же отступами что и заголовок: 2 + _W_IP + 1 + _W_CC + 1 + _W_ISP + 1 + _W_SRC
        print(
            f"  "
            f"{row_col}{ip:<{_W_IP}}{NC} "
            f"{_cc_field}{' ' * _cc_pad} "
            f"{DIM}{isp_trunc:<{_W_ISP}}{NC} "
            f"{DIM}{src_trunc}{NC}"
        )

    print()

    # ── Итог — отдельный бокс ────────────────────────────────────────────────
    _box_top("Итог")

    if leak_detected:
        _box_row(f"  {RED}⚠  DNS LEAK ОБНАРУЖЕНА!{NC}")
        _box_row(f"  {RED}   Резолвер(ы) в России: "
                 f"{', '.join(r['ip'] for r in ru_resolvers)}{NC}")
        _box_row(f"  {YELLOW}   DNS-запросы видит российский провайдер — это утечка!{NC}")
        _box_row()
        _box_row(f"  {BOLD}Рекомендации:{NC}")
        # Определяем что настроено
        dnscrypt_active = _run(
            ["systemctl", "is-active", "dnscrypt-proxy"],
            capture=True, check=False
        ).stdout.strip() == "active"
        if not dnscrypt_active:
            _box_row(f"  {CYAN}  1. Включите DNSCrypt-proxy: меню Сеть → DNSCrypt{NC}")
        else:
            _box_row(f"  {CYAN}  1. DNSCrypt активен — проверьте listen-address в конфиге{NC}")
        _box_row(f"  {CYAN}  2. Убедитесь что Xray routing не отправляет DNS напрямую{NC}")
        _box_row(f"  {CYAN}  3. Проверьте /etc/resolv.conf — должен указывать на 127.0.0.1{NC}")
        log_to_file("WARN", f"DNS leak test: LEAK detected, RU resolvers: "
                    f"{[r['ip'] for r in ru_resolvers]}")
    elif not foreign_resolvers and resolvers_found:
        _box_row(f"  {YELLOW}~ Страна резолвер(ов) не определена — возможна утечка{NC}")
        _box_row(f"  {DIM}  Проверьте вручную: dig +short TXT whoami.akamai.net{NC}")
        log_to_file("INFO", "DNS leak test: resolvers found but geo unknown")
    else:
        _box_row(f"  {GREEN}✓ DNS-утечки не обнаружено{NC}")
        _box_row(f"  {GREEN}  Резолверы находятся за пределами России{NC}")
        log_to_file("INFO", f"DNS leak test: OK — resolvers: "
                    f"{[r['ip'] for r in resolvers_found]}")

    _box_row()
    _box_bottom()

    # ── Сверка с настроенным DNS — отдельный бокс ───────────────────────────
    if configured_resolvers:
        print()
        _box_top("Сверка конфигурации")
        is_loopback = any(ip.startswith("127.") or ip == "::1"
                          for ip in configured_resolvers)
        if is_loopback:
            ns_str = ", ".join(configured_resolvers)
            line1 = f"  {GREEN}✓ /etc/resolv.conf → localhost — DNS проксируется локально{NC}"
            line2 = f"    {DIM}({ns_str}){NC}"
            _box_row(line1)
            _box_row(line2)
        else:
            _box_row(f"  {YELLOW}⚠ /etc/resolv.conf → внешний DNS "
                     f"({', '.join(configured_resolvers)}){NC}")
            _box_row(f"  {YELLOW}  DNS-запросы уходят напрямую, минуя Xray tunnel{NC}")
        # DNSCrypt
        dnscrypt_active = _run(
            ["systemctl", "is-active", "dnscrypt-proxy"],
            capture=True, check=False
        ).stdout.strip() == "active"
        dc_str = f"{GREEN}активен{NC}" if dnscrypt_active else f"{DIM}не запущен{NC}"
        _box_row(f"  DNSCrypt-proxy: {dc_str}")
        _box_row()
        _box_bottom()

    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ПОДМЕНЮ: 4 — ДИАГНОСТИКА И МОНИТОРИНГ
# =============================================================================
def _menu_diagnostics() -> None:
    while True:
        os.system("clear")
        _load_state_into_globals()
        print()
        _box_top("📊  ДИАГНОСТИКА И МОНИТОРИНГ")
        _box_row()
        _box_item("1", f"📡 Тест качества соединения  {DIM}(TTFB){NC}")
        _box_item("2", "📋 Лог изменений конфигурации")
        _box_item("3", f"🩺 Ежедневный Health-отчёт  {DIM}(cron 08:00){NC}")
        _box_item("4", "🩺 Полная диагностика HYDRA")
        _box_item("5", f"💻 Системный дашборд  {DIM}(CPU / RAM / Disk){NC}")
        _box_sep()
        _box_item("B", f"🔌 Проверка порта снаружи  {DIM}(заблокирован ли провайдером){NC}")
        _box_sep()
        _box_item("S", "🧪 Проверить статус и сеть")
        _box_item("L", "📋 Просмотр логов")
        _box_item("N", f"🔍 DNS Leak Test  {DIM}(проверить утечку DNS-запросов){NC}")
        _box_item("T", f"🔒 Проверка TLS-сертификата  {DIM}(цепочка, срок, SAN){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_connection_quality_test()
        elif ch == "2":
            do_view_changes_log()
        elif ch == "3":
            do_manage_health_report()
        elif ch == "4":
            do_full_diagnostic()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            do_system_dashboard()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "s":
            print()
            print(f"{BOLD}Статус сервисов:{NC}")
            svcs = ["caddy-naive", "mita", "hydra-sub-server", "dnscrypt-proxy"]
            for svc in svcs:
                rs = _run(["systemctl", "is-active", svc], capture=True, check=False)
                if rs.stdout.strip() == "active":
                    success(f"{svc}: ● активен")
                else:
                    warn(f"{svc}: ○ неактивен")
            r2 = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                      capture=True, check=False)
            if r2.stdout.strip() == "active":
                r3 = _run([str(DNSCRYPT_BIN), "--version"], capture=True, check=False)
                dc_ver = r3.stdout.splitlines()[0] if r3.stdout else ""
                info(f"DNSCrypt слушает на {DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT} | {dc_ver}")
            _box_top("Проверка сетевой доступности")
            verify_connectivity()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "l":
            do_view_logs()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "n":
            do_dns_leak_test()
        elif ch.lower() == "t":
            do_check_tls_cert()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch.lower() == "b":
            do_port_block_detect()
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


def do_scheduler_menu() -> None:
    """
    Единый планировщик задач — все cron/systemd задачи в одном месте.
    Показывает статус каждой задачи и позволяет включить/выключить одним нажатием.
    """

    # ── Описание всех задач ────────────────────────────────────────────────────
    # Формат: (ключ, метка, расписание_описание, cron_path или None, systemd_unit или None,
    #           fn_install, fn_remove)

    def _cron_exists(p: str) -> bool:
        return Path(p).exists()

    def _systemd_active(unit: str) -> bool:
        r = _run(["systemctl", "is-active", unit], capture=True, check=False)
        return r.stdout.strip() == "active"

    def _systemd_enabled(unit: str) -> bool:
        r = _run(["systemctl", "is-enabled", unit], capture=True, check=False)
        return r.stdout.strip() == "enabled"

    def _task_status(cron: str | None, unit: str | None) -> bool:
        if cron:
            return _cron_exists(cron)
        if unit:
            return _systemd_enabled(unit)
        return False

    def _next_run(cron_file: str | None, unit: str | None) -> str:
        """Возвращает строку с временем следующего запуска."""
        if unit:
            r = _run(["systemctl", "list-timers", unit, "--no-legend"],
                     capture=True, check=False)
            if r.stdout.strip():
                parts = r.stdout.strip().split()
                # "NEXT" колонка — первые два слова (дата + время)
                if len(parts) >= 2:
                    return f"{parts[0]} {parts[1]}"
        if cron_file and Path(cron_file).exists():
            try:
                line = [l for l in Path(cron_file).read_text().splitlines()
                        if l and not l.startswith("#")]
                if line:
                    return line[0].split()[:5].__str__().strip("[]").replace("'", "")
            except Exception:
                pass
        return "—"

    # Определяем задачи
    TASKS = [
        {
            "id":       "health",
            "emoji":    "❤️",
            "label":    "Ежедневный Health-отчёт",
            "schedule": "08:00 ежедневно",
            "cron":     "/etc/cron.d/xray-health-report",
            "unit":     None,
            "log":      "/var/log/xray-health-report.log",
            "configure": do_manage_health_report,
        },
        {
            "id":       "tg",
            "emoji":    "📬",
            "label":    "Telegram мониторинг",
            "schedule": "каждые 5 мин",
            "cron":     "/etc/cron.d/xray-tg-monitor",
            "unit":     None,
            "log":      None,
            "configure": do_manage_telegram,
        },
        {
            "id":       "certbot",
            "emoji":    "🔒",
            "label":    "Мониторинг SSL-сертификата",
            "schedule": "03:00 и 15:00",
            "cron":     "/etc/cron.d/xray-certbot-monitor",
            "unit":     None,
            "log":      "/var/log/xray-certbot-monitor.log",
            "configure": do_manage_certbot_monitor,
        },

        {
            "id":       "limits",
            "emoji":    "📊",
            "label":    "Лимиты трафика",
            "schedule": "каждые 5 мин",
            "cron":     "/etc/cron.d/xray-traffic-limits",
            "unit":     None,
            "log":      None,
            "configure": do_manage_traffic_limits,
        },
        {
            "id":       "ttl",
            "emoji":    "⏱️",
            "label":    "TTL пользователей (авто-откл.)",
            "schedule": "ежедневно",
            "cron":     str(TTL_CRON_FILE),
            "unit":     None,
            "log":      None,
            "configure": do_manage_ttl_users,
        },
        {
            "id":       "snapshot",
            "emoji":    "📈",
            "label":    "Снимки трафика (история)",
            "schedule": "каждый час",
            "cron":     "/etc/cron.d/xray-traffic-snapshot",
            "unit":     None,
            "log":      None,
            "configure": do_traffic_history,
        },

        {
            "id":       "ingress",
            "emoji":    "🛡️",
            "label":    "Ingress GeoIP блокировка",
            "schedule": "настраивается",
            "cron":     str(INGRESS_CRON_FILE),
            "unit":     None,
            "log":      None,
            "configure": do_manage_ingress_geoip,
        },
        {
            "id":       "autoupdate",
            "emoji":    "⬆️",
            "label":    "Авто-обновление Xray",
            "schedule": "ежедневно 03:30",
            "cron":     None,
            "unit":     "xray-autoupdate.timer",
            "log":      None,
            "configure": None,  # управляется в меню установки
        },
        {
            "id":       "rusubnets",
            "emoji":    "RU",
            "label":    "Обновление РУ-подсетей",
            "schedule": "настраивается",
            "cron":     None,
            "unit":     "xray-ru-subnets.timer",
            "log":      None,
            "configure": do_manage_ru_subnet_direct,
        },
        {
            "id":       "asdirect",
            "emoji":    "AS",
            "label":    "AS-провайдер → direct",
            "schedule": "настраивается",
            "cron":     None,
            "unit":     "xray-as-direct.timer",
            "log":      None,
            "configure": do_manage_as_direct,
        },
        {
            "id":       "logrotate",
            "emoji":    "📋",
            "label":    "Ротация логов Xray (logrotate)",
            "schedule": "ежедневно (системный cron)",
            "cron":     "/etc/logrotate.d/xray",
            "unit":     None,
            "log":      "/var/log/xray/access.log",
            "configure": do_manage_logrotate,
        },
        {
            "id":       "backup",
            "emoji":    "📦",
            "label":    "Автобэкап конфигурации",
            "schedule": "настраивается",
            "cron":     str(_SCHEDULED_BACKUP_CRON),
            "unit":     None,
            "log":      "/var/log/xray-scheduled-backup.log",
            "configure": do_manage_scheduled_backup,
        },
    ]

    render_scheduler_menu(TASKS)

def do_cold_boot_menu() -> None:
    """Заглушка: Cold Boot Restore удалён в HYDRA-only сборке."""
    warn("Cold Boot Restore недоступен в HYDRA-only сборке (legacy VLESS удалён).")
    try:
        input(f"{BLUE}Нажмите Enter...{NC}")
    except KeyboardInterrupt:
        pass


def _menu_security() -> None:
    while True:
        os.system("clear")
        _load_state_into_globals()
        _box_top("🛡️  БЕЗОПАСНОСТЬ И АВТОМАТИЗАЦИЯ")
        _box_item("1", f"🛡️  Ingress GeoIP  {DIM}(блок входящих из РФ — iptables){NC}")
        _box_item("2", f"📬 Telegram Admin Panel  {DIM}(управление сервером через бот){NC}")
        _box_item("3", f"🤖 Telegram User Bot  {DIM}(подписки для пользователей){NC}")
        _box_item("4", f"🚫 IP-Бан  {DIM}(iptables/ipset: IP / подсеть / ASN){NC}")
        _box_item("5", f"🛡️  Fail2ban  {DIM}(банит за подбор пароля / лишние запросы){NC}")
        _box_item("6", f"🔒 Мониторинг SSL/Let's Encrypt  {DIM}(подписки / Caddy){NC}")
        _box_item("7", f"🔒 SSH Hardening  {DIM}(порт / ключи / AllowUsers){NC}")
        _box_item("8", f"🍯 Honeypot-порт  {DIM}(ловушка для сканеров){NC}")
        _box_item("9", f"🗓️  Планировщик задач  {DIM}(все cron/systemd в одном месте){NC}")
        # Показываем статус ingress-блокировки прямо в меню
        _ing = _ingress_state_load()
        _ing_on = _ing.get("enabled")
        _ing_str = (
            f"{GREEN}вкл  порт {_ing.get('port','')}  {_ing.get('cidrs_v4',0)} CIDR{NC}"
            if _ing_on else f"{DIM}выкл{NC}"
        )
        _box_item("10", f"🛡️  Блокировка входящих из РФ  {_ing_str}")
        _box_item("11", f"🔄 Cold Boot Restore  {DIM}(legacy VLESS — недоступно){NC}")
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_manage_ingress_geoip()
        elif ch == "2":
            do_manage_telegram()
        elif ch == "3":
            do_tg_bot_menu()
        elif ch == "4":
            do_manage_ipban()
        elif ch == "5":
            do_manage_fail2ban()
        elif ch == "6":
            do_manage_certbot_monitor()
        elif ch == "7":
            do_ssh_hardening()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "8":
            do_manage_honeypot()
        elif ch == "9":
            do_scheduler_menu()
        elif ch == "10":
            do_manage_ingress_geoip()
        elif ch == "11":
            do_cold_boot_menu()
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


def _load_state_into_globals() -> None:
    global PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_SHORTID
    global IS_IPV6_AVAILABLE, IPV6_PREFLIGHT, PARAM_USE_DNSCRYPT
    global INSTALL_MODE, PROTOCOL_MODE, XHTTP_MODE, XHTTP_PATH, XHTTP_PERF_PRESET
    global AWG_EXIT_ENABLED, AWG_INSTALLED, AWG_EXIT_HOST, AWG_EXIT_PORT, PARAM_REALITY_DEST
    global H2_EXIT_ENABLED
    global XTLS_FLOW
    global PARAM_FINGERPRINT
    # === FIX 1: объявление глобалей для multi-node полей ===
    global AWG_NODES, AWG_ACTIVE_NODE_INDEX, _AWG_SSH_CLIENT_IP
    # === END FIX 1 ===
    global XHTTP_PADDING_BYTES, XHTTP_NO_SSE_HEADER, XHTTP_NO_GRPC_HEADER, XHTTP_HOST
    global XHTTP_SC_STREAM_UP_SERVER_SECS, XHTTP_SC_MAX_EACH_POST_BYTES
    global XHTTP_SC_MIN_POSTS_INTERVAL_MS, XHTTP_SC_MAX_BUFFERED_POSTS
    global XHTTP_XMUX_ENABLED, XHTTP_XMUX_MAX_CONCURRENCY, XHTTP_XMUX_MAX_CONNECTIONS
    global XHTTP_XMUX_C_MAX_REUSE_TIMES, XHTTP_XMUX_H_MAX_REQUEST_TIMES
    global XHTTP_XMUX_H_MAX_REUSABLE_SECS, XHTTP_XMUX_H_KEEP_ALIVE_PERIOD
    global XHTTP_TCP_NO_DELAY, XHTTP_ENABLE_SESSION_RESUMPTION
    global SERVER_PORT, XHTTP_PORT, CHAIN_BALANCER_STRATEGY
    global CHAIN_EXIT_HOST, CHAIN_EXIT_PORT, CHAIN_EXIT_UUID
    global CHAIN_EXIT_PUBKEY, CHAIN_EXIT_SHORTID, CHAIN_EXIT_SNI, CHAIN_EXIT_FP
    global CHAIN_NODES
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        PARAM_DOMAIN     = state.get("domain",      PARAM_DOMAIN)
        PARAM_UUID       = state.get("uuid",        PARAM_UUID)
        PARAM_PUBLIC_KEY = state.get("public_key",  PARAM_PUBLIC_KEY)
        PARAM_SHORTID    = state.get("short_id",    PARAM_SHORTID)
        PARAM_FINGERPRINT = state.get("fingerprint", PARAM_FINGERPRINT) or "chrome"
        IPV6_PREFLIGHT   = state.get("ipv6",        IPV6_PREFLIGHT)
        INSTALL_MODE     = state.get("install_mode", "A")
        if IPV6_PREFLIGHT:
            IS_IPV6_AVAILABLE = True
        PARAM_USE_DNSCRYPT = state.get("use_dnscrypt", False)
        PROTOCOL_MODE = state.get("protocol_mode", "reality")
        XTLS_FLOW     = state.get("xtls_flow",      "xtls-rprx-vision")
        XHTTP_MODE    = state.get("xhttp_mode",    "streamup")
        XHTTP_PATH    = state.get("xhttp_path",    "/")
        XHTTP_PERF_PRESET = state.get("xhttp_perf_preset", "auto")
        XHTTP_PADDING_BYTES             = state.get("xhttp_padding_bytes",            "100-1000")
        XHTTP_NO_SSE_HEADER             = state.get("xhttp_no_sse_header",            False)
        XHTTP_NO_GRPC_HEADER            = state.get("xhttp_no_grpc_header",           False)
        XHTTP_HOST                      = state.get("xhttp_host",                     "")
        XHTTP_SC_STREAM_UP_SERVER_SECS  = state.get("xhttp_sc_stream_up_server_secs", "20-80")
        XHTTP_SC_MAX_EACH_POST_BYTES    = state.get("xhttp_sc_max_each_post_bytes",   "1000000")
        XHTTP_SC_MIN_POSTS_INTERVAL_MS  = state.get("xhttp_sc_min_posts_interval_ms", "30")
        XHTTP_SC_MAX_BUFFERED_POSTS     = state.get("xhttp_sc_max_buffered_posts",    30)
        XHTTP_XMUX_ENABLED              = state.get("xhttp_xmux_enabled",             False)
        XHTTP_XMUX_MAX_CONCURRENCY      = state.get("xhttp_xmux_max_concurrency",     "16-32")
        XHTTP_XMUX_MAX_CONNECTIONS      = state.get("xhttp_xmux_max_connections",     0)
        XHTTP_XMUX_C_MAX_REUSE_TIMES    = state.get("xhttp_xmux_c_max_reuse_times",   "0")
        XHTTP_XMUX_H_MAX_REQUEST_TIMES  = state.get("xhttp_xmux_h_max_request_times", "600-900")
        XHTTP_XMUX_H_MAX_REUSABLE_SECS  = state.get("xhttp_xmux_h_max_reusable_secs", "1800-3000")
        XHTTP_XMUX_H_KEEP_ALIVE_PERIOD  = state.get("xhttp_xmux_h_keep_alive_period", 0)
        XHTTP_TCP_NO_DELAY              = state.get("xhttp_tcp_no_delay",             False)
        XHTTP_ENABLE_SESSION_RESUMPTION = state.get("xhttp_enable_session_resumption", False)
        SERVER_PORT   = state.get("server_port",   443)
        XHTTP_PORT    = SERVER_PORT
        CHAIN_EXIT_HOST    = state.get("chain_exit_host",    CHAIN_EXIT_HOST)
        CHAIN_EXIT_PORT    = state.get("chain_exit_port",    CHAIN_EXIT_PORT)
        CHAIN_EXIT_UUID    = state.get("chain_exit_uuid",    CHAIN_EXIT_UUID)
        CHAIN_EXIT_PUBKEY  = state.get("chain_exit_pubkey",  CHAIN_EXIT_PUBKEY)
        CHAIN_EXIT_SHORTID = state.get("chain_exit_shortid", CHAIN_EXIT_SHORTID)
        CHAIN_EXIT_SNI     = state.get("chain_exit_sni",     CHAIN_EXIT_SNI)
        CHAIN_EXIT_FP      = state.get("chain_exit_fp",      CHAIN_EXIT_FP)
        CHAIN_NODES = []
        CHAIN_BALANCER_STRATEGY = state.get("chain_balancer_strategy", "roundRobin")
        # AWG 2.0 — критически важно для корректной генерации xray config
        AWG_EXIT_ENABLED = state.get("awg_exit_enabled",  False)
        AWG_INSTALLED    = state.get("awg_installed",     AWG_EXIT_ENABLED)
        AWG_EXIT_HOST    = state.get("awg_exit_host",     AWG_EXIT_HOST)
        AWG_EXIT_PORT    = state.get("awg_exit_port",     AWG_EXIT_PORT)
        AWG_CLIENT_LISTEN_PORT = state.get("awg_client_listen_port", AWG_CLIENT_LISTEN_PORT)
        PARAM_REALITY_DEST = state.get("reality_dest",   PARAM_REALITY_DEST)
        # Hysteria2 транспорт
        H2_EXIT_ENABLED  = state.get("h2_exit_enabled",  False)
        # === FIX 1: загрузка multi-node полей ===
        AWG_NODES             = state.get("awg_nodes",             [])
        AWG_ACTIVE_NODE_INDEX = state.get("awg_active_node_index", 0)
        _AWG_SSH_CLIENT_IP    = state.get("awg_ssh_client_ip",     "")
        # === END FIX 1 ===
    except Exception:
        pass


# =============================================================================
#  ГЛАВНОЕ МЕНЮ (НОВАЯ ВЕРСИЯ — ГРУППЫ ПО 5 РАЗДЕЛАМ)
# =============================================================================
def main_menu() -> None:
    global PARAM_DOMAIN, PARAM_UUID, PARAM_PUBLIC_KEY, PARAM_SHORTID
    global IS_IPV6_AVAILABLE, IPV6_PREFLIGHT, PARAM_USE_DNSCRYPT, DNSCRYPT_INSTALLED
    global INSTALL_MODE
    global PROTOCOL_MODE, XHTTP_MODE, XHTTP_PATH, XHTTP_PERF_PRESET
    global _BOX_W
    global XHTTP_PADDING_BYTES, XHTTP_NO_SSE_HEADER
    global XHTTP_NO_GRPC_HEADER, XHTTP_HOST, XHTTP_SC_MIN_POSTS_INTERVAL_MS
    global XHTTP_XMUX_ENABLED, XHTTP_XMUX_MAX_CONCURRENCY, XHTTP_XMUX_MAX_CONNECTIONS
    global XHTTP_XMUX_C_MAX_REUSE_TIMES, XHTTP_XMUX_H_MAX_REQUEST_TIMES
    global XHTTP_XMUX_H_MAX_REUSABLE_SECS, XHTTP_XMUX_H_KEEP_ALIVE_PERIOD
    global XHTTP_TCP_NO_DELAY, XHTTP_ENABLE_SESSION_RESUMPTION
    global XHTTP_SC_STREAM_UP_SERVER_SECS, XHTTP_SC_MAX_EACH_POST_BYTES
    global XHTTP_SC_MAX_BUFFERED_POSTS
    global CHAIN_EXIT_HOST, CHAIN_EXIT_PORT, CHAIN_EXIT_UUID
    global CHAIN_EXIT_PUBKEY, CHAIN_EXIT_SHORTID, CHAIN_EXIT_SNI, CHAIN_EXIT_FP
    # Авто-генерация ботов при запуске
    try:
        from vless_installer.modules.tg_bot import _regenerate_bot, _regenerate_admin_bot
        _regenerate_bot()
        _regenerate_admin_bot()
    except Exception:
        pass

    while True:
        try:
            _BOX_W = _get_box_width()
            os.system("clear")
            print_banner()
            print()

            # Главное меню фиксируется по ширине баннера (64 символа)
            _BOX_W_saved = _BOX_W
            _BOX_W = 64
            _box_top()
            _box_row(f"  {BOLD}{TITLE}HYDRA MULTI-PROXY MANAGER v{__import__('vless_installer').__version__}{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}1{NC}  ⚙️  {TITLE}Установка и Система{NC}")
            _box_row(f"     {DIM}Установка и обновление зависимостей, тюнинг BBR/sysctl{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}2{NC}  👥 {TITLE}Управление пользователями и подписками{NC}")
            _box_row(f"     {DIM}Управление подписками, авторизация, раздача конфигов{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}3{NC}  🌐 {TITLE}Настройки сети{NC}")
            _box_row(f"     {DIM}Настройка Cloudflare WARP, внешняя проверка доменов и IP{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}4{NC}  📊 {TITLE}Диагностика и Мониторинг{NC}")
            _box_row(f"     {DIM}История трафика, логи, аудит подключений и системный дашборд{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}5{NC}  🛡️  {TITLE}Безопасность и Автоматизация{NC}")
            _box_row(f"     {DIM}GeoIP блок, IP-Бан, Fail2ban, SSH Hardening и TG панель{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}6{NC}  🔐 {TITLE}NaiveProxy{NC}")
            _box_row(f"     {DIM}HTTPS/HTTP2 + Chromium fingerprint + Caddy{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}7{NC}  🔒 {TITLE}Mieru{NC}")
            _box_row(f"     {DIM}mTLS + random padding — маскировка без домена{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}8{NC}  🛡️  {TITLE}AmneziaVPN{NC}")
            _box_row(f"     {DIM}AWG через Docker — управление контейнером Amnezia{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}9{NC}  📡 {TITLE}Telemt MTProxy{NC}")
            _box_row(f"     {DIM}Telegram MTProto-прокси (Rust/Tokio){NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}10{NC} 📲 {TITLE}VK Turn Tunnel & qWDTT{NC}")
            _box_row(f"     {DIM}Tunnels: FreeTurn · WireTurn · qWDTT (WireGuard over TURN){NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}11{NC} 📹 {TITLE}olcRTC{NC}  {DIM}(Beta){NC}")
            _box_row(f"     {DIM}TCP-over-WebRTC — туннель под видеозвонок{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}12{NC} 🌐 {TITLE}SlipGate / SlipNet{NC}")
            _box_row(f"     {DIM}DNS-туннели (DNSTT, NoizDNS, Slipstream){NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {CYAN}13{NC} ☁️  {TITLE}WebDAV Tunnel{NC}")
            _box_row(f"     {DIM}TCP/SOCKS5 поверх WebDAV-файлов — маскировка под облако{NC}")
            _box_sep()
            _box_row()
            _box_row(f"  {DIM}[{NC}{TITLE}{BOLD}0{NC}{DIM}]{NC}  🚪 Выход")
            _box_bottom()
            _BOX_W = _BOX_W_saved
            print()
            choice = input(f"{CYAN}Выбор (1–13 / 0):{NC} ").strip()
        except KeyboardInterrupt:
            print()
            print(f"{GREEN}До свидания! 👋{NC}")
            log_to_file("INFO", "Скрипт завершён пользователем (Ctrl+C)")
            sys.exit(0)

        if not choice:
            continue

        if choice == "1":
            _menu_install_system()

        elif choice == "2":
            _load_state_into_globals()
            do_subscription_menu()

        elif choice == "3":
            _load_state_into_globals()
            _menu_network()

        elif choice == "4":
            _menu_diagnostics()

        elif choice == "5":
            _menu_security()

        elif choice == "6":
            try:
                do_naiveproxy_menu()
            except ImportError as _e:
                warn(f"Модуль NaiveProxy не найден: {_e}")
                time.sleep(2)

        elif choice == "7":
            try:
                do_mieru_menu()
            except ImportError as _e:
                warn(f"Модуль Mieru не найден: {_e}")
                time.sleep(2)

        elif choice == "8":
            try:
                do_amnezia_vpn_menu()
            except Exception as _e:
                warn(f"Ошибка вызова AmneziaVPN: {_e}")
                time.sleep(2)

        elif choice == "9":
            try:
                from vless_installer.modules.mtproto import mtproto_menu
                mtproto_menu()
            except ImportError as _e:
                warn(f"Модуль MTProxy не найден: {_e}")
                time.sleep(2)

        elif choice == "10":
            _menu_vk_tunnels()

        elif choice == "11":
            try:
                from vless_installer.modules.olcrtc import do_olcrtc_menu
                do_olcrtc_menu()
            except ImportError as _e:
                warn(f"Модуль olcRTC не найден: {_e}")
                time.sleep(2)

        elif choice == "12":
            try:
                do_slipgate_menu()
            except ImportError as _e:
                warn(f"Модуль SlipGate не найден: {_e}")
                time.sleep(2)

        elif choice == "13":
            try:
                do_webdav_tunnel_menu()
            except ImportError as _e:
                warn(f"Модуль WebDAV Tunnel не найден: {_e}")
                time.sleep(2)

        elif choice == "0":
            print(f"{GREEN}До свидания! 👋{NC}")
            log_to_file("INFO", "Скрипт завершён пользователем")
            sys.exit(0)

        else:
            warn(f"Неверный выбор: {choice}")
            time.sleep(1)


def _menu_vk_tunnels() -> None:
    """Подменю для VK Turn Tunnel и qWDTT."""
    while True:
        os.system("clear")
        print()
        _box_top("📲  VK TURN & qWDTT TUNNELS")
        _box_row()
        _box_item("1", f"VK Turn Tunnel  {DIM}(FreeTurn / WireTurn / Turnable){NC}")
        _box_item("2", f"qWDTT  {DIM}(WireGuard через VK TURN){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            try:
                do_vkturn_menu()
            except Exception as e:
                warn(f"Ошибка VK Turn: {e}")
                time.sleep(2)
        elif ch == "2":
            try:
                do_wdtt_menu()
            except Exception as e:
                warn(f"Ошибка qWDTT: {e}")
                time.sleep(2)
        elif ch.lower() in ("q", ""):
            break


def apply_sysctl_and_limits() -> None:
    """Применяет настройки sysctl и limits.conf для оптимизации производительности."""
    sysctl_conf = OPTIMIZER_CONF
    limits_conf = LIMITS_CONF
    applied = False

    # Если файлов оптимизации нет, сгенерируем их
    if not sysctl_conf.exists() or not limits_conf.exists():
        info("Конфигурационные файлы оптимизации не найдены. Генерируем...")
        PROGRESS.init(100, "Оптимизация")
        apply_network_optimizations()
        PROGRESS.update(100 - PROGRESS.current, "Готово")

    if sysctl_conf.exists():
        r = _run(["sysctl", "--system"], check=False, quiet=False)
        if r.returncode == 0:
            success(f"sysctl применён из {sysctl_conf}")
            applied = True
        else:
            warn("Ошибка применения sysctl")
    else:
        warn(f"Файл {sysctl_conf} не найден — запустите установку (п.1)")
    if limits_conf.exists():
        success(f"limits.conf готов: {limits_conf}")
        applied = True
    if not applied:
        warn("Файлы оптимизации не найдены. Сначала выполните установку (п.1).")


# Удалён дублирующий пункт [2] «Управление пользователями» —
# он полностью совпадал с пунктом [U] «Менеджер пользователей».
# Теперь оба объединены в разделе 2 главного меню.

def _DELETED_old_main_menu_handlers() -> None:
    """
    Заглушка — старые обработчики главного меню перенесены в подменю:
      _menu_install_system(), _menu_users(), _menu_network(),
      _menu_diagnostics(), _menu_security()
    Эта функция никогда не вызывается.
    """
    pass


# =============================================================================
#  ПЕРЕКЛЮЧЕНИЕ РЕЖИМА A ↔ B БЕЗ ПЕРЕУСТАНОВКИ
# =============================================================================

# =============================================================================
#  SMART BALANCER — composite latency + bandwidth + load
# smart_balancer — перенесено в vless_installer/modules/smart_balancer.py
# =============================================================================
# === PATCH v2: AWG MULTI-NODE — вспомогательные функции и watchdog ===
# =============================================================================

# =============================================================================
#  МОДУЛЬ 9: TUI — ИНТЕРАКТИВНЫЙ ВВОД (stdlib curses, без зависимостей)
#
#  Не требует rich/textual. Реализует:
#    • tui_input()      — строка ввода с валидацией на лету
#    • tui_confirm()    — [Y/n] диалог с подсветкой
#    • tui_select()     — выбор из списка стрелками (↑↓ + Enter)
#    • tui_progress()   — прогресс-бар внутри рамки
#    • tui_form()       — многополевая форма с переходом Tab/Enter
#
#  Все функции graceful-деградируют на обычный input() если терминал не TTY
#  (например, при запуске из cron/pipe).
# tui_input/tui_confirm/tui_select/tui_progress/tui_form
# — перенесено в vless_installer/modules/tui.py
# =============================================================================
#  МОДУЛЬ 10: GEOIP БЛОКИРОВКА ВХОДЯЩИХ ЧЕРЕЗ IPTABLES (РЕЖИМ B)
#
#  Логика:
#    • Читает РФ-подсети из уже существующего ru_subnets_ripe.txt
#      (тот же файл, что использует split-tunnel модуль)
#    • Если файла нет — скачивает свежий список с RIPE NCC через
#      уже существующую функцию _fetch_ru_subnets_from_ripe()
#    • Применяет через iptables/ip6tables: DROP входящих на SERVER_PORT
#      с российских IP (ipset для эффективности, fallback на цепочку правил)
#    • Обновление через существующий systemd-таймер РФ подсетей
#      или отдельный cron
#    • Состояние хранится в /var/lib/xray-installer/ingress_geoip.json
# ingress_geoip — перенесено в vless_installer/modules/ingress_geoip.py
# INGRESS_* константы импортируются из модуля
# =============================================================================

def do_mtu_tracepath_diag() -> None:
    """
    Детальная MTU-диагностика маршрута до цели.
    Запускает tracepath для выявления хопов с уменьшенным MTU,
    затем уточняет бинарным ping-зондом вокруг проблемных хопов.
    Не меняет никаких настроек — только диагностика.
    """
    os.system("clear")
    print()
    _box_top("📡  MTU TRACEPATH — ДИАГНОСТИКА МАРШРУТА")
    _box_row(f"  {DIM}Показывает MTU на каждом хопе до цели. Помогает найти узкое место.{NC}")
    _box_row(f"  {DIM}Не изменяет настройки — только анализ.{NC}")
    _box_sep()

    # Определяем цели из state.json или предлагаем ввод
    targets = []
    if STATE_FILE.exists():
        try:
            st = json.loads(STATE_FILE.read_text())
            dom = st.get("sub_domain") or st.get("domain", "")
            if dom:
                targets.append({"host": dom, "label": f"Домен подписок ({dom})"})
        except Exception:
            pass
    if not targets:
        targets = [
            {"host": "1.1.1.1", "label": "Cloudflare (1.1.1.1)"},
            {"host": "8.8.8.8", "label": "Google DNS (8.8.8.8)"},
        ]

    _box_row(f"  Цели для диагностики:")
    for i, t in enumerate(targets, 1):
        _box_row(f"    {CYAN}[{i}]{NC} {t['label']}")
    _box_row(f"    {CYAN}[M]{NC} Ввести хост вручную")
    _box_row(f"    {CYAN}[A]{NC} Все цели подряд")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    if ch in ("q", ""):
        return

    selected = []
    if ch == "a":
        selected = targets
    elif ch == "m":
        raw = input("  Хост или IP: ").strip()
        if raw:
            selected = [{"host": raw, "label": raw}]
        else:
            return
    elif ch.isdigit() and 1 <= int(ch) <= len(targets):
        selected = [targets[int(ch) - 1]]
    else:
        warn("Неверный выбор")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    for tgt in selected:
        _mtu_tracepath_one(tgt["host"], tgt["label"])

    input(f"{BLUE}Нажмите Enter...{NC}")


def _mtu_tracepath_one(host: str, label: str) -> None:
    """Диагностика MTU-маршрута до одного хоста."""
    os.system("clear")
    print()
    _box_top(f"📡  MTU МАРШРУТ → {label}")
    _box_sep()

    # Шаг 1: tracepath (встроенный Path MTU Discovery, не нужен root)
    if command_exists("tracepath"):
        _box_row(f"  {CYAN}[1/3] tracepath -n {host}{NC}")
        _box_row(f"  {DIM}Запуск... (до 15 сек){NC}")
        r = _run(["tracepath", "-n", "-m", "20", host],
                 capture=True, check=False)
        hops = []
        min_pmtu = 1500
        if r.returncode == 0 or r.stdout.strip():
            for line in r.stdout.strip().splitlines():
                _box_row(f"  {DIM}{line[:80]}{NC}")
                # tracepath печатает "pmtu NNNN" при обнаружении меньшего MTU
                m = re.search(r'pmtu\s+(\d+)', line)
                if m:
                    pmtu_val = int(m.group(1))
                    if pmtu_val < min_pmtu:
                        min_pmtu = pmtu_val
                    hops.append(pmtu_val)
        else:
            _box_row(f"  {YELLOW}tracepath не дал результата (ICMP может быть заблокирован){NC}")
        _box_sep()
        if hops:
            _box_row(f"  {BOLD}Минимальный PMTU по маршруту: {GREEN}{min_pmtu}{NC}")
        else:
            _box_row(f"  {DIM}PMTU-ограничений на маршруте не обнаружено (или ICMP заблокирован){NC}")
    else:
        _box_warn("tracepath не установлен (apt install iputils-tracepath)")
        min_pmtu = 1500

    _box_sep()

    # Шаг 2: Бинарный ping-зонд (собственная реализация, как в do_mtu_tuning)
    _box_row(f"  {CYAN}[2/3] Бинарный ping-зонд (DF-bit){NC}")
    _box_row(f"  {DIM}Точный поиск максимального MTU...{NC}")
    probed_mtu = _mtu_probe(host, max_mtu=1500, min_mtu=576)
    if probed_mtu > 0:
        col = GREEN if probed_mtu >= 1400 else YELLOW if probed_mtu >= 1200 else RED
        _box_row(f"  Ping-зонд: максимальный MTU = {col}{probed_mtu}{NC}  "
                 f"{DIM}(MSS = {probed_mtu - 40}){NC}")
    else:
        _box_row(f"  {YELLOW}Ping-зонд не дал результата (ICMP DF заблокирован){NC}")
        probed_mtu = 0

    _box_sep()

    # Шаг 3: MTU-зонд по контрольным значениям (быстрый sweep)
    _box_row(f"  {CYAN}[3/3] Проверка стандартных MTU-значений{NC}")
    check_values = [1500, 1492, 1480, 1460, 1440, 1420, 1400, 1380, 1280, 1024, 576]
    results_sweep = []
    for mtu_val in check_values:
        payload = mtu_val - 28
        if payload < 1:
            continue
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            _box_warn(f"  Не удалось разрешить {host}")
            break
        r = _run(
            ["ping", "-c", "1", "-W", "1", "-M", "do", "-s", str(payload), ip],
            capture=True, check=False
        )
        ok = r.returncode == 0
        col = GREEN if ok else RED
        mark = "✓" if ok else "✗"
        results_sweep.append((mtu_val, ok))
        _box_row(f"  {col}{mark}{NC}  MTU {mtu_val:>5}  "
                 f"{DIM}(payload {payload}){NC}")

    # Итог
    _box_sep()
    max_ok = max((v for v, ok in results_sweep if ok), default=0)
    if max_ok:
        col = GREEN if max_ok >= 1400 else YELLOW if max_ok >= 1200 else RED
        _box_row(f"  {BOLD}Максимальный рабочий MTU: {col}{max_ok}{NC}")

        # Рекомендация
        recommend = max_ok
        if max_ok >= 1500:
            _box_row(f"  {GREEN}✓ Маршрут не ограничивает MTU — фрагментации нет{NC}")
        elif max_ok >= 1400:
            _box_row(f"  {YELLOW}⚠ Есть ограничение MTU. Рекомендуется применить MTU {recommend} в тюнере{NC}")
        else:
            _box_row(f"  {RED}✗ Значительное ограничение MTU! Рекомендуется MTU {recommend}{NC}")
            _box_row(f"  {DIM}Используйте пункт [1] в MTU-тюнере для применения{NC}")

        _log_change("mtu_diag", f"tracepath {host}: max_ok={max_ok}, probed={probed_mtu}")
    else:
        _box_row(f"  {YELLOW}Все ping DF-зонды заблокированы (ICMP фильтруется){NC}")
        _box_row(f"  {DIM}Для VPN-туннелей безопасно использовать MTU 1420{NC}")

    _box_bottom()


# =============================================================================
#  МОДУЛЬ: DPI-ДЕТЕКТОР  (v3.99)
#  Анализирует xray/error.log на паттерны активного зондирования:
#  - TLS Client Hello без SNI
#  - нестандартные TLS client_random
#  - повторные хендшейки с разными параметрами (fingerprint sweep)
#  - HTTP-запросы к Xray (не-TLS трафик на TLS-порт)
#  Забаненные IP интегрируются в существующий AutoBan (autoban.json)
# dpi_detector — перенесено в vless_installer/modules/dpi_detector.py
