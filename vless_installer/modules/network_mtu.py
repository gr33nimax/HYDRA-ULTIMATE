"""
vless_installer/modules/network_mtu.py
──────────────────────────────────────────────────────────────────────────────
MTU/MSS и диагностика сетевого стека HYDRA (AWG, WARP, DNSCrypt, Mieru).

Используется из do_mtu_tuning() в _core.py и сетевого меню.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
from datetime import datetime
from pathlib import Path

AWG_RECOMMENDED_MTU = 1280
WARP_OVERHEAD_MTU = 1280
DEFAULT_MTU = 1500
_MSS_STATE = Path("/var/lib/xray-installer/mtu_state.json")


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def _service_active(unit: str) -> bool:
    r = _run(["systemctl", "is-active", unit], check=False)
    return r.stdout.strip() == "active"


def is_dnscrypt_active() -> bool:
    return _service_active("dnscrypt-proxy")


def is_mieru_active() -> bool:
    return _service_active("mita")


def is_warp_iface_up() -> bool:
    try:
        from vless_installer.modules.warp_universal import detect_warp_interface
        return bool(detect_warp_interface())
    except Exception:
        for iface in ("wg-warp", "warp0", "CloudflareWARP"):
            r = _run(["ip", "link", "show", iface], check=False)
            if r.returncode == 0 and "state UP" in (r.stdout or ""):
                return True
        return False


def is_awg_container_running() -> bool:
    try:
        r = _run(
            ["docker", "ps", "--filter", "name=amnezia", "--filter", "status=running", "--format", "{{.Names}}"],
            check=False, timeout=10,
        )
        return bool((r.stdout or "").strip())
    except Exception:
        return False


def detect_network_stack() -> dict[str, bool]:
    """Какие сетевые компоненты HYDRA сейчас активны."""
    return {
        "dnscrypt": is_dnscrypt_active(),
        "warp": is_warp_iface_up(),
        "awg": is_awg_container_running(),
        "mieru": is_mieru_active(),
    }


def stack_label(stack: dict[str, bool]) -> str:
    parts = []
    if stack.get("awg"):
        parts.append("AWG")
    if stack.get("warp"):
        parts.append("WARP")
    if stack.get("dnscrypt"):
        parts.append("DNSCrypt")
    if stack.get("mieru"):
        parts.append("Mieru")
    return " + ".join(parts) if parts else "базовый (без туннелей)"


def recommend_mtu_for_awg(stack: dict[str, bool] | None = None) -> int:
    """Рекомендуемый MTU для AWG-клиентов с учётом WARP."""
    if stack is None:
        stack = detect_network_stack()
    if stack.get("warp") and stack.get("awg"):
        return 1280
    if stack.get("warp"):
        return 1280
    if stack.get("awg"):
        return AWG_RECOMMENDED_MTU
    return AWG_RECOMMENDED_MTU


def build_mtu_recommendations(stack: dict[str, bool] | None = None) -> list[dict]:
    """Список рекомендаций MTU/MSS по активному стеку."""
    if stack is None:
        stack = detect_network_stack()
    recs: list[dict] = []

    awg_mtu = recommend_mtu_for_awg(stack)
    if stack.get("awg"):
        reason = "AWG через Docker"
        if stack.get("warp"):
            reason += " + WARP: двойная инкапсуляция — снижайте MTU на клиенте"
        recs.append({
            "target": "AWG клиент",
            "mtu": awg_mtu,
            "mss": max(awg_mtu - 40, 536),
            "reason": reason,
        })

    if stack.get("warp"):
        recs.append({
            "target": "WARP (wg-warp / warp0)",
            "mtu": WARP_OVERHEAD_MTU,
            "mss": max(WARP_OVERHEAD_MTU - 40, 536),
            "reason": "Туннель Cloudflare WARP — не поднимайте MTU выше 1280–1420",
        })

    main_iface = get_default_iface()
    main_mtu = get_iface_mtu(main_iface)
    recs.append({
        "target": f"Основной интерфейс ({main_iface})",
        "mtu": main_mtu,
        "mss": max(main_mtu - 40, 536),
        "reason": "Текущий MTU uplink; зондируйте через меню MTU [1]",
    })

    if stack.get("mieru"):
        recs.append({
            "target": "Mieru (mita)",
            "mtu": 1400,
            "mss": 1360,
            "reason": "mtu=1400 в server.json; клиентам — явный DNS (8.8.8.8 / 1.1.1.1)",
        })

    return recs


def get_default_iface() -> str:
    r = _run(["ip", "route", "show", "default"], check=False)
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return "eth0"


def get_iface_mtu(iface: str) -> int:
    try:
        r = _run(["cat", f"/sys/class/net/{iface}/mtu"], check=False)
        val = (r.stdout or "").strip()
        return int(val) if val.isdigit() else DEFAULT_MTU
    except Exception:
        return DEFAULT_MTU


def probe_path_mtu(host: str, max_mtu: int = 1500, min_mtu: int = 576) -> int:
    """ICMP path MTU discovery (DF bit)."""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return 0

    lo, hi = min_mtu, max_mtu
    best = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        payload = mid - 28
        if payload < 0:
            lo = mid + 1
            continue
        r = _run(
            ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), ip],
            check=False,
        )
        if r.returncode == 0:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def run_network_matrix() -> list[dict]:
    """Тестовая матрица: path MTU до ключевых целей."""
    targets = [
        ("1.1.1.1", "Cloudflare"),
        ("8.8.8.8", "Google DNS"),
    ]
    if is_warp_iface_up():
        targets.append(("162.159.192.1", "Cloudflare WARP edge"))

    results = []
    for host, label in targets:
        mtu = probe_path_mtu(host)
        results.append({"host": host, "label": label, "mtu": mtu})
    return results


def test_outbound_dns(host: str = "cloudflare.com") -> tuple[bool, str]:
    """Проверка исходящего DNS с сервера (важно для Mieru/Naive)."""
    try:
        socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        return True, f"getaddrinfo({host}) OK"
    except Exception as e:
        pass
    for resolver in ("1.1.1.1", "8.8.8.8"):
        try:
            r = _run(["dig", "+short", "A", host, f"@{resolver}"], timeout=8, check=False)
            if r.returncode == 0 and re.match(r"^\d", (r.stdout or "").strip()):
                return True, f"dig @{resolver} OK"
        except Exception:
            pass
    return False, f"не удалось разрешить {host}"


def apply_link_mtu(iface: str, mtu: int) -> bool:
    if not iface or mtu < 576:
        return False
    r = _run(["ip", "link", "set", "dev", iface, "mtu", str(mtu)], check=False)
    return r.returncode == 0


def apply_mss_clamp(mtu: int, table: str = "mangle", chain: str = "FORWARD") -> bool:
    """TCP MSS clamp: MSS = MTU - 40 (IPv4)."""
    mss = max(mtu - 40, 536)
    _run(
        ["iptables", "-t", table, "-D", chain, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--set-mss", str(mss)],
        check=False,
    )
    r = _run(
        ["iptables", "-t", table, "-A", chain, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--set-mss", str(mss)],
        check=False,
    )
    return r.returncode == 0


def clear_mss_clamp(table: str = "mangle", chain: str = "FORWARD") -> None:
    while True:
        r = _run(
            ["iptables", "-t", table, "-L", chain, "-n", "--line-numbers"],
            check=False,
        )
        if r.returncode != 0:
            break
        removed = False
        for line in (r.stdout or "").splitlines():
            if "TCPMSS" in line and "set-mss" in line.lower():
                num = line.split()[0]
                if num.isdigit():
                    _run(
                        ["iptables", "-t", table, "-D", chain, int(num)],
                        check=False,
                    )
                    removed = True
                    break
        if not removed:
            break


def save_mtu_state(data: dict) -> None:
    _MSS_STATE.parent.mkdir(parents=True, exist_ok=True)
    data.setdefault("timestamp", datetime.now().isoformat())
    _MSS_STATE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_mtu_state() -> dict | None:
    if not _MSS_STATE.exists():
        return None
    try:
        return json.loads(_MSS_STATE.read_text(encoding="utf-8"))
    except Exception:
        return None


def do_network_diagnostics_menu() -> None:
    """Интерактивная диагностика сети HYDRA (Фаза 3)."""
    import os
    import time

    from vless_installer.modules.box_renderer import (
        CYAN, DIM, GREEN, NC, RED, YELLOW,
        _box_back, _box_bottom, _box_item, _box_row, _box_sep, _box_top,
    )

    while True:
        os.system("clear")
        stack = detect_network_stack()
        print()
        _box_top("🌐  ДИАГНОСТИКА СЕТИ HYDRA")
        _box_row(f"  {DIM}Стек: {CYAN}{stack_label(stack)}{NC}")
        _box_sep()
        for key, label in (
            ("dnscrypt", "DNSCrypt-proxy"),
            ("warp", "WARP"),
            ("awg", "AmneziaWG (Docker)"),
            ("mieru", "Mieru (mita)"),
        ):
            on = stack.get(key)
            col = GREEN if on else DIM
            st = "активен" if on else "выкл"
            _box_row(f"  {col}●{NC} {label:<22} {st}")
        _box_sep()
        _box_item("1", "Рекомендации MTU/MSS по текущему стеку")
        _box_item("2", "Матрица path-MTU (ping DF)")
        _box_item("3", "Проверка исходящего DNS с сервера")
        _box_item("4", "Политика DNSCrypt + WARP")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break

        if ch in ("q", "Q", ""):
            break

        if ch == "1":
            os.system("clear")
            print()
            _box_top("📏  РЕКОМЕНДАЦИИ MTU")
            for rec in build_mtu_recommendations(stack):
                _box_row(f"  {CYAN}{rec['target']}{NC}")
                _box_row(f"    MTU {rec['mtu']}  MSS {rec['mss']}  {DIM}{rec['reason']}{NC}")
            _box_bottom()
            input("\nНажмите Enter...")

        elif ch == "2":
            os.system("clear")
            print()
            _box_top("📡  PATH MTU")
            _box_row(f"  {DIM}ICMP с DF-битом; 0 = хост недоступен или ICMP фильтруется{NC}")
            _box_sep()
            for row in run_network_matrix():
                mtu = row["mtu"]
                if mtu <= 0:
                    col = RED
                    txt = "н/д"
                elif mtu >= 1400:
                    col = GREEN
                    txt = str(mtu)
                elif mtu >= 1200:
                    col = YELLOW
                    txt = str(mtu)
                else:
                    col = RED
                    txt = str(mtu)
                _box_row(f"  {row['label']:<18} {col}{txt}{NC}")
            _box_bottom()
            input("\nНажмите Enter...")

        elif ch == "3":
            ok, msg = test_outbound_dns()
            os.system("clear")
            print()
            _box_top("🔍  DNS С СЕРВЕРА")
            col = GREEN if ok else RED
            _box_row(f"  {col}{msg}{NC}")
            if not ok and stack.get("dnscrypt"):
                _box_row(f"  {YELLOW}Подсказка:{NC} проверьте dnscrypt-proxy и resolved")
            _box_bottom()
            input("\nНажмите Enter...")

        elif ch == "4":
            os.system("clear")
            print()
            _box_top("📋  DNSCrypt + WARP")
            _box_row("  Системный DNS приложений → DNSCrypt (127.0.0.1:5300)")
            _box_row("  Синхронизация WARP-маршрутов → dig @1.1.1.1 / @8.8.8.8")
            _box_row("  (минуя локальный DNSCrypt, чтобы IP доменов были актуальны)")
            _box_sep()
            if stack.get("dnscrypt") and stack.get("warp"):
                _box_row(f"  {GREEN}Оба активны — политика bypass включена в warp_universal{NC}")
            elif stack.get("dnscrypt"):
                _box_row(f"  {YELLOW}Только DNSCrypt — WARP sync использует системный DNS{NC}")
            else:
                _box_row(f"  {DIM}DNSCrypt выкл — обычный системный резолв{NC}")
            _box_bottom()
            input("\nНажмите Enter...")

        else:
            time.sleep(0.5)
