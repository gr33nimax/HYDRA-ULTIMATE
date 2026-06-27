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


def persist_link_mtu(iface: str, mtu: int) -> None:
    """Сохраняет MTU uplink в netplan или /etc/network/interfaces."""
    netplan_dir = Path("/etc/netplan")
    if netplan_dir.exists():
        for yf in list(netplan_dir.glob("*.yaml")) + list(netplan_dir.glob("*.yml")):
            try:
                txt = yf.read_text(encoding="utf-8")
                if iface in txt and f"mtu: {mtu}" not in txt:
                    new_txt = re.sub(
                        rf"((?:ethernets|wifis|bonds|vlans):\s*\n\s+{re.escape(iface)}:.*?\n)",
                        lambda m: m.group(0) + f"      mtu: {mtu}\n",
                        txt,
                        flags=re.DOTALL,
                    )
                    if new_txt != txt:
                        yf.write_text(new_txt, encoding="utf-8")
                        _run(["netplan", "apply"], check=False)
                        return
            except Exception:
                pass
    interfaces_file = Path("/etc/network/interfaces")
    if interfaces_file.exists():
        try:
            txt = interfaces_file.read_text(encoding="utf-8")
            if f"iface {iface}" in txt and f"mtu {mtu}" not in txt:
                new_txt = re.sub(
                    rf"(iface {re.escape(iface)}[^\n]*)",
                    lambda m: m.group(0) + f"\n    mtu {mtu}",
                    txt,
                )
                if new_txt != txt:
                    interfaces_file.write_text(new_txt, encoding="utf-8")
        except Exception:
            pass


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
        _box_item("5", f"{GREEN}Мастер MTU — зондирование и применение ко всему стеку{NC}")
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

        elif ch == "5":
            do_mtu_stack_wizard(apply=True)

        else:
            time.sleep(0.5)


# =============================================================================
#  Зондирование + применение MTU по всему стеку HYDRA
# =============================================================================

_PROBE_HOSTS = (
    ("1.1.1.1", "Cloudflare"),
    ("8.8.8.8", "Google DNS"),
    ("208.67.222.222", "OpenDNS"),
)

_AWG_MTU_HINT = Path("/var/lib/xray-installer/awg_mtu_hint.json")
_MIERU_SERVER_CFG = Path("/etc/mita/server.json")


def get_warp_interface() -> str | None:
    try:
        from vless_installer.modules.warp_universal import detect_warp_interface
        return detect_warp_interface()
    except Exception:
        pass
    for iface in ("wg-warp", "warp0", "CloudflareWARP", "tun0"):
        r = _run(["ip", "link", "show", iface], check=False)
        if r.returncode == 0:
            return iface
    return None


def get_awg_container_name() -> str | None:
    try:
        r = _run(["docker", "ps", "-a", "--format", "{{.Names}}"], check=False, timeout=10)
        if r.returncode != 0:
            return None
        names = [n.strip() for n in (r.stdout or "").splitlines() if n.strip()]
        for cand in ("amnezia-awg2", "amnezia-awg", "amnezia-wg"):
            if cand in names:
                return cand
        for n in names:
            if n.startswith("amnezia-") and ("awg" in n or "wg" in n):
                return n
    except Exception:
        pass
    return None


def probe_uplink_mtu() -> tuple[int, list[dict]]:
    """Path-MTU до внешних узлов; возвращает (оптимальный MTU, детали)."""
    details: list[dict] = []
    mtus: list[int] = []
    for host, label in _PROBE_HOSTS:
        m = probe_path_mtu(host)
        details.append({"host": host, "label": label, "mtu": m})
        if m > 0:
            mtus.append(m)
    optimal = min(mtus) if mtus else 1420
    return optimal, details


def compute_stack_mtu_plan(uplink_mtu: int, stack: dict[str, bool] | None = None) -> list[dict]:
    """План: что и куда применить (uplink, WARP, AWG, Mieru, MSS)."""
    if stack is None:
        stack = detect_network_stack()
    plan: list[dict] = []

    main_iface = get_default_iface()
    plan.append({
        "component": "uplink",
        "target": main_iface,
        "mtu": uplink_mtu,
        "mss": max(uplink_mtu - 40, 536),
        "action": "ip_link",
        "desc": f"Основной интерфейс {main_iface}",
    })

    warp_iface = get_warp_interface()
    if stack.get("warp") and warp_iface:
        warp_mtu = min(uplink_mtu - 80, 1420)
        if stack.get("awg"):
            warp_mtu = min(warp_mtu, 1280)
        warp_mtu = max(int(warp_mtu), 1280)
        plan.append({
            "component": "warp",
            "target": warp_iface,
            "mtu": warp_mtu,
            "mss": max(warp_mtu - 40, 536),
            "action": "ip_link",
            "desc": f"WARP {warp_iface}",
        })

    if stack.get("awg"):
        awg_mtu = 1280 if stack.get("warp") else min(uplink_mtu - 80, 1420)
        awg_mtu = max(int(awg_mtu), 1280)
        cname = get_awg_container_name() or "amnezia"
        plan.append({
            "component": "awg",
            "target": cname,
            "mtu": awg_mtu,
            "mss": max(awg_mtu - 40, 536),
            "action": "awg_docker",
            "desc": f"AWG в Docker ({cname}): awg0 + клиентские .conf",
        })

    if stack.get("mieru") and _MIERU_SERVER_CFG.exists():
        mieru_mtu = min(uplink_mtu - 60, 1400)
        mieru_mtu = max(int(mieru_mtu), 1200)
        plan.append({
            "component": "mieru",
            "target": "mita",
            "mtu": mieru_mtu,
            "mss": max(mieru_mtu - 40, 536),
            "action": "mieru_config",
            "desc": "Mieru server.json + restart mita",
        })

    plan.append({
        "component": "mss",
        "target": "FORWARD",
        "mtu": uplink_mtu,
        "mss": max(uplink_mtu - 40, 536),
        "action": "mss_clamp",
        "desc": "iptables TCPMSS на FORWARD",
    })
    return plan


def _patch_wg_conf_mtu(conf_text: str, mtu: int) -> str:
    """Добавляет/заменяет MTU = в секции [Interface]."""
    lines = conf_text.splitlines()
    out: list[str] = []
    in_iface = False
    found_mtu = False
    for line in lines:
        stripped = line.strip()
        low = stripped.lower()
        if low == "[interface]":
            in_iface = True
            found_mtu = False
            out.append(line)
            continue
        if stripped.startswith("[") and in_iface:
            if not found_mtu:
                out.append(f"MTU = {mtu}")
            in_iface = False
            found_mtu = False
            out.append(line)
            continue
        if in_iface and low.startswith("mtu"):
            out.append(f"MTU = {mtu}")
            found_mtu = True
            continue
        out.append(line)
    if in_iface and not found_mtu:
        out.append(f"MTU = {mtu}")
    return "\n".join(out) + ("\n" if out else "")


def apply_awg_mtu_in_container(mtu: int) -> tuple[bool, str]:
    """MTU на awg0 внутри контейнера + правка awg0.conf и клиентских конфигов."""
    name = get_awg_container_name()
    if not name:
        return False, "контейнер AWG не найден"

    msgs: list[str] = []
    ok_any = False

    for wg_iface in ("awg0", "wg0"):
        r = _run(["docker", "exec", name, "ip", "link", "show", wg_iface], check=False, timeout=15)
        if r.returncode != 0:
            continue
        r2 = _run(
            ["docker", "exec", name, "ip", "link", "set", "dev", wg_iface, "mtu", str(mtu)],
            check=False, timeout=15,
        )
        if r2.returncode == 0:
            msgs.append(f"{wg_iface} mtu={mtu}")
            ok_any = True

    for conf_name in ("awg0.conf", "wg0.conf"):
        conf_path = f"/opt/amnezia/awg/{conf_name}"
        r = _run(["docker", "exec", name, "cat", conf_path], check=False, timeout=15)
        if r.returncode != 0:
            continue
        patched = _patch_wg_conf_mtu(r.stdout, mtu)
        if patched == r.stdout:
            continue
        proc = subprocess.run(
            ["docker", "exec", "-i", name, "tee", conf_path],
            input=patched, text=True, capture_output=True, timeout=30,
        )
        if proc.returncode == 0:
            msgs.append(f"патч {conf_name}")
            ok_any = True

    r_files = _run(
        ["docker", "exec", name, "find", "/opt/amnezia/awg/", "-name", "*.conf"],
        check=False, timeout=20,
    )
    if r_files.returncode == 0:
        for fpath in (r_files.stdout or "").splitlines():
            fpath = fpath.strip()
            if not fpath or fpath.endswith(("awg0.conf", "wg0.conf")):
                continue
            r_cat = _run(["docker", "exec", name, "cat", fpath], check=False, timeout=15)
            if r_cat.returncode != 0 or "[Interface]" not in r_cat.stdout:
                continue
            patched = _patch_wg_conf_mtu(r_cat.stdout, mtu)
            if patched == r_cat.stdout:
                continue
            proc = subprocess.run(
                ["docker", "exec", "-i", name, "tee", fpath],
                input=patched, text=True, capture_output=True, timeout=30,
            )
            if proc.returncode == 0:
                msgs.append(f"клиент {Path(fpath).name}")
                ok_any = True

    _AWG_MTU_HINT.parent.mkdir(parents=True, exist_ok=True)
    _AWG_MTU_HINT.write_text(
        json.dumps({
            "mtu": mtu,
            "container": name,
            "updated": datetime.now().isoformat(),
            "note": "Укажите MTU = {mtu} в AmneziaVPN на клиенте, если приложение не подхватило из .conf",
        }, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if ok_any:
        return True, "; ".join(msgs)
    return False, "awg0/wg0 не найден в контейнере"


def apply_mieru_mtu(mtu: int) -> tuple[bool, str]:
    """Обновляет mtu в server.json и перезапускает mita."""
    if not _MIERU_SERVER_CFG.exists():
        return False, "server.json не найден — сначала установите Mieru"
    try:
        cfg = json.loads(_MIERU_SERVER_CFG.read_text(encoding="utf-8"))
    except Exception as e:
        return False, f"не читается server.json: {e}"

    cfg["mtu"] = mtu
    cfg_text = json.dumps(cfg, indent=2, ensure_ascii=False)
    _MIERU_SERVER_CFG.write_text(cfg_text, encoding="utf-8")
    tmp_cfg = Path("/etc/mita/server.json")
    tmp_cfg.parent.mkdir(parents=True, exist_ok=True)
    tmp_cfg.write_text(cfg_text, encoding="utf-8")
    tmp_cfg.chmod(0o600)

    mita = Path("/usr/local/bin/mita")
    if mita.exists():
        r = _run([str(mita), "apply", "config", str(tmp_cfg)], check=False, timeout=60)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "")[:200]
            return False, f"mita apply config: {err}"

    _run(["systemctl", "restart", "mita"], check=False)
    return True, f"server.json mtu={mtu}, mita перезапущен"


def apply_plan_item(item: dict) -> tuple[bool, str]:
    action = item.get("action", "")
    mtu = int(item.get("mtu", 1500))
    target = item.get("target", "")

    if action == "ip_link":
        ok = apply_link_mtu(target, mtu)
        return ok, f"{target} → MTU {mtu}" if ok else f"не удалось: {target}"

    if action == "awg_docker":
        return apply_awg_mtu_in_container(mtu)

    if action == "mieru_config":
        return apply_mieru_mtu(mtu)

    if action == "mss_clamp":
        ok = apply_mss_clamp(mtu)
        return ok, f"MSS clamp {mtu - 40} на FORWARD"

    return False, f"неизвестное действие: {action}"


def apply_stack_mtu_plan(plan: list[dict]) -> list[dict]:
    """Применяет план; возвращает список {component, ok, message}."""
    results: list[dict] = []
    for item in plan:
        ok, msg = apply_plan_item(item)
        results.append({
            "component": item.get("component", "?"),
            "ok": ok,
            "message": msg,
        })
    return results


def reset_stack_mtu() -> list[str]:
    """Сброс uplink/WARP MTU и MSS-правил."""
    msgs: list[str] = []
    main = get_default_iface()
    if apply_link_mtu(main, DEFAULT_MTU):
        msgs.append(f"{main} → 1500")
    warp = get_warp_interface()
    if warp and apply_link_mtu(warp, 1420):
        msgs.append(f"{warp} → 1420")
    clear_mss_clamp()
    msgs.append("MSS rules cleared")
    if _MSS_STATE.exists():
        _MSS_STATE.unlink()
    return msgs


def do_mtu_stack_wizard(apply: bool = True) -> None:
    """
    Мастер: зондирование uplink → план по стеку → (опционально) применение.
    """
    import os

    from vless_installer.modules.box_renderer import (
        BLUE, BOLD, CYAN, DIM, GREEN, NC, RED, YELLOW,
        _box_bottom, _box_row, _box_sep, _box_top,
    )

    stack = detect_network_stack()
    os.system("clear")
    print()
    _box_top("📡  МАСТЕР MTU — HYDRA STACK")
    _box_row(f"  {DIM}Стек: {CYAN}{stack_label(stack)}{NC}")
    _box_row(f"  {DIM}Зондирование path-MTU (ICMP DF)...{NC}")
    _box_sep()

    uplink_mtu, probe_details = probe_uplink_mtu()
    for row in probe_details:
        m = row["mtu"]
        if m <= 0:
            col, txt = RED, "н/д"
        elif m >= 1400:
            col, txt = GREEN, str(m)
        elif m >= 1200:
            col, txt = YELLOW, str(m)
        else:
            col, txt = RED, str(m)
        _box_row(f"  {row['label']:<16} {col}{txt}{NC}")

    _box_sep()
    _box_row(f"  {BOLD}Uplink MTU:{NC}  {GREEN}{uplink_mtu}{NC}  {DIM}(min из ответивших){NC}")

    plan = compute_stack_mtu_plan(uplink_mtu, stack)
    _box_sep()
    _box_row(f"  {BOLD}План применения:{NC}")
    for p in plan:
        if p["action"] == "mss_clamp":
            _box_row(f"    {CYAN}{p['desc']}{NC}  MSS={p['mss']}")
        else:
            _box_row(f"    {CYAN}{p['desc']}{NC}  MTU={p['mtu']}")

    if not apply:
        _box_row()
        _box_row(f"  {DIM}Режим просмотра — изменения не применены{NC}")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    _box_row()
    try:
        ans = input(f"  {YELLOW}Применить план ко всему стеку? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans != "y":
        _box_row(f"  {DIM}Отмена{NC}")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    _box_sep()
    results = apply_stack_mtu_plan(plan)
    for res in results:
        col = GREEN if res["ok"] else RED
        _box_row(f"  {col}{'✓' if res['ok'] else '✗'}{NC} {res['component']}: {res['message']}")

    uplink_item = next((p for p in plan if p.get("component") == "uplink"), None)
    if uplink_item and uplink_item.get("action") == "ip_link":
        persist_link_mtu(uplink_item["target"], uplink_item["mtu"])
        _box_row(f"  {DIM}Uplink MTU сохранён в netplan/interfaces (если доступно){NC}")

    save_mtu_state({
        "applied_mtu": uplink_mtu,
        "interface": get_default_iface(),
        "mss": uplink_mtu - 40,
        "stack": stack,
        "plan": [{"component": p["component"], "target": p["target"], "mtu": p["mtu"]} for p in plan],
        "probe_results": probe_details,
        "apply_results": results,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

    _box_bottom()
    input(f"\n{BLUE}Нажмите Enter...{NC}")
