"""
hydra/utils/firewall.py — Менеджер firewall: авто-выбор UFW/iptables, persist правил.

Логика портирована из legacy vless_installer/modules/naiveproxy.py и mieru.py
(_ipt_*/_ufw_* хелперы — идентичны в обоих модулях).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


# ══════════════════════════════════════════════════════════════════════════════
#  Внутренние хелперы
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: list[str], capture: bool = True) -> subprocess.CompletedProcess:
    """Выполнить команду, вернуть CompletedProcess."""
    return subprocess.run(cmd, capture_output=capture, text=True)


def _ipt_rule_exists(table: str, chain: str, spec: list[str]) -> bool:
    """Проверяет существование iptables-правила по спецификации."""
    r = _run(["iptables", "-t", table, "-C", chain] + spec, capture=True)
    return r.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
#  UFW
# ══════════════════════════════════════════════════════════════════════════════

def is_ufw_active() -> bool:
    """True если ufw есть и status: active.

    ВАЖНО: «inactive» содержит подстроку «active» — поэтому проверяем
    именно «status: active», а не просто «active» в выводе.
    """
    if not shutil.which("ufw"):
        return False
    r = _run(["ufw", "status"], capture=True)
    return "status: active" in r.stdout.lower()


def _ufw_open(proto: str, port_start: int, port_end: int, comment: str) -> None:
    """Открывает порты через UFW."""
    proto = proto.lower()
    if port_start == port_end:
        _run(["ufw", "allow", f"{port_start}/{proto}", "comment", comment])
    else:
        _run(["ufw", "allow", f"{port_start}:{port_end}/{proto}", "comment", comment])


def _ufw_close(proto: str, port_start: int, port_end: int) -> None:
    """Закрывает порты через UFW."""
    proto = proto.lower()
    if port_start == port_end:
        _run(["ufw", "delete", "allow", f"{port_start}/{proto}"])
    else:
        _run(["ufw", "delete", "allow", f"{port_start}:{port_end}/{proto}"])


# ══════════════════════════════════════════════════════════════════════════════
#  iptables
# ══════════════════════════════════════════════════════════════════════════════

def _ipt_open(proto: str, port_start: int, port_end: int, comment: str) -> None:
    """Открывает порты через iptables INPUT."""
    proto = proto.lower()
    comment_spec = ["-m", "comment", "--comment", comment]
    if port_start == port_end:
        spec = ["-p", proto, "--dport", str(port_start), "-j", "ACCEPT"] + comment_spec
        if not _ipt_rule_exists("filter", "INPUT", spec):
            _run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + spec)
    else:
        spec = ["-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"] + comment_spec
        if not _ipt_rule_exists("filter", "INPUT", spec):
            _run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + spec)


def _ipt_close(proto: str, port_start: int, port_end: int) -> None:
    """Закрывает порты через iptables INPUT."""
    proto = proto.lower()
    if port_start == port_end:
        for _ in range(5):
            spec = ["-p", proto, "--dport", str(port_start), "-j", "ACCEPT"]
            if not _ipt_rule_exists("filter", "INPUT", spec):
                break
            _run(["iptables", "-t", "filter", "-D", "INPUT"] + spec)
    else:
        for _ in range(5):
            spec = ["-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"]
            if not _ipt_rule_exists("filter", "INPUT", spec):
                break
            _run(["iptables", "-t", "filter", "-D", "INPUT"] + spec)


# ══════════════════════════════════════════════════════════════════════════════
#  Persist
# ══════════════════════════════════════════════════════════════════════════════

def persist() -> None:
    """Сохраняет текущие правила: netfilter-persistent save либо /etc/iptables/rules.v4."""
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"])
        return
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r = _run(["iptables-save"])
    if r.returncode == 0 and r.stdout:
        (rules_dir / "rules.v4").write_text(r.stdout)


# ══════════════════════════════════════════════════════════════════════════════
#  Публичный API
# ══════════════════════════════════════════════════════════════════════════════

def open_tcp(port: int, comment: str = "hydra") -> str:
    """Открывает TCP порт через UFW (если активен) иначе iptables. Возвращает описание."""
    if is_ufw_active():
        _ufw_open("tcp", port, port, comment)
        return f"UFW: TCP {port} открыт."
    _ipt_open("tcp", port, port, comment)
    persist()
    return f"iptables: TCP {port} открыт."


def open_udp(port: int, comment: str = "hydra") -> str:
    """Открывает UDP порт через UFW (если активен) иначе iptables. Возвращает описание."""
    if is_ufw_active():
        _ufw_open("udp", port, port, comment)
        return f"UFW: UDP {port} открыт."
    _ipt_open("udp", port, port, comment)
    persist()
    return f"iptables: UDP {port} открыт."


def open_range(proto: str, start: int, end: int, comment: str = "hydra") -> str:
    """Открывает диапазон портов. proto = 'tcp' | 'udp'."""
    if is_ufw_active():
        _ufw_open(proto, start, end, comment)
        return f"UFW: {proto} {start}-{end} открыт."
    _ipt_open(proto, start, end, comment)
    persist()
    return f"iptables: {proto} {start}-{end} открыт."


def close_tcp(port: int) -> None:
    """Закрывает TCP порт через UFW (если активен) иначе iptables."""
    if is_ufw_active():
        _ufw_close("tcp", port, port)
    else:
        _ipt_close("tcp", port, port)
        persist()


def close_udp(port: int) -> None:
    """Закрывает UDP порт через UFW (если активен) иначе iptables."""
    if is_ufw_active():
        _ufw_close("udp", port, port)
    else:
        _ipt_close("udp", port, port)
        persist()


def close_range(proto: str, start: int, end: int) -> None:
    """Закрывает диапазон портов. proto = 'tcp' | 'udp'."""
    if is_ufw_active():
        _ufw_close(proto, start, end)
    else:
        _ipt_close(proto, start, end)
        persist()
