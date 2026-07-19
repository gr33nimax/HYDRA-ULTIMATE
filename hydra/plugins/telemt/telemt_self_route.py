"""
telemt_self_route.py
====================
Маршрутизация исходящего трафика самого процесса Telemt через Sing-Box.
Использует марку 0xff для защиты Sing-Box от зацикливания и iptables REDIRECT.
"""
from __future__ import annotations

from hydra.core.host import HOST

import shutil
import subprocess
from pathlib import Path

__all__ = ["enable", "disable", "status"]

# ---------------------------------------------------------------------------
#  Константы
# ---------------------------------------------------------------------------
_TELEMT_SERVICE   = Path("/etc/systemd/system/telemt.service")
_SINGBOX_SERVICE  = "sing-box.service"
_AFTER_MARKER     = "After=sing-box.service"
_IPT              = "iptables"

# Подсети Telegram
from hydra.plugins.telemt.tg_nets import get_tg_nets

# ---------------------------------------------------------------------------
#  Вспомогательные функции
# ---------------------------------------------------------------------------

def _run(cmd: list) -> subprocess.CompletedProcess:
    return HOST.run(cmd, capture_output=True, text=True)


def _return_rule_exists() -> bool:
    """Проверяет наличие RETURN правила для пакетов с маркой 0xff в nat OUTPUT."""
    r = _run([_IPT, "-t", "nat", "-C", "OUTPUT",
              "-m", "mark", "--mark", "0xff",
              "-j", "RETURN"])
    return r.returncode == 0


def _add_return_rule() -> bool:
    """Вставляет RETURN правило для пакетов с маркой 0xff на позицию 1 в nat OUTPUT."""
    if _return_rule_exists():
        return True
    r = _run([_IPT, "-t", "nat", "-I", "OUTPUT", "1",
              "-m", "mark", "--mark", "0xff",
              "-j", "RETURN"])
    return r.returncode == 0


def _del_return_rule() -> None:
    """Удаляет RETURN правило для пакетов с маркой 0xff из nat OUTPUT (все копии)."""
    for _ in range(5):
        if not _return_rule_exists():
            break
        _run([_IPT, "-t", "nat", "-D", "OUTPUT",
              "-m", "mark", "--mark", "0xff",
              "-j", "RETURN"])


def _port8888_rule_exists() -> bool:
    """Проверяет наличие RETURN правила для порта 8888 в nat OUTPUT."""
    r = _run([_IPT, "-t", "nat", "-C", "OUTPUT",
              "-p", "tcp", "--dport", "8888",
              "-j", "RETURN"])
    return r.returncode == 0


def _add_port8888_rule() -> bool:
    """Вставляет RETURN правило для порта 8888 на позицию 2 в nat OUTPUT."""
    if _port8888_rule_exists():
        return True
    r = _run([_IPT, "-t", "nat", "-I", "OUTPUT", "2",
              "-p", "tcp", "--dport", "8888",
              "-j", "RETURN"])
    return r.returncode == 0


def _del_port8888_rule() -> None:
    """Удаляет RETURN правило для порта 8888 из nat OUTPUT."""
    for _ in range(5):
        if not _port8888_rule_exists():
            break
        _run([_IPT, "-t", "nat", "-D", "OUTPUT",
              "-p", "tcp", "--dport", "8888",
              "-j", "RETURN"])


def _ipt_rule_exists(net: str, port: int) -> bool:
    v6  = ":" in net
    ipt = "ip6tables" if v6 else _IPT
    r   = _run([ipt, "-t", "nat", "-C", "OUTPUT",
                "-d", net, "-p", "tcp",
                "-j", "REDIRECT", "--to-port", str(port)])
    return r.returncode == 0


def _ipt_add_redirect(net: str, port: int) -> bool:
    if _ipt_rule_exists(net, port):
        return True
    v6  = ":" in net
    ipt = "ip6tables" if v6 else _IPT
    r   = _run([ipt, "-t", "nat", "-A", "OUTPUT",
                "-d", net, "-p", "tcp",
                "-j", "REDIRECT", "--to-port", str(port)])
    return r.returncode == 0


def _ipt_del_redirect(net: str, port: int) -> None:
    for _ in range(5):
        if not _ipt_rule_exists(net, port):
            break
        v6  = ":" in net
        ipt = "ip6tables" if v6 else _IPT
        _run([ipt, "-t", "nat", "-D", "OUTPUT",
              "-d", net, "-p", "tcp",
              "-j", "REDIRECT", "--to-port", str(port)])


def _service_has_after() -> bool:
    """Проверяет наличие After=sing-box.service в telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return False
    text = _TELEMT_SERVICE.read_text()
    for line in text.splitlines():
        if line.startswith("After=") and "sing-box.service" in line:
            return True
    return False


def _add_after_to_service() -> bool:
    """Добавляет After=sing-box.service в секцию [Unit] telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return False
    if _service_has_after():
        return True

    text = _TELEMT_SERVICE.read_text()

    # Ищем строку After= в секции [Unit] и дописываем sing-box.service
    lines = text.splitlines()
    new_lines = []
    inserted = False
    for line in lines:
        new_lines.append(line)
        if not inserted and line.startswith("After="):
            new_lines[-1] = line.rstrip() + " sing-box.service"
            inserted = True

    if not inserted:
        final = []
        for line in new_lines:
            final.append(line)
            if line.strip() == "[Unit]":
                final.append(_AFTER_MARKER)
                inserted = True
        new_lines = final

    if not inserted:
        return False

    _TELEMT_SERVICE.write_text("\n".join(new_lines) + "\n")
    return True


def _remove_after_from_service() -> bool:
    """Убирает sing-box.service из After= в telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return True
    text = _TELEMT_SERVICE.read_text()
    if _AFTER_MARKER not in text and "sing-box.service" not in text:
        return True

    lines = text.splitlines()
    new_lines = []
    for line in lines:
        if line.startswith("After=") and "sing-box.service" in line:
            parts = line.split()
            parts = [p for p in parts if p != "sing-box.service"]
            line = " ".join(parts)
            if line.strip() == "After=":
                continue
        new_lines.append(line)

    _TELEMT_SERVICE.write_text("\n".join(new_lines) + "\n")
    return True


def _systemd_reload() -> None:
    _run(["systemctl", "daemon-reload"])


def _iptables_persist() -> None:
    """Сохраняет iptables правила для выживания после ребута."""
    if shutil.which("netfilter-persistent"):
        r = _run(["netfilter-persistent", "save"])
        if r.returncode == 0:
            return
    _run(["bash", "-c",
          "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true"])

# ---------------------------------------------------------------------------
#  Публичное API
# ---------------------------------------------------------------------------

def enable(redirect_port: int = 10811) -> tuple[bool, str]:
    """
    Активирует маршрутизацию трафика telemt через sing-box:
      1. Вставляет RETURN rule для пакетов с маркой 0xff и порта 8888
      2. Добавляет After=sing-box.service в telemt.service
      3. Перенаправляет подсети Telegram на redirect_port
      4. Перезагружает systemd daemon
    """
    # 1. RETURN rules
    if not _add_return_rule():
        return False, "Не удалось добавить iptables RETURN rule для марки 0xff"
        
    _add_port8888_rule()

    # 2. After=sing-box.service
    if _TELEMT_SERVICE.exists():
        _add_after_to_service()
        _systemd_reload()

    # 3. REDIRECT rules
    nets = get_tg_nets()
    failed = [n for n in nets if not _ipt_add_redirect(n, redirect_port)]
    _iptables_persist()

    if failed:
        return False, f"Не удалось настроить REDIRECT для: {', '.join(failed[:3])}"

    return True, f"Маршрутизация через Sing-Box активирована (redirect :{redirect_port}, {len(nets)} подсетей)."


def disable(redirect_port: int = 10811) -> tuple[bool, str]:
    """
    Откатывает изменения:
      1. Удаляет RETURN rules
      2. Убирает After=sing-box.service из telemt.service
      3. Удаляет REDIRECT правила подсетей Telegram
    """
    _del_return_rule()
    _del_port8888_rule()
    
    _remove_after_from_service()
    _systemd_reload()

    nets = get_tg_nets()
    for n in nets:
        _ipt_del_redirect(n, redirect_port)
    _iptables_persist()

    return True, "Маршрутизация трафика telemt через sing-box отключена."


def status(redirect_port: int = 10811) -> dict:
    """
    Возвращает текущее состояние:
      {
        "return_rule": bool,   — RETURN rule для марки 0xff активен
        "after_xray":  bool,   — After=sing-box.service в telemt.service
        "ipt_count":   int,    — количество активных правил REDIRECT
        "ipt_total":   int,    — общее количество подсетей Telegram
      }
    """
    nets = get_tg_nets()
    ipt_active = sum(1 for n in nets if _ipt_rule_exists(n, redirect_port))
    
    return {
        "return_rule": _return_rule_exists(),
        "after_xray":  _service_has_after(),
        "ipt_count":   ipt_active,
        "ipt_total":   len(nets),
        "xray_uid":    None,
    }
