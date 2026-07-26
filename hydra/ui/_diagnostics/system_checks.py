"""System, package and command helpers for diagnostics."""
from __future__ import annotations

import re
import shlex
import sys
import threading

from hydra.services.application import ApplicationService
from hydra.services.diagnostic_compatibility import (
    address_family,
    current_diagnostic_operations,
    operations_from_application,
    original_getaddrinfo as _original_getaddrinfo,
    selector_state,
)
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    NC,
    RED,
    clear,
    confirm,
    error,
    info,
    prompt,
    success,
    warn,
)
from hydra.utils.commands import DEFAULT_TIMEOUT


_thread_local = selector_state()

# Переопределяем socket.getaddrinfo для поддержки принудительной фильтрации по семейству (IPv4/IPv6)
original_getaddrinfo = _original_getaddrinfo

def filtered_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    version = getattr(_thread_local, "ip_version", None)
    return original_getaddrinfo(
        host,
        port,
        address_family(version, family),
        type,
        proto,
        flags,
    )

def check_system_ipv6() -> bool:
    """Быстрая проверка доступности IPv6 на уровне операционной системы."""
    return current_diagnostic_operations().ipv6_available()

def ensure_packages(pkgs: list[str], app: ApplicationService) -> bool:
    """Offer installation of missing diagnostic tools via the command port."""
    pkg_to_binary = {
        "dnsutils": "dig",
        "netcat-openbsd": "nc",
        "netcat": "nc",
        "bsdmainutils": "column",
    }
    missing = [
        pkg
        for pkg in pkgs
        if not operations_from_application(app).which(
            pkg_to_binary.get(pkg, pkg),
        )
    ]
    if not missing:
        return True
    warn(f"Для выполнения этого теста требуются утилиты: {', '.join(missing)}")
    if not confirm("Установить их сейчас?", default=True):
        return False
    info("Обновляю список пакетов и устанавливаю зависимости...")
    if app.admin.install_packages(missing):
        success("Зависимости успешно установлены")
        return True
    error("Не удалось установить зависимости")
    prompt("Нажмите Enter для продолжения...")
    return False



def _command_argv(cmd: str | list[str] | tuple[str, ...]) -> list[str]:
    """Convert legacy command strings to argv without invoking a shell."""
    argv = [str(item) for item in cmd] if not isinstance(cmd, str) else shlex.split(cmd)
    if not argv:
        raise ValueError("Пустая системная команда")
    return argv


def run_with_spinner(
    title_text: str,
    cmd: str | list[str] | tuple[str, ...],
    app: ApplicationService,
) -> str:
    """Запускает системную команду с плавной TUI-анимацией загрузки (spinner) и возвращает stdout."""
    operations = operations_from_application(app)
    process = app.admin.popen_command(
        _command_argv(cmd),
        stdout=operations.pipe,
        stderr=operations.devnull,
        text=True,
    )

    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    deadline = operations.monotonic() + DEFAULT_TIMEOUT
    try:
        while process.poll() is None:
            if operations.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise TimeoutError(f"Команда превысила таймаут {DEFAULT_TIMEOUT} секунд")
            sys.stdout.write(f"\r  {CYAN}[{spinner[idx]}]{NC} {title_text}...")
            sys.stdout.flush()
            idx = (idx + 1) % len(spinner)
            operations.sleep(0.1)
    except KeyboardInterrupt:
        process.terminate()
        process.wait()
        sys.stdout.write(f"\r  {RED}✗{NC} {title_text}: выполнение прервано.\n")
        sys.stdout.flush()
        raise KeyboardInterrupt

    stdout, _ = process.communicate()
    sys.stdout.write("\r" + " " * 80 + "\r")  # Очистка строки
    sys.stdout.flush()

    if process.returncode != 0:
        raise Exception(f"Команда завершилась с ошибкой ({process.returncode})")

    return stdout


def run_function_with_spinner(title_text: str, func, *args, **kwargs):
    """Запускает Python-функцию в фоновом потоке и показывает красивый спиннер в TUI."""
    operations = current_diagnostic_operations()
    result = []
    error_container = []

    def target():
        try:
            result.append(func(*args, **kwargs))
        except Exception as e:
            error_container.append(e)

    t = threading.Thread(target=target)
    t.start()

    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    try:
        while t.is_alive():
            sys.stdout.write(f"\r  {CYAN}[{spinner[idx]}]{NC} {title_text}...")
            sys.stdout.flush()
            idx = (idx + 1) % len(spinner)
            operations.sleep(0.1)
    except KeyboardInterrupt:
        sys.stdout.write(f"\r  {RED}✗{NC} {title_text}: выполнение прервано.\n")
        sys.stdout.flush()
        raise KeyboardInterrupt

    sys.stdout.write("\r" + " " * 80 + "\r")  # Очистка строки
    sys.stdout.flush()

    if error_container:
        raise error_container[0]

    return result[0]


def run_streaming_cmd(
    title_text: str,
    cmd: str | list[str] | tuple[str, ...],
    app: ApplicationService,
):
    """Стримит вывод команды в реальном времени, фильтруя шум и оборачивая вывод в рамки HYDRA."""
    print(f"\n  {CYAN}╔{'═' * 76}╗{NC}")
    print(f"  {CYAN}║{NC} {BOLD}{title_text:<74}{NC} {CYAN}║{NC}")
    print(f"  {CYAN}╠{'═' * 76}╣{NC}")

    operations = operations_from_application(app)
    process = app.admin.popen_command(
        _command_argv(cmd),
        stdout=operations.pipe,
        stderr=operations.stdout,
        text=True,
        bufsize=1
    )

    skip_patterns = [
        r"Performing IPv\d iperf3",
        r"Preparing system for disk tests",
        r"Generating fio test file",
        r"Running fio random mixed",
        r"yet-another-bench-script",
        r"masonr/yet-another-bench-script",
        r"# ## ## ## ## ## ## ##",
        r"wget -qO- bench.sh",
        r"Speedtest by Ookla"
    ]

    try:
        for line in process.stdout:
            cleaned = line.strip()
            if not cleaned:
                sys.stdout.write(f"  {CYAN}║{NC}{' ' * 76}{CYAN}║{NC}\n")
                sys.stdout.flush()
                continue

            should_skip = False
            for pat in skip_patterns:
                if re.search(pat, cleaned):
                    should_skip = True
                    break
            if should_skip:
                continue

            if all(c in "- ─" for c in cleaned) and len(cleaned) > 10:
                sys.stdout.write(f"  {CYAN}║{NC}{DIM}{'─' * 76}{NC}{CYAN}║{NC}\n")
                sys.stdout.flush()
                continue

            line_val = line.rstrip("\r\n").replace("\t", "    ")
            plain = re.sub(r"\033\[[0-9;]*m", "", line_val)
            visible_w = len(plain)

            if visible_w > 76:
                padded_line = line_val[:76]
            else:
                padded_line = line_val + " " * (76 - visible_w)

            sys.stdout.write(f"  {CYAN}║{NC}{padded_line}{CYAN}║{NC}\n")
            sys.stdout.flush()

    except KeyboardInterrupt:
        process.terminate()
        process.wait()
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(f"  {CYAN}╚{'═' * 76}╝{NC}")
        print(f"\n  {RED}[!] Выполнение прервано.{NC}")
        raise KeyboardInterrupt

    process.wait(timeout=DEFAULT_TIMEOUT)
    print(f"  {CYAN}╚{'═' * 76}╝{NC}")
    print()
    success("Тест завершен.")


def run_direct_cmd(
    title_text: str,
    cmd: str | list[str] | tuple[str, ...],
    app: ApplicationService,
):
    """Очищает экран, выводит заголовок HYDRA и запускает команду напрямую (для поддержки интерактивных TUI-меню)."""
    clear()
    print(f"\n  {CYAN}╔{'═' * 76}╗{NC}")
    print(f"  {CYAN}║{NC} {BOLD}{title_text:<74}{NC} {CYAN}║{NC}")
    print(f"  {CYAN}╚{'═' * 76}╝{NC}\n")

    try:
        app.admin.run_command(_command_argv(cmd), timeout=DEFAULT_TIMEOUT, check=False)
    except KeyboardInterrupt:
        print(f"\n  {RED}[!] Выполнение прервано.{NC}")
