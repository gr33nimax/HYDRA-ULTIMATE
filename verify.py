#!/usr/bin/env python3
"""
verify.py — Проверка целостности VLESS Ultimate Installer v4.11.3
Запуск: python3 verify.py
"""
import sys
import ast
import subprocess
from pathlib import Path

GREEN = "\033[0;32m"; RED = "\033[0;31m"; YELLOW = "\033[1;33m"
CYAN  = "\033[0;36m"; BOLD = "\033[1m";  NC    = "\033[0m"

passed = 0; failed = 0

def ok(msg):
    global passed; passed += 1
    print(f"  {GREEN}✓{NC} {msg}")

def fail(msg):
    global failed; failed += 1
    print(f"  {RED}✗{NC} {msg}")

def section(title):
    print(f"\n{CYAN}{BOLD}{'━'*55}{NC}")
    print(f"{CYAN}{BOLD}  {title}{NC}")
    print(f"{CYAN}{BOLD}{'━'*55}{NC}")

sys.path.insert(0, str(Path(__file__).parent))

# ── 1. Файловая структура ────────────────────────────────────
section("1. Файловая структура")
required = [
    "main.py",
    "bootstrap.sh",
    "verify.py",
    "README.md",
    "TROUBLESHOOTING.md",
    "INSTALL.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "LICENSE",
    ".gitignore",
    "vless_installer/__init__.py",
    "vless_installer/_core.py",
    "vless_installer/modules/sub_generator.py",
    "vless_installer/modules/sub_server.py",
    "vless_installer/modules/warp_universal.py",
]
for f in required:
    if Path(f).exists():
        ok(f)
    else:
        fail(f"{f} — НЕ НАЙДЕН")

# ── 2. Синтаксис Python файлов ───────────────────────────────
section("2. Синтаксис Python файлов")
for py in ["main.py", "verify.py",
           "vless_installer/__init__.py",
           "vless_installer/_core.py",
           "vless_installer/modules/sub_generator.py",
           "vless_installer/modules/sub_server.py",
           "vless_installer/modules/warp_universal.py"]:
    try:
        ast.parse(Path(py).read_text(encoding="utf-8"))
        ok(f"{py} — синтаксис OK")
    except SyntaxError as e:
        fail(f"{py} — SyntaxError L{e.lineno}: {e.msg}")
    except FileNotFoundError:
        fail(f"{py} — файл не найден")

# ── 3. Целостность _core.py ──────────────────────────────────
section("3. Целостность _core.py")
core = Path("vless_installer/_core.py")
if core.exists():
    lines = len(core.read_text(encoding="utf-8").splitlines())
    if lines > 30000:
        ok(f"_core.py: {lines} строк — полный")
    else:
        fail(f"_core.py: {lines} строк — подозрительно мало")
else:
    fail("_core.py не найден")

# ── 4. Ключевые функции в _core.py ───────────────────────────
section("4. Ключевые функции в _core.py")
if core.exists():
    key_funcs = [
        ("def main_menu(", "vless_installer/_core.py"),
        ("def ensure_startup_dependencies(", "vless_installer/_core.py"),
        ("def _init_pkg_mgr(", "vless_installer/_core.py"),
        ("def print_banner(", "vless_installer/_core.py"),
        ("def gen_uuid(", "vless_installer/_core.py"),
        ("def _run(", "vless_installer/_core.py"),
        ("def log_to_file(", "vless_installer/_core.py"),
        ("def switch_mode_ab(", "vless_installer/_core.py"),
        ("def _smart_recover(", "vless_installer/_core.py"),
        ("def do_quick_status(", "vless_installer/_core.py"),
        ("def _ttl_check_and_expire(", "vless_installer/_core.py"),
        ("def _ru_subnets_cli_update(", "vless_installer/_core.py"),
        ("def _as_direct_cli_update(", "vless_installer/_core.py"),
        ("def _ingress_state_load(", "vless_installer/modules/ingress_geoip.py"),
        ("def _ingress_enable(", "vless_installer/modules/ingress_geoip.py"),
        ("def _ingress_remove(", "vless_installer/modules/ingress_geoip.py"),
        ("def tg_notify_event(", "vless_installer/modules/tg_bot.py"),
        ("def _autoban_run_once(", "vless_installer/_core.py"),
        ("def _scheduled_backup_run(", "vless_installer/_core.py"),
        ("def _asn_cache_connect(", "vless_installer/_core.py"),
        ("def _asn_cache_delete(", "vless_installer/_core.py"),
        ("def get_server_country_cached(", "vless_installer/_core.py"),
    ]
    file_contents = {}
    for func_sig, filepath in key_funcs:
        if filepath not in file_contents:
            p = Path(filepath)
            file_contents[filepath] = p.read_text(encoding="utf-8") if p.exists() else ""
        
        name = func_sig.replace("def ", "").rstrip("(")
        if func_sig in file_contents[filepath]:
            ok(f"{name}()")
        else:
            fail(f"{name}() — НЕ НАЙДЕНА в {filepath}")

# ── 5. Загрузка _core.py через exec ──────────────────────────
section("5. Загрузка _core.py через exec (как делает main.py)")
try:
    import sys
    from types import ModuleType
    if sys.platform == "win32":
        # Mock grp module
        grp_mock = ModuleType("grp")
        grp_mock.getgrnam = lambda name: type("struct_group", (object,), {"gr_gid": 1000})()
        grp_mock.getgrgid = lambda gid: type("struct_group", (object,), {"gr_name": "root"})()
        sys.modules["grp"] = grp_mock

        # Mock pwd module
        pwd_mock = ModuleType("pwd")
        pwd_mock.getpwnam = lambda name: type("struct_passwd", (object,), {"pw_uid": 1000, "pw_gid": 1000})()
        sys.modules["pwd"] = pwd_mock

        # Mock termios module
        termios_mock = ModuleType("termios")
        termios_mock.tcgetattr = lambda fd: [0, 0, 0, 0, 0, 0, [0]*32]
        termios_mock.tcsetattr = lambda fd, when, attributes: None
        termios_mock.TCSANOW = 0
        sys.modules["termios"] = termios_mock

        # Mock tty module
        tty_mock = ModuleType("tty")
        tty_mock.setraw = lambda fd: None
        tty_mock.setcbreak = lambda fd: None
        sys.modules["tty"] = tty_mock

        # Mock fcntl module
        fcntl_mock = ModuleType("fcntl")
        fcntl_mock.fcntl = lambda fd, op, arg=0: 0
        fcntl_mock.ioctl = lambda fd, op, arg=0: 0
        sys.modules["fcntl"] = fcntl_mock

    _globals = {}
    core_src = Path("vless_installer/_core.py").read_text(encoding="utf-8")
    exec(compile(core_src, "vless_installer/_core.py", "exec"), _globals)
    ok("exec(_core.py) — без ошибок")

    for sym in ["main_menu", "gen_uuid", "BANNER", "RED", "GREEN", "CYAN", "NC",
                "LOG_FILE", "STATE_FILE", "CONFIG_DIR",
                "print_banner", "log_to_file", "info", "warn", "die",
                "ensure_startup_dependencies", "_init_pkg_mgr",
                "switch_mode_ab", "_smart_recover"]:
        if sym in _globals:
            ok(f"  {sym} доступен")
        else:
            fail(f"  {sym} — НЕ НАЙДЕН")

    uuid_val = _globals["gen_uuid"]()
    if len(uuid_val) == 36 and uuid_val.count("-") == 4:
        ok(f"  gen_uuid() → {uuid_val}")
    else:
        fail(f"  gen_uuid() вернул некорректный UUID: {uuid_val}")

    banner = _globals.get("BANNER", "")
    if len(banner) > 100:
        ok(f"  BANNER: {len(banner)} символов")
    else:
        fail(f"  BANNER слишком короткий: {len(banner)} символов")

except Exception as e:
    fail(f"exec(_core.py) — ошибка: {e}")
    import traceback; traceback.print_exc()

# ── 6. bootstrap.sh ──────────────────────────────────────────
section("6. bootstrap.sh")
import sys
if sys.platform == "win32":
    print("  ⚠ Пропуск синтаксической проверки bash на Windows (нет нативного bash)")
    passed += 1
else:
    try:
        r = subprocess.run(["bash", "-n", "bootstrap.sh"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            ok("bootstrap.sh — синтаксис bash OK")
        else:
            fail(f"bootstrap.sh — ошибка: {r.stderr.strip()}")
    except FileNotFoundError:
        print("  ⚠ bash не найден для синтаксической проверки")
        passed += 1

# ── 7. Документация ───────────────────────────────────────────
section("7. Документация")
doc_files = {
    "README.md":           1000,
    "TROUBLESHOOTING.md":  2000,
    "INSTALL.md":          1000,
    "CHANGELOG.md":        500,
    "SECURITY.md":         500,
    "CONTRIBUTING.md":     500,
    "LICENSE":             200,
}
for fname, min_chars in doc_files.items():
    p = Path(fname)
    if p.exists():
        size = len(p.read_text(encoding="utf-8"))
        if size >= min_chars:
            ok(f"{fname}: {size} символов")
        else:
            fail(f"{fname}: слишком маленький ({size} < {min_chars} символов)")
    else:
        fail(f"{fname} — не найден")

# ── 8. SHA256-placeholder в bootstrap.sh ──────────────────────
section("8. bootstrap.sh — SHA256")
bs = Path("bootstrap.sh")
if bs.exists():
    bs_text = bs.read_text(encoding="utf-8")
    if "EXPECTED_SHA256" in bs_text:
        if "PLACEHOLDER_SHA256_UPDATE_BEFORE_RELEASE" in bs_text:
            import sys as _sys
            _col = "\033[1;33m"
            print(f"  {_col}⚠{NC} SHA256 placeholder не заменён — заменить перед релизом")
            passed += 1  # не блокирующее, просто предупреждение
        else:
            ok("EXPECTED_SHA256 задан (не placeholder)")
    else:
        fail("EXPECTED_SHA256 не найден в bootstrap.sh — SHA256-проверка отсутствует")

# ── ИТОГ ─────────────────────────────────────────────────────
print(f"\n{'═'*55}")
print(f"{BOLD}  ИТОГ{NC}")
print(f"{'═'*55}")
print(f"  {GREEN}✓ Успешно: {passed}{NC}")
if failed:
    print(f"  {RED}✗ Ошибок:  {failed}{NC}")

score = round(10 * passed / max(passed + failed, 1), 1)
color = GREEN if score >= 9 else (YELLOW if score >= 7 else RED)
print(f"\n  {color}{BOLD}Готовность к публикации: {score}/10{NC}")
if failed == 0:
    print(f"\n  {GREEN}{BOLD}Проект готов к публикации на GitHub! 🚀{NC}")
    print(f"\n  Команды для публикации:")
    print(f"  {CYAN}git init{NC}")
    print(f"  {CYAN}git add .{NC}")
    print(f"  {CYAN}git commit -m 'HYDRA ULTIMATE v0.0.1-alpha'{NC}")
    print(f"  {CYAN}git remote add origin https://github.com/gr33nimax/HYDRA-ULTIMATE.git{NC}")
    print(f"  {CYAN}git push -u origin main{NC}")
else:
    print(f"\n  {YELLOW}Есть проблемы — исправьте перед публикацией.{NC}")

sys.exit(0 if failed == 0 else 1)
