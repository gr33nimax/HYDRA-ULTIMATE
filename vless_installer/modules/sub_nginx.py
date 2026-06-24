"""
vless_installer/modules/sub_nginx.py
───────────────────────────────────────────────────────────────────────────────
Интеграция сервера подписок с nginx.

Инжектирует location /sub/ в существующий nginx server-блок,
проксируя запросы на локальный HTTP-сервер подписок.

Точка входа:
    from vless_installer.modules.sub_nginx import (
        inject_sub_location, remove_sub_location, check_sub_location
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

# ── Маркеры ───────────────────────────────────────────────────────────────────
START_MARKER = "# --- VLESS-SUB-START ---"
END_MARKER   = "# --- VLESS-SUB-END ---"

# Стандартные пути к nginx-конфигам
NGINX_CONF_CANDIDATES = [
    Path("/etc/nginx/sites-enabled/default"),
    Path("/etc/nginx/conf.d/default.conf"),
    Path("/etc/nginx/conf.d/vless.conf"),
    Path("/etc/nginx/sites-enabled/vless"),
]

DEFAULT_SUB_PORT = 9443


def _find_nginx_conf() -> Path | None:
    """Найти основной конфиг nginx."""
    candidates = list(NGINX_CONF_CANDIDATES)
    
    # Пытаемся получить домен из state.json
    state_file = Path("/var/lib/xray-installer/state.json")
    if state_file.exists():
        try:
            import json
            state = json.loads(state_file.read_text(encoding="utf-8"))
            domain = state.get("domain")
            if domain:
                # Вставляем доменные конфиги в начало списка
                candidates.insert(0, Path(f"/etc/nginx/sites-enabled/{domain}"))
                candidates.insert(1, Path(f"/etc/nginx/sites-available/{domain}"))
        except Exception:
            pass

    for p in candidates:
        if p.exists():
            return p
            
    # Попробуем найти через nginx -T
    try:
        r = subprocess.run(["nginx", "-T"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            m = re.match(r'# configuration file (/etc/nginx/\S+\.conf):', line)
            if m:
                p = Path(m.group(1))
                if p.exists() and p.name != "nginx.conf":
                    return p
    except Exception:
        pass
    return None


def generate_location_block(port: int = DEFAULT_SUB_PORT) -> str:
    """Сгенерировать nginx location-блок для подписок."""
    return f"""
    {START_MARKER}
    location /sub/ {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 30s;
    }}
    {END_MARKER}
"""


def check_sub_location(nginx_conf_path: str | Path | None = None) -> bool:
    """Проверить, уже ли инжектирован location /sub/."""
    conf = Path(nginx_conf_path) if nginx_conf_path else _find_nginx_conf()
    if not conf or not conf.exists():
        return False
    content = conf.read_text(encoding="utf-8", errors="replace")
    return START_MARKER in content


def find_active_server_brace(content: str) -> int:
    """Находит индекс закрывающей фигурной скобки активного (незакомментированного) server-блока."""
    clean_lines = []
    for line in content.splitlines(keepends=True):
        if "#" in line:
            idx = line.index("#")
            clean_lines.append(line[:idx] + " " * (len(line) - idx))
        else:
            clean_lines.append(line)
    clean_content = "".join(clean_lines)

    server_matches = list(re.finditer(r'\bserver\s*\{', clean_content))
    if not server_matches:
        return -1

    # Ищем с последнего server-блока к первому
    for last_server in reversed(server_matches):
        start_idx = last_server.end()
        depth = 1
        for i in range(start_idx, len(clean_content)):
            char = clean_content[i]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return i
    return -1


def _cleanup_stale_backups() -> None:
    """Удаляет старые бэкап-файлы из папок конфигурации nginx, которые могут вызывать дублирование."""
    for folder in ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d"):
        p = Path(folder)
        if p.exists():
            for f in p.glob("*.sub.bak"):
                try:
                    f.unlink()
                    print(f"\033[1;33m[WARN]\033[0m  Удален конфликтный бэкап: {f}")
                except Exception:
                    pass


def inject_sub_location(nginx_conf_path: str | Path | None = None,
                        port: int = DEFAULT_SUB_PORT) -> bool:
    """Инжектировать location /sub/ в nginx-конфиг.

    Вставляет блок внутрь первого server { } перед последней закрывающей }.
    """
    # Удаляем старые конфликтующие бэкапы, если они есть
    _cleanup_stale_backups()

    conf = Path(nginx_conf_path) if nginx_conf_path else _find_nginx_conf()
    if not conf:
        print("\033[0;31m[ERR]\033[0m   Не найден nginx-конфиг")
        return False

    content = conf.read_text(encoding="utf-8", errors="replace")

    # Уже есть?
    if START_MARKER in content:
        print("\033[1;33m[WARN]\033[0m  location /sub/ уже добавлен")
        return True

    location_block = generate_location_block(port)

    # Находим закрывающую скобку активного server-блока
    server_brace = find_active_server_brace(content)
    if server_brace == -1:
        # Резервный вариант, если не смогли распарсить структуру скобок
        server_brace = content.rfind("}")

    if server_brace == -1:
        print("\033[0;31m[ERR]\033[0m   Не удалось найти server-блок в nginx-конфиге")
        return False

    new_content = content[:server_brace] + location_block + "\n" + content[server_brace:]

    # Бэкап + запись (бэкапим в /tmp во избежание duplicate default server в nginx)
    backup = Path(f"/tmp/{conf.name}.sub.bak")
    if backup.exists():
        backup.unlink()
    conf.rename(backup)
    conf.write_text(new_content, encoding="utf-8")

    # Проверяем конфиг
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if r.returncode != 0:
        # Откатываем
        conf.unlink()
        backup.rename(conf)
        print(f"\033[0;31m[ERR]\033[0m   nginx -t failed:\n{r.stderr}")
        return False

    # Перезагружаем nginx
    subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
    print(f"\033[0;32m[OK]\033[0m    location /sub/ добавлен в {conf}")
    return True


def remove_sub_location(nginx_conf_path: str | Path | None = None) -> bool:
    """Удалить инжектированный location /sub/ из nginx-конфига."""
    # Удаляем старые конфликтующие бэкапы, если они есть
    _cleanup_stale_backups()

    conf = Path(nginx_conf_path) if nginx_conf_path else _find_nginx_conf()
    if not conf or not conf.exists():
        print("\033[0;31m[ERR]\033[0m   Не найден nginx-конфиг")
        return False

    content = conf.read_text(encoding="utf-8", errors="replace")
    if START_MARKER not in content:
        print("\033[1;33m[WARN]\033[0m  location /sub/ не найден в конфиге")
        return True

    # Удаляем всё между маркерами (включительно)
    pattern = re.compile(
        rf'\n?\s*{re.escape(START_MARKER)}.*?{re.escape(END_MARKER)}\s*\n?',
        re.DOTALL,
    )
    new_content = pattern.sub("\n", content)

    # Бэкап + запись (бэкапим в /tmp во избежание duplicate default server в nginx)
    backup = Path(f"/tmp/{conf.name}.sub.bak")
    if backup.exists():
        backup.unlink()
    conf.rename(backup)
    conf.write_text(new_content, encoding="utf-8")

    # Проверяем
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if r.returncode != 0:
        conf.unlink()
        backup.rename(conf)
        print(f"\033[0;31m[ERR]\033[0m   nginx -t failed после удаления:\n{r.stderr}")
        return False

    subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
    print(f"\033[0;32m[OK]\033[0m    location /sub/ удалён из {conf}")
    return True
