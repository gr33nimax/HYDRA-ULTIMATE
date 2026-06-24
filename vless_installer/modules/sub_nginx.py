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
    for p in NGINX_CONF_CANDIDATES:
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


def inject_sub_location(nginx_conf_path: str | Path | None = None,
                        port: int = DEFAULT_SUB_PORT) -> bool:
    """Инжектировать location /sub/ в nginx-конфиг.

    Вставляет блок внутрь первого server { } перед последней закрывающей }.
    """
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

    # Ищем последнюю `}` от server-блока и вставляем перед ней
    # Стратегия: находим последний `}` в файле
    last_brace = content.rfind("}")
    if last_brace == -1:
        print("\033[0;31m[ERR]\033[0m   Не удалось найти server-блок в nginx-конфиге")
        return False

    new_content = content[:last_brace] + location_block + "\n" + content[last_brace:]

    # Бэкап + запись
    backup = conf.with_suffix(conf.suffix + ".sub.bak")
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

    backup = conf.with_suffix(conf.suffix + ".sub.bak")
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
