"""
hydra/plugins/warp/plugin.py — Cloudflare WARP.

WARP обеспечивает выборочный исходящий трафик через сеть Cloudflare.
Реализован как WireGuard outbound в Sing-Box с route-правилами.

Архитектура:
  Inbound → Sing-Box routing (селективные домены / IP) → WARP outbound → Cloudflare → интернет
  Всё остальное → direct
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState

WGCF_BIN = Path("/usr/local/bin/wgcf")
WGCF_PROFILE = Path("/etc/wireguard/wgcf-profile.conf")
WARP_INTERFACE = "wgcf"
WARP_EXTERNAL_CACHE = Path("/var/lib/hydra/warp_external.json")

DEFAULT_WARP_DOMAINS = [
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "chatgpt.com",
    "sora.com",
    "gemini.google.com",
    "bard.google.com",
]


class WarpPlugin(BasePlugin):
    meta = PluginMeta(
        name="warp",
        description="Cloudflare WARP: выборочное туннелирование через сеть Cloudflare",
        category=PluginCategory.ENHANCEMENT,
        version="2.1.0",
    )

    def install(self) -> bool:
        if WGCF_PROFILE.exists() and WGCF_BIN.exists():
            return True

        from hydra.utils.net import detect_arch
        from hydra.utils.downloader import download_github_asset_filtered

        # Путь для логов отладки
        log_path = Path("/var/log/hydra/warp_install.log")
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            WGCF_PROFILE.parent.mkdir(parents=True, exist_ok=True)

            # Скачиваем wgcf напрямую через GitHub API, если его нет
            if not WGCF_BIN.exists():
                arch = detect_arch()
                def _match(name: str) -> bool:
                    return f"linux_{arch}" in name and not name.endswith(".sha256")
                
                WGCF_BIN.parent.mkdir(parents=True, exist_ok=True)
                ok = download_github_asset_filtered("ViRb3/wgcf", _match, WGCF_BIN)
                if not ok:
                    log_path.write_text("Failed to download wgcf binary from GitHub.\n", encoding="utf-8")
                    return False
                WGCF_BIN.chmod(0o755)

            # Регистрация
            account_toml = WGCF_PROFILE.parent / "wgcf-account.toml"
            if not account_toml.exists():
                r = subprocess.run(
                    [str(WGCF_BIN), "register", "--accept-tos"],
                    capture_output=True, text=True, timeout=30,
                    cwd=str(WGCF_PROFILE.parent)
                )
                if r.returncode != 0:
                    log_path.write_text(
                        f"wgcf register failed with code {r.returncode}\n"
                        f"Stdout: {r.stdout}\nStderr: {r.stderr}\n",
                        encoding="utf-8"
                    )

            # Генерация профиля
            r = subprocess.run(
                [str(WGCF_BIN), "generate"],
                capture_output=True, text=True, timeout=30,
                cwd=str(WGCF_PROFILE.parent)
            )
            if r.returncode != 0:
                with log_path.open("a", encoding="utf-8") as lf:
                    lf.write(
                        f"wgcf generate failed with code {r.returncode}\n"
                        f"Stdout: {r.stdout}\nStderr: {r.stderr}\n"
                    )

            return WGCF_PROFILE.exists()
        except Exception as e:
            try:
                log_path.write_text(f"Installation exception: {e}\n", encoding="utf-8")
            except Exception:
                pass
            return False

    def uninstall(self) -> bool:
        if WGCF_PROFILE.exists():
            WGCF_PROFILE.unlink()
        if WGCF_BIN.exists():
            WGCF_BIN.unlink()
        
        # Удаляем локальные и системные файлы учетных записей wgcf
        Path("/etc/wireguard/wgcf-account.toml").unlink(missing_ok=True)
        Path("wgcf-account.toml").unlink(missing_ok=True)
        Path("wgcf-profile.conf").unlink(missing_ok=True)
        try:
            WARP_EXTERNAL_CACHE.unlink(missing_ok=True)
        except Exception:
            pass
        return True

    def _load_warp_config(self) -> dict | None:
        """Извлекает ключи из wgcf-профиля."""
        if not WGCF_PROFILE.exists():
            return None

        try:
            text = WGCF_PROFILE.read_text(encoding="utf-8")
        except Exception:
            return None

        private = re.search(r"PrivateKey\s*=\s*(\S+)", text)
        if not private:
            return None

        # Надежно парсим Address (может быть как IPv4, так и IPv6 через запятую)
        address_match = re.search(r"Address\s*=\s*(.+)", text)
        addresses = []
        if address_match:
            raw_addr = address_match.group(1)
            # Разделяем по запятым, убираем пробелы и лишние знаки препинания
            for addr in raw_addr.split(","):
                addr = addr.strip()
                if addr:
                    addresses.append(addr)
        
        if not addresses:
            addresses = ["172.16.0.2/32"]

        return {
            "private_key": private.group(1),
            "addresses": addresses,
        }

    def configure(self, state: AppState) -> ConfigFragment:
        """Генерирует Sing-Box outbound для WARP и route-правила."""
        warp_cfg = self._load_warp_config()
        if not warp_cfg:
            return ConfigFragment()

        # Sing-Box требует IP-адрес в качестве `server` (домены не поддерживаются напрямую)
        try:
            server_ip = socket.gethostbyname("engage.cloudflareclient.com")
        except Exception:
            server_ip = "162.159.192.1"

        # WARP outbound (используем стандартную структуру peers для совместимости с новыми версиями Sing-Box)
        outbound = {
            "type": "wireguard",
            "tag": "warp",
            "local_address": warp_cfg["addresses"],
            "private_key": warp_cfg["private_key"],
            "mtu": 1280,
            "peers": [
                {
                    "server": server_ip,
                    "server_port": 2408,
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "allowed_ips": ["0.0.0.0/0", "::/0"]
                }
            ]
        }

        # Получаем списки доменов и IP из конфига плагина
        ps = state.protocols.get("warp")
        if ps:
            # Инициализация дефолтами, если ключи отсутствуют
            if "domains" not in ps.config:
                ps.config["domains"] = DEFAULT_WARP_DOMAINS.copy()
            if "ips" not in ps.config:
                ps.config["ips"] = []
            
            domains = ps.config.get("domains", [])
            ips = ps.config.get("ips", [])
        else:
            domains = DEFAULT_WARP_DOMAINS.copy()
            ips = []

        # Загружаем правила из кэша внешнего источника
        ext_domains = []
        ext_ips = []
        if WARP_EXTERNAL_CACHE.exists():
            try:
                ext_data = json.loads(WARP_EXTERNAL_CACHE.read_text(encoding="utf-8"))
                ext_domains = ext_data.get("domains", [])
                ext_ips = ext_data.get("ips", [])
            except Exception:
                pass

        all_domains = list(set(domains + ext_domains))
        all_ips = list(set(ips + ext_ips))

        # Генерируем route_rules для Sing-Box
        rules = []
        if all_domains:
            clean_domains = [d.strip() for d in all_domains if d.strip()]
            if clean_domains:
                rules.append({
                    "domain": clean_domains,
                    "outbound": "warp",
                })
        if all_ips:
            clean_ips = [ip.strip() for ip in all_ips if ip.strip()]
            if clean_ips:
                rules.append({
                    "ip_cidr": clean_ips,
                    "outbound": "warp",
                })

        # Если нет ни одного правила маршрутизации, не отдаем outbound/правила,
        # чтобы зря не занимать ресурсы и не перезаписывать пустые правила
        if not rules:
            return ConfigFragment()

        return ConfigFragment(
            outbounds=[outbound],
            route_rules=rules,
        )

    def status(self) -> PluginStatus:
        from hydra.core.singbox import is_running as sb_running
        from hydra.core.state import load_state

        installed = WGCF_PROFILE.exists()
        enabled = False
        running = False
        
        try:
            state = load_state()
            ps = state.protocols.get("warp")
            if ps:
                enabled = ps.enabled
                running = enabled and sb_running()
        except Exception:
            pass

        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=running,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        state.network.warp_enabled = True

    def on_disable(self, state: AppState) -> None:
        state.network.warp_enabled = False

    @staticmethod
    def _is_ip_or_cidr(token: str) -> bool:
        import ipaddress
        try:
            if "/" in token:
                ipaddress.ip_network(token, strict=False)
            else:
                ipaddress.ip_address(token)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_domain(token: str) -> bool:
        if not token or len(token) > 253:
            return False
        # Разрешаем опциональную начальную точку для wildcard-доменов в Sing-Box (например: .google.com)
        pattern = r"^\.?[a-zA-Z0-9][-a-zA-Z0-9._]*\.[a-zA-Z]{2,24}$"
        if not re.match(pattern, token):
            return False
        return True

    def update_external_rules(self) -> tuple[bool, str]:
        """Загружает правила из внешнего источника и сохраняет их в кэш."""
        from hydra.core.state import load_state
        state = load_state()
        ps = state.protocols.get("warp")
        if not ps:
            return False, "Плагин не настроен в state.json"
        
        url = ps.config.get("external_url")
        if not url:
            if WARP_EXTERNAL_CACHE.exists():
                try:
                    WARP_EXTERNAL_CACHE.unlink()
                except Exception:
                    pass
            return True, "Внешний URL не задан"

        import urllib.request
        try:
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode("utf-8", errors="replace")
        except Exception as e:
            return False, f"Ошибка скачивания: {e}"

        domains = []
        ips = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
                continue
            parts = line.split()
            if not parts:
                continue
            for token in parts:
                token = token.strip()
                if self._is_ip_or_cidr(token):
                    ips.append(token)
                elif self._is_valid_domain(token):
                    domains.append(token)

        try:
            WARP_EXTERNAL_CACHE.parent.mkdir(parents=True, exist_ok=True)
            WARP_EXTERNAL_CACHE.write_text(json.dumps({
                "domains": domains,
                "ips": ips,
                "updated_at": __import__("datetime").datetime.now().isoformat()
            }, indent=2, ensure_ascii=False), encoding="utf-8")
            return True, f"Успешно загружено: {len(domains)} доменов, {len(ips)} IP/подсетей"
        except Exception as e:
            return False, f"Ошибка сохранения кэша: {e}"
