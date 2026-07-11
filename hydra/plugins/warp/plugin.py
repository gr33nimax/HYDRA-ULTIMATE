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
from hydra.core.state import AppState, PluginState

WGCF_BIN = Path("/usr/local/bin/wgcf")
WGCF_PROFILE = Path("/etc/wireguard/wgcf-profile.conf")
WARP_INTERFACE = "wgcf"
WARP_EXTERNAL_CACHE = Path("/var/lib/hydra/warp_external.json")
WARP_PROFILES_DIR = Path("/etc/hydra/warp_profiles")

DEFAULT_WARP_DOMAINS = [
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "chatgpt.com",
    "sora.com",
    "gemini.google.com",
    "bard.google.com",
]

EXTERNAL_LISTS = {
    "russia": {
        "name": "РФ-сервисы",
        "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-raw.lst",
        "desc": "Российские сервисы, доступные только с IP-адресов РФ (outside-raw.lst)"
    },
    "geoblock": {
        "name": "GEO-block",
        "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst",
        "desc": "Заблокированные в РФ иностранные ресурсы (geoblock.lst)"
    },
    "google_ai": {
        "name": "GoogleAI",
        "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/google_ai.lst",
        "desc": "Сервисы ИИ от Google: Gemini, AI Studio и др. (google_ai.lst)"
    }
}


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

            # Принудительно убиваем любые зависшие процессы wgcf, чтобы избежать Text file busy
            subprocess.run(["pkill", "-9", "wgcf"], capture_output=True)

            # Скачиваем wgcf напрямую через GitHub API, если его нет
            if not WGCF_BIN.exists():
                arch = detect_arch()
                def _match(name: str) -> bool:
                    return f"linux_{arch}" in name and not name.endswith(".sha256")
                
                WGCF_BIN.parent.mkdir(parents=True, exist_ok=True)
                ok = download_github_asset_filtered("ViRb3/wgcf", _match, WGCF_BIN)
                if not ok:
                    # Резервный прямой запуск скачивания (на случай лимитов API)
                    fallback_url = f"https://github.com/ViRb3/wgcf/releases/download/v2.2.31/wgcf_2.2.31_linux_{arch}"
                    log_path.write_text(f"GitHub API query failed. Trying fallback direct download from: {fallback_url}\n", encoding="utf-8")
                    ok = self._download_file(fallback_url, WGCF_BIN)
                    if not ok:
                        log_path.write_text("Failed both GitHub API query and direct download.\n", encoding="utf-8")
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
        subprocess.run(["pkill", "-9", "wgcf"], capture_output=True)
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

    @staticmethod
    def _download_file(url: str, dest: Path) -> bool:
        import urllib.request
        import shutil
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, timeout=60) as response:
                with dest.open("wb") as out_file:
                    shutil.copyfileobj(response, out_file)
            return True
        except Exception:
            return False

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

    def _parse_wg_conf(self, text: str) -> dict | None:
        """Парсит WireGuard / AmneziaWG .conf файл."""
        import re
        result = {"interface": {}, "peer": {}}
        current_section = None
        
        for line in text.splitlines():
            # Очищаем inline комментарии и пробелы
            line = re.sub(r"[#;].*$", "", line).strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].lower()
                continue
            if current_section and "=" in line:
                parts = line.split("=", 1)
                key = parts[0].strip().lower()
                val = parts[1].strip()
                result[current_section][key] = val
                
        if not result["interface"] or not result["peer"]:
            return None
        return result

    def configure(self, state: AppState) -> ConfigFragment:
        """Генерирует Sing-Box outbound/endpoints для WARP и route-правила."""
        WARP_PROFILES_DIR.mkdir(parents=True, exist_ok=True)

        ps = state.protocols.setdefault("warp", state.protocols.get("warp") or PluginState())
        if not ps.config:
            ps.config = {}

        # ── ИНИЦИАЛИЗАЦИЯ ДЕФОЛТНЫХ НАСТРОЕК ──
        if "local_lists" not in ps.config and "list_targets" not in ps.config:
            if "domains" not in ps.config and "ips" not in ps.config:
                local_lists = ps.config.setdefault("local_lists", {})
                local_lists["default"] = {"domains": DEFAULT_WARP_DOMAINS.copy(), "ips": []}
                list_targets = ps.config.setdefault("list_targets", {})
                list_targets["local:default"] = "warp"
                from hydra.core.state import save_state
                save_state(state)

        # ── МИГРАЦИЯ СТАРЫХ НАСТРОЕК ──
        migrated = False
        old_domains = ps.config.pop("domains", None)
        old_ips = ps.config.pop("ips", None)
        if old_domains is not None or old_ips is not None:
            local_lists = ps.config.setdefault("local_lists", {})
            default_list = local_lists.setdefault("default", {"domains": [], "ips": []})
            if old_domains:
                default_list["domains"] = list(set(default_list["domains"] + old_domains))
            if old_ips:
                default_list["ips"] = list(set(default_list["ips"] + old_ips))
            
            list_targets = ps.config.setdefault("list_targets", {})
            list_targets.setdefault("local:default", "warp")
            migrated = True

        enabled_ext = ps.config.pop("enabled_external_lists", None)
        if enabled_ext is not None:
            list_targets = ps.config.setdefault("list_targets", {})
            for ext_key in enabled_ext:
                list_targets.setdefault(f"ext:{ext_key}", "warp")
            migrated = True

        if migrated:
            from hydra.core.state import save_state
            save_state(state)

        # ── ЗАГРУЗКА ТОЧЕК ВЫХОДА (OUTBOUNDS/ENDPOINTS) ──
        endpoints = []
        destinations = set()

        # 1. Кастомные гео-профили из /etc/hydra/warp_profiles/
        custom_profiles = []
        for p_file in sorted(WARP_PROFILES_DIR.glob("*.conf")):
            profile_name = p_file.stem
            try:
                text = p_file.read_text(encoding="utf-8", errors="replace")
                parsed = self._parse_wg_conf(text)
                if parsed:
                    custom_profiles.append((profile_name, parsed))
            except Exception as e:
                from hydra.core.singbox import _log
                _log("ERROR", f"Failed to parse warp profile {p_file}: {e}")

        for profile_name, parsed in custom_profiles:
            raw_endpoint = parsed["peer"].get("endpoint", "")
            if ":" in raw_endpoint:
                host, port_str = raw_endpoint.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 2408
            else:
                host = raw_endpoint
                port = 2408

            try:
                server_ip = socket.gethostbyname(host)
            except Exception:
                server_ip = host

            is_amnezia = any(k in parsed["interface"] for k in ["s1", "s2", "jc", "jmin", "jmax", "h1", "h2", "h3", "h4"])
            
            addresses = []
            for addr in parsed["interface"].get("address", "").split(","):
                addr = addr.strip()
                if addr:
                    if "/" not in addr:
                        addr += "/128" if ":" in addr else "/32"
                    addresses.append(addr)

            if not addresses:
                addresses = ["172.16.0.2/32"]

            tag = f"warp_{profile_name}"
            destinations.add(tag)

            endpoint = {
                "type": "amneziawg" if is_amnezia else "wireguard",
                "tag": tag,
                "address": addresses,
                "private_key": parsed["interface"].get("privatekey", ""),
                "mtu": int(parsed["interface"].get("mtu", 1280)),
                "peers": [
                    {
                        "address": server_ip,
                        "port": port,
                        "public_key": parsed["peer"].get("publickey", ""),
                        "allowed_ips": [ip.strip() for ip in parsed["peer"].get("allowedips", "0.0.0.0/0, ::/0").split(",") if ip.strip()]
                    }
                ]
            }

            if is_amnezia:
                for k in ["s1", "s2", "jc", "jmin", "jmax", "h1", "h2", "h3", "h4"]:
                    if k in parsed["interface"]:
                        try:
                            endpoint[k] = int(parsed["interface"][k])
                        except ValueError:
                            pass

            endpoints.append(endpoint)

        # 2. Стандартный WGCF (если профиль сгенерирован)
        warp_cfg = self._load_warp_config()
        if warp_cfg:
            destinations.add("warp")
            try:
                server_ip = socket.gethostbyname("engage.cloudflareclient.com")
            except Exception:
                server_ip = "162.159.192.1"

            endpoint = {
                "type": "wireguard",
                "tag": "warp",
                "address": warp_cfg["addresses"],
                "private_key": warp_cfg["private_key"],
                "mtu": 1280,
                "peers": [
                    {
                        "address": server_ip,
                        "port": 2408,
                        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        "allowed_ips": ["0.0.0.0/0", "::/0"]
                    }
                ]
            }
            endpoints.append(endpoint)

        # ── СБОРКА ПРАВИЛ МАРШРУТИЗАЦИИ ──
        list_targets = ps.config.get("list_targets", {})
        local_lists = ps.config.get("local_lists", {})

        ext_rules = {}
        if WARP_EXTERNAL_CACHE.exists():
            try:
                ext_rules = json.loads(WARP_EXTERNAL_CACHE.read_text(encoding="utf-8"))
            except Exception:
                pass

        outbound_domains = {}
        outbound_ips = {}

        for list_key, target in list_targets.items():
            if not target or target == "none" or target not in destinations:
                continue

            domains = []
            ips = []

            if list_key.startswith("local:"):
                list_name = list_key.split(":", 1)[1]
                local_list = local_lists.get(list_name, {})
                domains = local_list.get("domains", [])
                ips = local_list.get("ips", [])
            elif list_key.startswith("ext:"):
                list_name = list_key.split(":", 1)[1]
                ext_list = ext_rules.get(list_name, {})
                domains = ext_list.get("domains", [])
                ips = ext_list.get("ips", [])

            if domains:
                outbound_domains.setdefault(target, []).extend(domains)
            if ips:
                outbound_ips.setdefault(target, []).extend(ips)

        rules = []
        for target, domains_list in outbound_domains.items():
            clean_domains = list(set([d.strip() for d in domains_list if d.strip()]))
            if clean_domains:
                rules.append({
                    "domain": clean_domains,
                    "outbound": target,
                })

        for target, ips_list in outbound_ips.items():
            clean_ips = list(set([ip.strip() for ip in ips_list if ip.strip()]))
            if clean_ips:
                rules.append({
                    "ip_cidr": clean_ips,
                    "outbound": target,
                })

        if not rules:
            return ConfigFragment()

        return ConfigFragment(
            outbounds=[],
            endpoints=endpoints,
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
        """Загружает правила из всех включенных внешних источников и сохраняет их в кэш."""
        from hydra.core.state import load_state
        state = load_state()
        ps = state.protocols.get("warp")
        if not ps:
            return False, "Плагин не настроен в state.json"
        
        list_targets = ps.config.get("list_targets", {})
        enabled_keys = []
        for k, target in list_targets.items():
            if k.startswith("ext:") and target and target != "none":
                enabled_keys.append(k.split(":", 1)[1])

        if not enabled_keys:
            if WARP_EXTERNAL_CACHE.exists():
                try:
                    WARP_EXTERNAL_CACHE.unlink()
                except Exception:
                    pass
            return True, "Нет активных внешних списков"

        import urllib.request
        downloaded_lists = {}
        downloaded_count = 0
        errors = []

        for key in enabled_keys:
            if key not in EXTERNAL_LISTS:
                continue
            item = EXTERNAL_LISTS[key]
            url = item["url"]
            domains = []
            ips = []
            try:
                req = urllib.request.Request(
                    url, 
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                )
                with urllib.request.urlopen(req, timeout=30) as response:
                    content = response.read().decode("utf-8", errors="replace")
                
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
                
                downloaded_lists[key] = {
                    "domains": list(set(domains)),
                    "ips": list(set(ips))
                }
                downloaded_count += 1
            except Exception as e:
                errors.append(f"{item['name']}: {e}")

        if not downloaded_lists:
            status_msg = f"Ошибка обновления списков."
            if errors:
                status_msg += f" Ошибки: {'; '.join(errors)}"
            return False, status_msg

        try:
            existing = {}
            if WARP_EXTERNAL_CACHE.exists():
                try:
                    existing = json.loads(WARP_EXTERNAL_CACHE.read_text(encoding="utf-8"))
                    if "domains" in existing and not isinstance(existing["domains"], dict):
                        existing = {}
                except Exception:
                    pass

            for key in downloaded_lists:
                existing[key] = downloaded_lists[key]

            # Удаляем из кэша списки, которые больше не активны
            keys_to_delete = [k for k in existing if k != "updated_at" and k not in enabled_keys]
            for k in keys_to_delete:
                existing.pop(k, None)

            existing["updated_at"] = __import__("datetime").datetime.now().isoformat()

            WARP_EXTERNAL_CACHE.parent.mkdir(parents=True, exist_ok=True)
            WARP_EXTERNAL_CACHE.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
            
            status_msg = f"Обновлено списков: {downloaded_count}/{len(enabled_keys)}."
            if errors:
                status_msg += f" Ошибки: {'; '.join(errors)}"
            
            return len(errors) == 0, status_msg
        except Exception as e:
            return False, f"Ошибка сохранения кэша: {e}"
