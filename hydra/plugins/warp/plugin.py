"""
hydra/plugins/warp/plugin.py — Cloudflare WARP.

WARP обеспечивает выборочный исходящий трафик через сеть Cloudflare.
Реализован как WireGuard outbound в Sing-Box с route-правилами.

Архитектура:
  Inbound → Sing-Box routing (селективные домены / IP) → WARP outbound → Cloudflare → интернет
  Всё остальное → direct
"""
from __future__ import annotations

from hydra.core.host import HOST

import json
import re
import socket
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, PluginState

WGCF_BIN = Path("/usr/local/bin/wgcf")
WGCF_PROFILE = Path("/etc/wireguard/wgcf-profile.conf")
WGCF_ACCOUNT = Path("/etc/wireguard/wgcf-account.toml")
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
            HOST.run(["pkill", "-9", "wgcf"], capture_output=True)

            # Скачиваем wgcf напрямую через GitHub API, если его нет
            if not WGCF_BIN.exists():
                arch = detect_arch()
                def _match(name: str) -> bool:
                    return f"linux_{arch}" in name and not name.endswith(".sha256")
                
                WGCF_BIN.parent.mkdir(parents=True, exist_ok=True)
                ok = download_github_asset_filtered("ViRb3/wgcf", _match, WGCF_BIN)
                if not ok:
                    log_path.write_text(
                        "Failed to download a verified wgcf release asset.\n",
                        encoding="utf-8",
                    )
                    return False
                from hydra.utils.downloader import verify_elf
                if not verify_elf(WGCF_BIN):
                    WGCF_BIN.unlink(missing_ok=True)
                    log_path.write_text("Downloaded wgcf asset is not an ELF binary.\n", encoding="utf-8")
                    return False
                WGCF_BIN.chmod(0o755)

            # Регистрация
            account_toml = WGCF_ACCOUNT
            if not account_toml.exists():
                r = HOST.run(
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
                    return False

            # Генерация профиля
            r = HOST.run(
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
                return False

            return WGCF_PROFILE.exists()
        except Exception as e:
            try:
                log_path.write_text(f"Installation exception: {e}\n", encoding="utf-8")
            except Exception:
                pass
            return False

    def uninstall(self) -> bool:
        HOST.run(["pkill", "-9", "wgcf"], capture_output=True)
        self.remove_local_profile()
        if WGCF_BIN.exists():
            WGCF_BIN.unlink()
        try:
            WARP_EXTERNAL_CACHE.unlink(missing_ok=True)
        except Exception:
            pass
        return True

    @staticmethod
    def remove_local_profile() -> None:
        """Remove WGCF credentials without touching relay profiles or rule cache."""
        WGCF_PROFILE.unlink(missing_ok=True)
        WGCF_ACCOUNT.unlink(missing_ok=True)

    @staticmethod
    def snapshot_local_profile() -> tuple[bytes | None, bytes | None]:
        """Capture WGCF credentials so a failed runtime apply can be rolled back."""
        profile = WGCF_PROFILE.read_bytes() if WGCF_PROFILE.exists() else None
        account = WGCF_ACCOUNT.read_bytes() if WGCF_ACCOUNT.exists() else None
        return profile, account

    @staticmethod
    def restore_local_profile(snapshot: tuple[bytes | None, bytes | None]) -> None:
        """Restore an earlier WGCF credential pair."""
        profile, account = snapshot
        WGCF_PROFILE.unlink(missing_ok=True)
        WGCF_ACCOUNT.unlink(missing_ok=True)
        if profile is not None:
            HOST.atomic_write(WGCF_PROFILE, profile, mode=0o600)
        if account is not None:
            HOST.atomic_write(WGCF_ACCOUNT, account, mode=0o600)

    def recreate_local_profile(self) -> bool:
        """Regenerate WGCF credentials and restore the old pair on failure."""
        snapshot = self.snapshot_local_profile()
        self.remove_local_profile()
        if self.install():
            return True
        self.remove_local_profile()
        self.restore_local_profile(snapshot)
        return False

    def _load_warp_config(self) -> dict | None:
        """Извлекает ключи из wgcf-профиля."""
        if not WGCF_PROFILE.exists():
            return None

        try:
            text = WGCF_PROFILE.read_text(encoding="utf-8")
        except Exception:
            return None

        parsed = self._parse_wg_conf(text)
        if parsed is None:
            return None
        addresses = []
        for addr in parsed["interface"]["address"].split(","):
            addr = addr.strip()
            if addr and self._is_ip_or_cidr(addr):
                if "/" not in addr:
                    addr += "/128" if ":" in addr else "/32"
                addresses.append(addr)
        
        if not addresses:
            return None

        return {
            "private_key": parsed["interface"]["privatekey"],
            "addresses": addresses,
            "endpoint": parsed["peer"]["endpoint"],
            "public_key": parsed["peer"]["publickey"],
            "allowed_ips": [
                value.strip()
                for value in parsed["peer"].get("allowedips", "0.0.0.0/0, ::/0").split(",")
                if self._is_ip_or_cidr(value.strip())
            ],
            "mtu": parsed["interface"].get("mtu", "1280"),
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
            if current_section in result and "=" in line:
                parts = line.split("=", 1)
                key = parts[0].strip().lower()
                val = parts[1].strip()
                # wg-quick permits Address and AllowedIPs to occur more than
                # once. wgcf commonly emits separate IPv4 and IPv6 lines.
                if key in {"address", "allowedips"} and result[current_section].get(key):
                    result[current_section][key] += f", {val}"
                else:
                    result[current_section][key] = val
                
        required_interface = {"privatekey", "address"}
        required_peer = {"publickey", "endpoint"}
        if not all(result["interface"].get(key) for key in required_interface):
            return None
        if not all(result["peer"].get(key) for key in required_peer):
            return None
        return result

    @staticmethod
    def _parse_endpoint(raw_endpoint: str) -> tuple[str, int] | None:
        """Parse WireGuard host:port, including bracketed IPv6 addresses."""
        value = raw_endpoint.strip()
        if value.startswith("["):
            match = re.fullmatch(r"\[([^]]+)]:(\d+)", value)
            if not match:
                return None
            host, port_text = match.groups()
        else:
            if ":" not in value:
                return None
            host, port_text = value.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            return None
        if not host or not 1 <= port <= 65535:
            return None
        return host, port

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
        outbounds = []
        destinations = {"direct"}

        # 1. Кастомные гео-профили из /etc/hydra/warp_profiles/
        custom_profiles = []
        for p_file in sorted(WARP_PROFILES_DIR.glob("*.conf")):
            profile_name = p_file.stem
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", profile_name):
                continue
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
            endpoint_target = self._parse_endpoint(raw_endpoint)
            if endpoint_target is None:
                continue
            host, port = endpoint_target

            try:
                server_ip = socket.gethostbyname(host)
            except Exception:
                server_ip = host

            is_amnezia = any(k in parsed["interface"] for k in ["s1", "s2", "jc", "jmin", "jmax", "h1", "h2", "h3", "h4"])
            
            addresses = []
            for addr in parsed["interface"].get("address", "").split(","):
                addr = addr.strip()
                if addr and self._is_ip_or_cidr(addr):
                    if "/" not in addr:
                        addr += "/128" if ":" in addr else "/32"
                    addresses.append(addr)

            if not addresses:
                continue

            try:
                mtu = int(parsed["interface"].get("mtu", 1280))
            except ValueError:
                continue
            if not 576 <= mtu <= 65535:
                continue

            tag = f"warp_{profile_name}"
            ep_tag = f"{tag}_ep"
            destinations.add(tag)

            allowed_ips = [
                ip.strip()
                for ip in parsed["peer"].get("allowedips", "0.0.0.0/0, ::/0").split(",")
                if self._is_ip_or_cidr(ip.strip())
            ]
            if not allowed_ips:
                continue

            endpoint = {
                "type": "wireguard",
                "tag": ep_tag,
                "address": addresses,
                "private_key": parsed["interface"].get("privatekey", ""),
                "mtu": mtu,
                "peers": [
                    {
                        "address": server_ip,
                        "port": port,
                        "public_key": parsed["peer"].get("publickey", ""),
                        "allowed_ips": allowed_ips,
                    }
                ]
            }

            if is_amnezia:
                amnezia_params = {}
                for k in ["s1", "s2", "s3", "s4", "jc", "jmin", "jmax", "h1", "h2", "h3", "h4"]:
                    if k in parsed["interface"]:
                        try:
                            amnezia_params[k] = int(parsed["interface"][k])
                        except ValueError:
                            pass
                for k in ["i1", "i2", "i3", "i4", "i5"]:
                    if k in parsed["interface"]:
                        val = parsed["interface"][k].strip()
                        if val:
                            amnezia_params[k] = val
                if amnezia_params:
                    endpoint["amnezia"] = amnezia_params

            endpoints.append(endpoint)
            outbounds.append({
                "type": "selector",
                "tag": tag,
                "outbounds": [ep_tag]
            })

        # 2. Стандартный WGCF (если профиль сгенерирован)
        warp_cfg = self._load_warp_config()
        if warp_cfg:
            endpoint_target = self._parse_endpoint(
                warp_cfg.get("endpoint", "engage.cloudflareclient.com:2408")
            )
            try:
                mtu = int(warp_cfg.get("mtu", 1280))
            except (TypeError, ValueError):
                mtu = 1280
            allowed_ips = warp_cfg.get("allowed_ips") or ["0.0.0.0/0", "::/0"]
            if endpoint_target is None or not 576 <= mtu <= 65535:
                endpoint_target = None

        if warp_cfg and endpoint_target is not None:
            destinations.add("warp")
            ep_tag = "warp_ep"
            host, port = endpoint_target
            try:
                server_ip = socket.gethostbyname(host)
            except Exception:
                server_ip = host

            endpoint = {
                "type": "wireguard",
                "tag": ep_tag,
                "address": warp_cfg["addresses"],
                "private_key": warp_cfg["private_key"],
                "mtu": mtu,
                "peers": [
                    {
                        "address": server_ip,
                        "port": port,
                        "public_key": warp_cfg.get(
                            "public_key",
                            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        ),
                        "allowed_ips": allowed_ips,
                    }
                ]
            }
            endpoints.append(endpoint)
            outbounds.append({
                "type": "selector",
                "tag": "warp",
                "outbounds": [ep_tag]
            })

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
            clean_domains = sorted({
                d.strip().lower()
                for d in domains_list
                if isinstance(d, str) and self._is_valid_domain(d.strip())
            })
            if clean_domains:
                rules.append({
                    "domain_suffix": clean_domains,
                    "outbound": target,
                })

        for target, ips_list in outbound_ips.items():
            clean_ips = sorted({
                ip.strip()
                for ip in ips_list
                if isinstance(ip, str) and self._is_ip_or_cidr(ip.strip())
            })
            if clean_ips:
                rules.append({
                    "ip_cidr": clean_ips,
                    "outbound": target,
                })

        if not rules:
            return ConfigFragment()

        return ConfigFragment(
            outbounds=outbounds,
            endpoints=endpoints,
            route_rules=rules,
        )

    def status(self) -> PluginStatus:
        from hydra.core.singbox import is_running as sb_running
        from hydra.core.state import load_state

        installed = WGCF_PROFILE.exists() or any(WARP_PROFILES_DIR.glob("*.conf"))
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

    def update_external_rules(self, state: AppState | None = None) -> tuple[bool, str]:
        """Загружает правила из всех включенных внешних источников и сохраняет их в кэш."""
        if state is None:
            from hydra.core.state import load_state
            state = load_state()
        ps = state.protocols.get("warp")
        if not ps:
            return False, "Плагин не настроен в state.json"
        
        list_targets = ps.config.get("list_targets", {})
        enabled_keys = []
        for k, target in list_targets.items():
            if k.startswith("ext:") and target and target != "none":
                key = k.split(":", 1)[1]
                if key not in enabled_keys:
                    enabled_keys.append(key)

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
                errors.append(f"Неизвестный источник: {key}")
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
                    "domains": sorted(set(domains)),
                    "ips": sorted(set(ips))
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
            metadata_keys = {"updated_at", "last_attempt_at"}
            keys_to_delete = [
                k for k in existing if k not in metadata_keys and k not in enabled_keys
            ]
            for k in keys_to_delete:
                existing.pop(k, None)

            attempted_at = __import__("datetime").datetime.now().isoformat()
            existing["last_attempt_at"] = attempted_at
            if errors:
                # A partial refresh is usable, but not fully fresh. The sync
                # agent will retry it after a short backoff instead of waiting
                # another 24 hours.
                existing.pop("updated_at", None)
            else:
                existing["updated_at"] = attempted_at

            HOST.atomic_write(
                WARP_EXTERNAL_CACHE,
                json.dumps(existing, indent=2, ensure_ascii=False),
                mode=0o600,
            )
            
            status_msg = f"Обновлено списков: {downloaded_count}/{len(enabled_keys)}."
            if errors:
                status_msg += f" Ошибки: {'; '.join(errors)}"
            
            return len(errors) == 0, status_msg
        except Exception as e:
            return False, f"Ошибка сохранения кэша: {e}"
