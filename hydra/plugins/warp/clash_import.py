"""Import the WARP-compatible subset of a Clash/Mihomo configuration.

The source YAML is intentionally not used as the sing-box configuration.  HYDRA
owns its listeners, DNS and TPROXY rules, so only WireGuard endpoints are
normalised and persisted here.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from pathlib import Path


WARP_CONFIGS_DIR = Path("/etc/hydra/warp_configs")
WARP_ULTIMATE_SOURCE = WARP_CONFIGS_DIR / "ultimate.yaml"
WARP_ULTIMATE_BUNDLE = WARP_CONFIGS_DIR / "ultimate.json"
MAX_CLASH_CONFIG_SIZE = 5 * 1024 * 1024
MAX_WARP_ENDPOINTS = 256
SUPPORTED_RULE_BEHAVIORS = frozenset({"classical", "domain", "ipcidr"})


class ClashImportError(ValueError):
    """Raised when a Clash file cannot be safely converted."""


def _key(value: object, field: str) -> str:
    value = str(value or "").strip()
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ClashImportError(f"{field}: ключ не является корректным base64") from exc
    if len(decoded) != 32:
        raise ClashImportError(f"{field}: ожидается 32-байтовый ключ")
    return value


def _addresses(proxy: dict) -> list[str]:
    result: list[str] = []
    for field in ("ip", "ipv6"):
        raw = str(proxy.get(field, "")).strip()
        if not raw:
            continue
        try:
            value = ipaddress.ip_interface(raw if "/" in raw else raw + ("/128" if ":" in raw else "/32"))
        except ValueError as exc:
            raise ClashImportError(f"{field}: некорректный адрес {raw!r}") from exc
        result.append(str(value))
    if not result:
        raise ClashImportError("у WireGuard endpoint отсутствуют ip/ipv6")
    return result


def _allowed_ips(proxy: dict) -> list[str]:
    values = proxy.get("allowed-ips", ["0.0.0.0/0", "::/0"])
    if isinstance(values, str):
        values = [part.strip() for part in values.split(",")]
    if not isinstance(values, list) or not values:
        raise ClashImportError("allowed-ips должен быть непустым списком")
    result = []
    for raw in values:
        try:
            result.append(str(ipaddress.ip_network(str(raw).strip(), strict=False)))
        except ValueError as exc:
            raise ClashImportError(f"allowed-ips: некорректная сеть {raw!r}") from exc
    return result


def _amnezia(proxy: dict) -> dict:
    source = proxy.get("amnezia-wg-option") or {}
    if not isinstance(source, dict):
        raise ClashImportError("amnezia-wg-option должен быть объектом")
    result = {}
    for key in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "itime"):
        if key in source:
            try:
                result[key] = int(source[key])
            except (TypeError, ValueError) as exc:
                raise ClashImportError(f"amnezia-wg-option.{key}: ожидается целое число") from exc
    for key in ("i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3"):
        value = str(source.get(key, "")).strip()
        if value:
            result[key] = value
    return result


def _normalise_proxy(proxy: dict, index: int) -> dict:
    name = str(proxy.get("name", "")).strip() or f"WARP endpoint {index}"
    server = str(proxy.get("server", "")).strip()
    if not server or re.search(r"\s", server):
        raise ClashImportError(f"{name}: отсутствует или некорректен server")
    try:
        port = int(proxy.get("port"))
        mtu = int(proxy.get("mtu", 1280))
    except (TypeError, ValueError) as exc:
        raise ClashImportError(f"{name}: port/mtu должны быть числами") from exc
    if not 1 <= port <= 65535 or not 576 <= mtu <= 65535:
        raise ClashImportError(f"{name}: port или mtu вне допустимого диапазона")

    peer = {
        "address": server,
        "port": port,
        "public_key": _key(proxy.get("public-key"), f"{name}.public-key"),
        "allowed_ips": _allowed_ips(proxy),
    }
    reserved = proxy.get("reserved")
    if reserved is not None:
        if not isinstance(reserved, list) or len(reserved) != 3:
            raise ClashImportError(f"{name}: reserved должен содержать три байта")
        try:
            reserved = [int(value) for value in reserved]
        except (TypeError, ValueError) as exc:
            raise ClashImportError(f"{name}: reserved должен содержать числа") from exc
        if any(value < 0 or value > 255 for value in reserved):
            raise ClashImportError(f"{name}: reserved должен содержать байты 0..255")
        peer["reserved"] = reserved

    identity = hashlib.sha256(f"{name}\0{server}\0{port}".encode("utf-8")).hexdigest()[:10]
    result = {
        "tag": f"warp_ultimate_{identity}",
        "name": name,
        "address": _addresses(proxy),
        "private_key": _key(proxy.get("private-key"), f"{name}.private-key"),
        "mtu": mtu,
        "peer": peer,
    }
    amnezia = _amnezia(proxy)
    if amnezia:
        result["amnezia"] = amnezia
    return result


def _normalise_rule_providers(data: dict) -> list[dict]:
    providers = data.get("rule-providers") or {}
    if not isinstance(providers, dict):
        raise ClashImportError("rule-providers должен быть объектом")

    route_groups: dict[str, str] = {}
    for raw_rule in data.get("rules") or []:
        if not isinstance(raw_rule, str):
            continue
        if raw_rule.startswith("RULE-SET,"):
            parts = [part.strip() for part in raw_rule.split(",")]
            if len(parts) >= 3:
                route_groups.setdefault(parts[1], parts[2])
            continue
        # Clash logical rule, e.g. AND,((NETWORK,udp),(RULE-SET,discord-ip)),Discord
        target = raw_rule.rsplit(",", 1)[-1].strip()
        for provider_name in re.findall(r"RULE-SET,([^,)]+)", raw_rule):
            route_groups.setdefault(provider_name.strip(), target)

    result = []
    for name, raw in providers.items():
        if not isinstance(raw, dict):
            continue
        behavior = str(raw.get("behavior", "classical")).lower()
        provider_format = str(raw.get("format", "yaml")).lower()
        url = str(raw.get("url", "")).strip()
        supported = True
        reason = ""
        if raw.get("type", "http") != "http":
            supported, reason = False, "поддерживаются только HTTP providers"
        elif provider_format == "mrs":
            supported, reason = False, "бинарный Mihomo MRS пока не поддерживается"
        elif behavior not in SUPPORTED_RULE_BEHAVIORS:
            supported, reason = False, f"неподдерживаемый behavior={behavior}"
        elif not re.match(r"^https?://", url, re.IGNORECASE):
            supported, reason = False, "отсутствует HTTP(S) URL"
        try:
            interval = max(300, int(raw.get("interval", 86400)))
        except (TypeError, ValueError):
            interval = 86400
        result.append({
            "name": str(name),
            "behavior": behavior,
            "format": provider_format,
            "url": url,
            "interval": interval,
            "route_group": route_groups.get(str(name), ""),
            "supported": supported,
            "unsupported_reason": reason,
        })
    return result


def import_clash_warp_bundle(source: Path, destination: Path = WARP_ULTIMATE_BUNDLE) -> dict:
    """Validate *source* and atomically store its WireGuard endpoints as JSON."""
    source = Path(source).expanduser()
    if not source.is_file():
        raise ClashImportError(f"файл не найден: {source}")
    if source.stat().st_size > MAX_CLASH_CONFIG_SIZE:
        raise ClashImportError("Clash-конфиг слишком большой (лимит 5 МБ)")
    try:
        import yaml
    except ImportError as exc:
        raise ClashImportError("не установлен PyYAML; переустановите HYDRA или выполните: pip3 install PyYAML") from exc
    try:
        source_text = source.read_text(encoding="utf-8")
        data = yaml.safe_load(source_text)
    except Exception as exc:
        raise ClashImportError(f"ошибка разбора YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        raise ClashImportError("в конфиге отсутствует список proxies")

    wireguard = [item for item in data["proxies"] if isinstance(item, dict) and item.get("type") == "wireguard"]
    skipped = len(data["proxies"]) - len(wireguard)
    if not wireguard:
        raise ClashImportError("в конфиге нет поддерживаемых WireGuard endpoints")
    if len(wireguard) > MAX_WARP_ENDPOINTS:
        raise ClashImportError(f"слишком много WireGuard endpoints (лимит {MAX_WARP_ENDPOINTS})")

    endpoints = []
    errors = []
    warnings = []
    for index, proxy in enumerate(wireguard, 1):
        try:
            endpoint = _normalise_proxy(proxy, index)
            endpoints.append(endpoint)
            named_port = re.search(r":(\d+)\s*$", endpoint["name"])
            if named_port and int(named_port.group(1)) != endpoint["peer"]["port"]:
                warnings.append(
                    f"{endpoint['name']}: в имени указан порт {named_port.group(1)}, "
                    f"но фактическое поле port={endpoint['peer']['port']}"
                )
        except ClashImportError as exc:
            errors.append(str(exc))
    if errors:
        preview = "; ".join(errors[:3])
        suffix = f"; ещё ошибок: {len(errors) - 3}" if len(errors) > 3 else ""
        raise ClashImportError(f"импорт отменён, обнаружены некорректные endpoints: {preview}{suffix}")

    source_hash = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    try:
        source_is_managed = source.resolve().parent == destination.parent.resolve()
    except OSError:
        source_is_managed = False
    canonical_source = source if source_is_managed else destination.with_suffix(".yaml")

    bundle = {
        "version": 2,
        "name": source.stem,
        "source_file": canonical_source.name,
        "source_sha256": source_hash,
        "endpoints": endpoints,
        "skipped_unsupported": skipped,
        "warnings": warnings,
        "rule_providers": _normalise_rule_providers(data),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.parent.chmod(0o700)
    except OSError:
        pass
    # Храним рядом исходник: его удобно обновлять вручную, а JSON остаётся
    # внутренним нормализованным представлением для генератора Sing-Box.
    if not source_is_managed:
        source_tmp = canonical_source.with_suffix(".yaml.tmp")
        source_tmp.write_text(source_text, encoding="utf-8")
        try:
            source_tmp.chmod(0o600)
        except OSError:
            pass
        source_tmp.replace(canonical_source)
    try:
        canonical_source.chmod(0o600)
    except OSError:
        pass
    tmp = destination.with_suffix(destination.suffix + ".tmp")
    tmp.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(destination)
    return bundle


def load_warp_bundle(path: Path = WARP_ULTIMATE_BUNDLE) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if data.get("version") != 2 or not isinstance(data.get("endpoints"), list):
        return None
    return data


def discover_warp_yaml_sources(directory: Path = WARP_CONFIGS_DIR) -> list[Path]:
    """Return managed Clash YAML files in deterministic order."""
    try:
        return sorted(
            path for path in directory.iterdir()
            if path.is_file() and path.suffix.lower() in (".yaml", ".yml")
        )
    except OSError:
        return []


def load_or_refresh_warp_bundle(destination: Path = WARP_ULTIMATE_BUNDLE) -> dict | None:
    """Auto-discover one YAML file and rebuild stale normalised data."""
    sources = discover_warp_yaml_sources(destination.parent)
    if not sources:
        return None
    if len(sources) > 1:
        names = ", ".join(path.name for path in sources[:5])
        raise ClashImportError(
            f"в {destination.parent} найдено несколько YAML-файлов ({names}); "
            "оставьте один Ultimate-конфиг"
        )
    source = sources[0]
    bundle = load_warp_bundle(destination)
    try:
        source_text = source.read_text(encoding="utf-8")
        digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    except (OSError, UnicodeError) as exc:
        raise ClashImportError(f"не удалось прочитать {source}: {exc}") from exc
    if bundle and bundle.get("source_sha256") == digest:
        return bundle
    return import_clash_warp_bundle(source, destination)
