import copy
import json
import re
from pathlib import Path
from typing import Callable

from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess

ParsedProfile = dict[str, dict[str, str]]
EndpointParser = Callable[[str], tuple[str, int] | None]


def normalize_config(
    source: dict,
    *,
    default_domains: list[str],
) -> dict:
    config = copy.deepcopy(source)
    if "local_lists" not in config and "list_targets" not in config:
        if "domains" not in config and "ips" not in config:
            config.setdefault("local_lists", {})["default"] = {
                "domains": default_domains.copy(),
                "ips": [],
            }
            config.setdefault("list_targets", {})["local:default"] = "warp"

    old_domains = config.pop("domains", None)
    old_ips = config.pop("ips", None)
    if old_domains is not None or old_ips is not None:
        default_list = config.setdefault("local_lists", {}).setdefault(
            "default",
            {"domains": [], "ips": []},
        )
        if old_domains:
            default_list["domains"] = list(set(default_list["domains"] + old_domains))
        if old_ips:
            default_list["ips"] = list(set(default_list["ips"] + old_ips))
        config.setdefault("list_targets", {}).setdefault("local:default", "warp")

    enabled_external = config.pop("enabled_external_lists", None)
    if enabled_external is not None:
        targets = config.setdefault("list_targets", {})
        for key in enabled_external:
            targets.setdefault(f"ext:{key}", "warp")
    return config


def read_custom_profiles(
    profiles_dir: Path,
    *,
    parse_config: Callable[[str], ParsedProfile | None],
) -> list[tuple[str, ParsedProfile]]:
    profiles = []
    for path in sorted(profiles_dir.glob("*.conf")):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", path.stem):
            continue
        try:
            parsed = parse_config(path.read_text(encoding="utf-8", errors="replace"))
            if parsed:
                profiles.append((path.stem, parsed))
        except Exception as exc:
            from hydra.core.singbox import _log
            _log("ERROR", f"Failed to parse warp profile {path}: {exc}")
    return profiles


def _addresses(
    raw: str,
    *,
    validate_ip: Callable[[str], bool],
) -> list[str]:
    result = []
    for value in raw.split(","):
        address = value.strip()
        if address and validate_ip(address):
            result.append(
                address if "/" in address else address + ("/128" if ":" in address else "/32")
            )
    return result


def _amnezia_parameters(interface: dict[str, str]) -> dict[str, object]:
    result: dict[str, object] = {}
    integer_keys = ("s1", "s2", "s3", "s4", "jc", "jmin", "jmax",
                    "h1", "h2", "h3", "h4")
    for key in integer_keys:
        if key in interface:
            try:
                result[key] = int(interface[key])
            except ValueError:
                pass
    for key in ("i1", "i2", "i3", "i4", "i5"):
        if key in interface and interface[key].strip():
            result[key] = interface[key].strip()
    return result


def render_custom_profile(
    name: str,
    parsed: ParsedProfile,
    *,
    parse_endpoint: EndpointParser,
    validate_ip: Callable[[str], bool],
    resolve_host: Callable[[str], str],
) -> tuple[dict, dict] | None:
    target = parse_endpoint(parsed["peer"].get("endpoint", ""))
    if target is None:
        return None
    host, port = target
    try:
        server_ip = resolve_host(host)
    except Exception:
        server_ip = host
    addresses = _addresses(
        parsed["interface"].get("address", ""),
        validate_ip=validate_ip,
    )
    try:
        mtu = int(parsed["interface"].get("mtu", 1280))
    except ValueError:
        return None
    allowed_ips = [
        value.strip()
        for value in parsed["peer"].get("allowedips", "0.0.0.0/0, ::/0").split(",")
        if validate_ip(value.strip())
    ]
    if not addresses or not allowed_ips or not 576 <= mtu <= 65535:
        return None

    tag = f"warp_{name}"
    endpoint = {
        "type": "wireguard",
        "tag": f"{tag}_ep",
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
        ],
    }
    interface = parsed["interface"]
    amnezia_keys = ("s1", "s2", "jc", "jmin", "jmax", "h1", "h2", "h3", "h4")
    if any(key in interface for key in amnezia_keys):
        amnezia = _amnezia_parameters(interface)
        if amnezia:
            endpoint["amnezia"] = amnezia
    outbound = {"type": "selector", "tag": tag, "outbounds": [f"{tag}_ep"]}
    return endpoint, outbound


def render_default_profile(
    config: dict | None,
    *,
    parse_endpoint: EndpointParser,
    resolve_host: Callable[[str], str],
) -> tuple[dict, dict] | None:
    if not config:
        return None
    target = parse_endpoint(
        config.get("endpoint", "engage.cloudflareclient.com:2408")
    )
    try:
        mtu = int(config.get("mtu", 1280))
    except (TypeError, ValueError):
        mtu = 1280
    if target is None or not 576 <= mtu <= 65535:
        return None
    host, port = target
    try:
        server_ip = resolve_host(host)
    except Exception:
        server_ip = host
    endpoint = {
        "type": "wireguard",
        "tag": "warp_ep",
        "address": config["addresses"],
        "private_key": config["private_key"],
        "mtu": mtu,
        "peers": [
            {
                "address": server_ip,
                "port": port,
                "public_key": config.get(
                    "public_key",
                    "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                ),
                "allowed_ips": config.get("allowed_ips")
                or ["0.0.0.0/0", "::/0"],
            }
        ],
    }
    return endpoint, {"type": "selector", "tag": "warp", "outbounds": ["warp_ep"]}


def load_external_rules(cache: Path) -> dict:
    if not cache.exists():
        return {}
    try:
        return json.loads(cache.read_text(encoding="utf-8"))
    except Exception:
        return {}


def render_route_rules(
    config: dict,
    external_rules: dict,
    destinations: set[str],
    *,
    russia_suffixes: list[str],
    validate_domain: Callable[[str], bool],
    validate_ip: Callable[[str], bool],
) -> list[dict]:
    outbound_domains: dict[str, list] = {}
    outbound_ips: dict[str, list] = {}
    local_lists = config.get("local_lists", {})
    for list_key, target in config.get("list_targets", {}).items():
        if not target or target == "none" or target not in destinations:
            continue
        domains, ips = _list_entries(
            list_key,
            local_lists,
            external_rules,
            russia_suffixes,
        )
        if domains:
            outbound_domains.setdefault(target, []).extend(domains)
        if ips:
            outbound_ips.setdefault(target, []).extend(ips)

    rules = []
    for target, values in outbound_domains.items():
        domains = sorted(
            {
                item.strip().lower()
                for item in values
                if isinstance(item, str) and validate_domain(item.strip())
            }
        )
        if domains:
            rules.append({"domain_suffix": domains, "outbound": target})
    for target, values in outbound_ips.items():
        ips = sorted(
            {
                item.strip()
                for item in values
                if isinstance(item, str) and validate_ip(item.strip())
            }
        )
        if ips:
            rules.append({"ip_cidr": ips, "outbound": target})
    return rules


def _list_entries(
    list_key: str,
    local_lists: dict,
    external_rules: dict,
    russia_suffixes: list[str],
) -> tuple[list, list]:
    if list_key.startswith("local:"):
        values = local_lists.get(list_key.split(":", 1)[1], {})
        return values.get("domains", []), values.get("ips", [])
    if list_key.startswith("ext:"):
        name = list_key.split(":", 1)[1]
        values = external_rules.get(name, {})
        domains = values.get("domains", [])
        if name == "russia":
            domains = [*domains, *russia_suffixes]
        return domains, values.get("ips", [])
    return [], []


def configure_warp(
    state: PluginStateAccess,
    *,
    profiles_dir: Path,
    external_cache: Path,
    default_domains: list[str],
    russia_suffixes: list[str],
    parse_config: Callable[[str], ParsedProfile | None],
    parse_endpoint: EndpointParser,
    validate_domain: Callable[[str], bool],
    validate_ip: Callable[[str], bool],
    resolve_host: Callable[[str], str],
    load_default_profile: Callable[[], dict | None],
) -> ConfigFragment:
    protocol = state.protocols.get("warp")
    config = normalize_config(
        protocol.config if protocol else {},
        default_domains=default_domains,
    )
    endpoints, outbounds = [], []
    destinations = {"direct"}
    for name, parsed in read_custom_profiles(
        profiles_dir,
        parse_config=parse_config,
    ):
        rendered = render_custom_profile(
            name,
            parsed,
            parse_endpoint=parse_endpoint,
            validate_ip=validate_ip,
            resolve_host=resolve_host,
        )
        if rendered:
            endpoint, outbound = rendered
            endpoints.append(endpoint)
            outbounds.append(outbound)
            destinations.add(outbound["tag"])

    rendered = render_default_profile(
        load_default_profile(),
        parse_endpoint=parse_endpoint,
        resolve_host=resolve_host,
    )
    if rendered:
        endpoint, outbound = rendered
        endpoints.append(endpoint)
        outbounds.append(outbound)
        destinations.add("warp")

    rules = render_route_rules(
        config,
        load_external_rules(external_cache),
        destinations,
        russia_suffixes=russia_suffixes,
        validate_domain=validate_domain,
        validate_ip=validate_ip,
    )
    if not rules:
        return ConfigFragment()
    return ConfigFragment(
        outbounds=outbounds,
        endpoints=endpoints,
        route_rules=rules,
    )
