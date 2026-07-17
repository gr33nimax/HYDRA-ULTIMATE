"""Download and convert Clash rule-provider payloads for HYDRA routing."""
from __future__ import annotations

import ipaddress
import re

MAX_PROVIDER_RULES = 250_000


class RuleProviderError(ValueError):
    pass


def _domain(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    if value.startswith("+."):
        value = value[2:]
    elif value.startswith("."):
        value = value[1:]
    if not value or len(value) > 253 or re.search(r"[\s/:]", value):
        return None
    return value


def parse_clash_rule_provider(content: str, behavior: str, provider_format: str = "yaml") -> dict:
    """Convert a Clash YAML/text provider to explicit Sing-Box match lists."""
    behavior = behavior.lower()
    provider_format = provider_format.lower()
    if provider_format == "mrs":
        raise RuleProviderError("Mihomo MRS является бинарным форматом")

    if provider_format == "text":
        payload = content.splitlines()
    else:
        try:
            import yaml
            document = yaml.safe_load(content)
        except Exception as exc:
            raise RuleProviderError(f"ошибка разбора provider YAML: {exc}") from exc
        if isinstance(document, dict):
            payload = document.get("payload")
        else:
            payload = document
        if not isinstance(payload, list):
            raise RuleProviderError("provider не содержит список payload")

    result = {
        "domains": [],
        "domain_suffix": [],
        "domain_keyword": [],
        "ips": [],
        "skipped": 0,
    }
    seen = {key: set() for key in ("domains", "domain_suffix", "domain_keyword", "ips")}

    def append(key: str, value: str) -> None:
        if value and value not in seen[key]:
            seen[key].add(value)
            result[key].append(value)

    for index, raw in enumerate(payload):
        if index >= MAX_PROVIDER_RULES:
            raise RuleProviderError(f"provider превышает лимит {MAX_PROVIDER_RULES} правил")
        token = str(raw).strip()
        if not token or token.startswith(("#", "//", ";")):
            continue

        if behavior == "domain" and "," not in token:
            value = _domain(token)
            if value:
                append("domain_suffix", value)
            else:
                result["skipped"] += 1
            continue
        if behavior == "ipcidr" and "," not in token:
            try:
                append("ips", str(ipaddress.ip_network(token, strict=False)))
            except ValueError:
                result["skipped"] += 1
            continue

        parts = [part.strip() for part in token.split(",")]
        rule_type = parts[0].upper()
        value = parts[1] if len(parts) > 1 else ""
        if rule_type == "DOMAIN":
            domain = _domain(value)
            append("domains", domain or "")
            result["skipped"] += int(domain is None)
        elif rule_type == "DOMAIN-SUFFIX":
            domain = _domain(value)
            append("domain_suffix", domain or "")
            result["skipped"] += int(domain is None)
        elif rule_type == "DOMAIN-KEYWORD" and value and not re.search(r"\s", value):
            append("domain_keyword", value.lower())
        elif rule_type in ("IP-CIDR", "IP-CIDR6"):
            try:
                append("ips", str(ipaddress.ip_network(value, strict=False)))
            except ValueError:
                result["skipped"] += 1
        else:
            result["skipped"] += 1
    return result
