"""Compatibility facade for the decomposed subscription package."""
from __future__ import annotations

from hydra.services.subscriptions.access import (
    SubscriptionPluginAccess,
    SubscriptionPluginService,
)
from hydra.services.subscriptions.certificates import find_any_cert
from hydra.services.subscriptions.client_configs import (
    generate_client_config,
    generate_nekobox_sub,
    generate_singbox_config,
    generate_throne_sub,
)
from hydra.services.subscriptions.devices import (
    register_subscription_device,
    subscription_device_id,
)
from hydra.services.subscriptions.links import (
    generate_base64_sub,
    generate_links,
)
from hydra.services.subscriptions.metadata import (
    SUPPORTED_SUBSCRIPTION_FORMATS,
    generate_userinfo_header,
    get_subscription_url,
    get_subscription_urls,
    get_user_access_status,
    get_user_entitlement_status,
    is_user_valid,
    resolve_subscription_format,
)
from hydra.services.subscriptions.serialization import (
    clean_link_to_sn,
    generate_awg_sn_link,
    generate_mieru_nekobox_link,
    serialize_anytls,
    serialize_naive,
    serialize_nekobox_config,
    serialize_trusttunnel,
)
from hydra.services.subscriptions.server import (
    SubscriptionHandler,
    run_standalone,
)

__all__ = [
    "SUPPORTED_SUBSCRIPTION_FORMATS",
    "SubscriptionHandler",
    "SubscriptionPluginAccess",
    "SubscriptionPluginService",
    "clean_link_to_sn",
    "find_any_cert",
    "generate_awg_sn_link",
    "generate_base64_sub",
    "generate_client_config",
    "generate_links",
    "generate_mieru_nekobox_link",
    "generate_nekobox_sub",
    "generate_singbox_config",
    "generate_throne_sub",
    "generate_userinfo_header",
    "get_subscription_url",
    "get_subscription_urls",
    "get_user_access_status",
    "get_user_entitlement_status",
    "is_user_valid",
    "register_subscription_device",
    "resolve_subscription_format",
    "run_standalone",
    "serialize_anytls",
    "serialize_naive",
    "serialize_nekobox_config",
    "serialize_trusttunnel",
    "subscription_device_id",
]


if __name__ == "__main__":
    # Compatibility for systemd units installed by HYDRA <= 2.5.3.
    from importlib import import_module

    import_module("hydra.entrypoints.subscription_server").main()
