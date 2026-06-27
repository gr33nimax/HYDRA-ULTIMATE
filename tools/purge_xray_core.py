#!/usr/bin/env python3
"""Remove Xray/VLESS/cascade functions from vless_installer/_core.py."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "vless_installer" / "_core.py"

REMOVE = [
    # Xray config / stats
    "_xray_log_block", "_xray_stats_blocks", "_apply_stats_to_config",
    "_set_config_owner",
    # VLESS install wizard
    "prompt_parameters", "prompt_install_mode", "prompt_protocol_mode",
    "_build_sockopt", "_build_xhttp_settings", "_build_tls_settings_xhttp",
    "_prompt_xhttp_options", "parse_vless_link", "prompt_chain_params",
    "_prompt_balancer_strategy", "prompt_chain_params_multi", "prompt_awg_exit_mode",
    "generate_xray_config_chain_entry", "_build_exit_xhttp_settings",
    "_build_exit_xhttp_outbound_settings", "_make_exit_node_config",
    "generate_xray_config_chain_exit", "_nodes_from_state",
    "_load_chain_nodes_from_state", "_save_chain_nodes_to_state",
    "_prompt_one_node", "_prompt_one_node_from_link", "_fix_node_fields",
    "_prompt_one_node_manual", "generate_xray_config_chain_entry_multi",
    "do_change_domain_strategy", "_rebuild_and_restart_xray", "do_manage_nodes",
    "generate_chain_summary", "install_dependencies",
    "configure_firewall",
    # Xray binary / nginx install path
    "_verify_sha256", "_xray_print_manual_download_hint", "_xray_try_local_zip",
    "install_xray", "_parse_x25519_keys", "_parse_x25519_field", "generate_reality_keys",
    "_detect_xhttp_mode_support", "generate_xray_config", "generate_xray_config_xhttp",
    "create_xray_service", "setup_fail2ban", "setup_nginx_rate_limit", "create_website",
    "_create_techhub", "_create_nexcloud", "_create_simple_site",
    "_ensure_nginx_sites_enabled_include", "setup_nginx_temp", "obtain_ssl_cert",
    "fix_letsencrypt_permissions", "setup_nginx_final", "setup_nginx_systemd_override",
    "ensure_cert_fix_script", "setup_cert_renewal", "_xray_get_release_info",
    "_xray_version_norm", "_xray_current_version", "_xray_geo_is_runetfreedom",
    "_geo_print_manual_download_hint", "_xray_update_geo_runetfreedom",
    "_xray_do_upgrade", "_xray_restart_all_services", "_nginx_restart_if_reality",
    "_xray_find_config", "_xray_config_rollback", "_xray_safe_apply_config",
    "_xray_rollback", "do_xray_update_interactive", "setup_xray_autoupdate",
    "_install_autoupdate_service",
    # Legacy Xray users
    "_fp_from_state", "_users_get_config", "_users_apply_config", "_users_gen_link",
    "do_user_list", "do_user_add", "do_user_delete", "do_user_show_link", "do_user_menu",
    "_gen_vless_link", "generate_client_links",
    # Split tunnel / geo (Xray routing)
    "prompt_split_tunnel", "_save_split_tunnel_custom", "_load_split_tunnel_custom",
    "download_geo_files", "setup_geo_autoupdate", "setup_logrotate",
    "build_split_tunnel_routing_rules", "_xray_count_ru_subnet_rules",
    "_show_xray_routing_rules", "do_manage_split_tunnel",
    "_apply_split_tunnel_config_from_state",
    # AWG 2.0 cascade (not Amnezia Docker)
    "awg_check_tool", "awg_generate_keys", "awg_install_local",
    "_awg_install_go_version_binary_only", "_awg_install_go_version",
    "_awg_detect_implementation", "_awg_create_userspace_stubs",
    "_awg_server_conf_text", "_awg_client_conf_text", "_awg_systemd_unit_text",
    "ensure_amneziawg_ready", "awg_setup_local_client", "awg_apply_policy_routing",
    "_awg_ensure_sshpass", "awg_setup_remote_server", "_awg_print_manual_guide",
    "awg_rollback", "awg_verify_tunnel", "_awg_cleanup_stale_interfaces", "awg_full_setup",
    "do_full_install", "do_dry_run",
    # Install rollback
    "create_backup", "perform_rollback",
    # Cascade mode / watchdog / fallback
    "switch_mode_ab", "awg_watchdog_install", "awg_watchdog_remove",
    "_awg_watchdog_set_flag", "do_manage_awg_watchdog",
    "_awg_node_subnets", "_ensure_ssh_protection", "_awg_persist_ssh_exclusion",
    "_awg_node_from_globals", "_awg_load_nodes_from_state", "_awg_save_nodes_to_state",
    "_awg_client_conf_for_node", "_awg_server_conf_for_node", "_awg_systemd_unit_for_node",
    "awg_setup_all_nodes", "_awg_bring_up_all_tunnels", "_awg_apply_policy_routing_all_nodes",
    "_awg_verify_all_tunnels", "_start_services_sequentially", "awg_multinode_watchdog_install",
    "do_manage_awg_nodes", "_awg_manual_switch", "_awg_ping_all_nodes",
    "_awg_show_failover_log", "_awg_show_ssh_protection_status", "_awg_diagnostic_all_nodes",
    "_prompt_awg_additional_nodes", "_awg_emergency_restore_all_nodes",
    "_auto_fallback_install", "_auto_fallback_set_flag", "do_manage_auto_fallback",
    # Xray maintenance
    "do_patch_stats_api", "do_emergency_repair", "do_manage_xtls_flow",
    "_fm_prompt_fingerprint",
    # Split tunnel diagnostics module entry
    "run_split_tunnel_diagnostics",
    "do_live_traffic_dashboard", "do_traffic_history",
    "_do_user_stats_screen", "_do_user_stats_sorted", "_do_user_stats_screen_v2",
    "do_manage_reality_keys", "_rotate_reality_keys",
    "do_manage_users",
    "_users_load", "_users_save", "_users_patch_config_no_restart",
    "_users_apply_to_config", "_users_get_traffic", "_users_get_traffic_extended",
    "_users_get_outbound_breakdown", "_users_get_connections_by_email",
    "_ru_subnets_save", "_ru_subnets_load_from_file", "_ru_subnets_restore_if_needed",
    "_ru_subnets_apply_to_xray", "_ru_subnets_remove_from_xray",
    "_ru_subnets_install_timer", "_ru_subnets_remove_timer", "_ru_subnets_timer_status",
    "do_manage_ru_subnet_direct", "_ru_subnets_cli_update",
    "do_full_diagnostic",
]


def remove_function(text: str, name: str) -> str:
    pat = re.compile(rf"^def {re.escape(name)}\([^)]*\)[^:]*:\n", re.MULTILINE)
    m = pat.search(text)
    if not m:
        return text
    start = m.start()
    rest = text[m.end():]
    nxt = re.search(r"^(?:def |# ={10,})", rest, re.MULTILINE)
    end = m.end() + (nxt.start() if nxt else len(rest))
    return text[:start] + text[end:]


def main() -> None:
    src = CORE.read_text(encoding="utf-8")
    removed = 0
    for name in REMOVE:
        new = remove_function(src, name)
        if new != src:
            removed += 1
            src = new
    CORE.write_text(src, encoding="utf-8")
    print(f"Removed {removed} functions from {CORE}")
    print(f"Lines: {len(src.splitlines())}")


if __name__ == "__main__":
    main()
