"""hydra/core/sni_router.py — Caddy L4 (Multiplexer + Decoy) management.

Replaces HAProxy, providing SNI-based routing, TLS termination, and decoy fallbacks.
"""
from __future__ import annotations

import os
import json
import shutil
import subprocess
from pathlib import Path
from hydra.core.state import AppState

CADDY_BIN = Path("/usr/local/bin/caddy-l4")
CADDY_CFG = Path("/etc/caddy-l4/config.json")
CADDY_CFG_DIR = Path("/etc/caddy-l4")
CADDY_LOG_DIR = Path("/var/log/caddy-l4")
DECOY_LOG = CADDY_LOG_DIR / "decoy-access.log"
SERVICE_NAME = "caddy-l4"
SERVICE_FILE = Path("/etc/systemd/system/caddy-l4.service")
FRONTEND_PORT = 443

_INTERNAL_PORTS = {
    "naive": 10443,       # Caddy HTTP app (forward_proxy + file_server)
    "anytls": 20444,      # sing-box anytls (tls OFF)
    "trusttunnel": 20445, # sing-box trusttunnel (tls OFF)
    "sub_server": 9443,
}

_DECOY_HTTP_PORTS = {
    "anytls": 10801,
    "trusttunnel": 10802,
}


def is_installed() -> bool:
    """Checks if Caddy L4 binary exists."""
    return CADDY_BIN.exists() or shutil.which("caddy-l4") is not None


def install() -> bool:
    """Builds and installs caddy-l4 with forwardproxy using xcaddy."""
    if is_installed():
        return True

    print("  Installing Go compiler...")
    if not shutil.which("go"):
        subprocess.run(["apt-get", "update"], capture_output=True)
        subprocess.run(["apt-get", "install", "-y", "golang-go"], capture_output=True)

    print("  Installing xcaddy and building caddy-l4...")
    # Install xcaddy in a local path to avoid global permissions issues
    go_path = "/usr/local/share/go"
    os.makedirs(go_path, exist_ok=True)
    env = {**os.environ, "GOPATH": go_path, "GOBIN": f"{go_path}/bin"}
    
    subprocess.run([
        "go", "install", "github.com/caddyserver/xcaddy/cmd/xcaddy@latest"
    ], capture_output=True, env=env)

    xcaddy_bin = f"{go_path}/bin/xcaddy"
    if not os.path.exists(xcaddy_bin):
        xcaddy_bin = shutil.which("xcaddy") or "xcaddy"

    # Build Caddy with layer4 and forwardproxy-naive plugins
    r = subprocess.run([
        xcaddy_bin, "build",
        "--with", "github.com/mholt/caddy-l4",
        "--with", "github.com/caddyserver/forwardproxy@caddy2=github.com/Michaol/forwardproxy-naive@caddy2",
        "--output", str(CADDY_BIN)
    ], capture_output=True, text=True, env=env)

    if r.returncode != 0:
        # Fallback to building without the naive fork if there are dependency conflicts
        r = subprocess.run([
            xcaddy_bin, "build",
            "--with", "github.com/mholt/caddy-l4",
            "--with", "github.com/caddyserver/forwardproxy@caddy2",
            "--output", str(CADDY_BIN)
        ], capture_output=True, text=True, env=env)

    if r.returncode == 0 and CADDY_BIN.exists():
        CADDY_BIN.chmod(0o755)
        return True

    return False


def is_active() -> bool:
    """Checks if the caddy-l4 service is active."""
    if not is_installed():
        return False
    r = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
    return r.stdout.strip() == "active"


def get_internal_port(plugin_name: str) -> int:
    """Returns the internal port for the plugin."""
    return _INTERNAL_PORTS.get(plugin_name, 0)


def get_decoy_http_port(plugin_name: str) -> int:
    """Returns the decoy http port for the plugin."""
    return _DECOY_HTTP_PORTS.get(plugin_name, 0)


def get_effective_port(plugin_name: str, state: AppState) -> int:
    """Returns the port the plugin should listen on.

    If multiplexer is active -> internal port.
    If single active transport -> FRONTEND_PORT (443) directly.
    """
    if needs_mux(state):
        return get_internal_port(plugin_name)
    return FRONTEND_PORT


def needs_mux(state: AppState) -> bool:
    """Returns True if multiplexing is required (2+ TLS plugins active or sub_domain configured)."""
    count = 0
    for name in _INTERNAL_PORTS:
        if name == "sub_server":
            continue
        proto = state.protocols.get(name)
        if proto and proto.enabled:
            domain = state.network.domain if name == "naive" else proto.config.get("domain")
            if domain:
                count += 1
    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        count += 1
    return count >= 2 or bool(sub_domain)


def _has_sub_domain(state: AppState) -> bool:
    return bool(getattr(state.network, "sub_domain", ""))


def _collect_backends(state: AppState) -> list[dict]:
    backends = []
    for name, port in _INTERNAL_PORTS.items():
        if name == "sub_server":
            continue
        proto = state.protocols.get(name)
        if proto and proto.enabled:
            domain = state.network.domain if name == "naive" else proto.config.get("domain", "")
            cert_file = proto.config.get("cert_file", "")
            key_file = proto.config.get("key_file", "")
            if domain:
                backends.append({
                    "name": name,
                    "domain": domain,
                    "port": port,
                    "cert_file": cert_file,
                    "key_file": key_file,
                })
    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        backends.append({
            "name": "sub_server",
            "domain": sub_domain,
            "port": _INTERNAL_PORTS["sub_server"],
            "cert_file": "",
            "key_file": "",
        })
    return backends


def _generate_config(backends: list[dict], state: AppState) -> dict:
    """Generates the Caddy JSON configuration."""
    
    # 1. Logging config
    logging = {
        "logs": {
            "default": {
                "writer": {"output": "discard"}
            },
            "decoy": {
                "writer": {
                    "output": "file",
                    "filename": str(DECOY_LOG)
                },
                "include": ["http.log.access.decoy"],
                "level": "INFO"
            }
        }
    }

    # 2. TLS app (load certificates for SNI matching)
    certificates = []
    for b in backends:
        if b["cert_file"] and b["key_file"]:
            certificates.append({
                "certificate": b["cert_file"],
                "key": b["key_file"]
            })
    
    tls_app = {}
    if certificates:
        tls_app["certificates"] = {
            "load_files": certificates
        }

    # 3. Layer 4 app (TLS termination and routing)
    l4_routes = []
    for b in backends:
        name = b["name"]
        domain = b["domain"]
        port = b["port"]

        if name == "naive":
            # Naive route: TLS termination -> local forward_proxy HTTP server
            l4_routes.append({
                "match": [{"tls": {"sni": [domain]}}],
                "handle": [
                    {"handler": "tls"},
                    {"handler": "proxy", "upstreams": [{"dial": [f"127.0.0.1:{port}"]}]}
                ]
            })
        elif name == "anytls":
            # AnyTLS route: TLS termination -> check if NOT HTTP -> proxy to sing-box AnyTLS (no TLS)
            # Else -> proxy to decoy HTTP server
            decoy_port = _DECOY_HTTP_PORTS["anytls"]
            l4_routes.append({
                "match": [{"tls": {"sni": [domain]}}],
                "handle": [
                    {"handler": "tls"},
                    {
                        "handler": "subroute",
                        "routes": [
                            {
                                "match": [{"not": [{"http": []}]}],
                                "handle": [
                                    {"handler": "proxy", "upstreams": [{"dial": [f"127.0.0.1:{port}"]}]}
                                ]
                            },
                            {
                                "handle": [
                                    {"handler": "proxy", "upstreams": [{"dial": [f"127.0.0.1:{decoy_port}"]}]}
                                ]
                            }
                        ]
                    }
                ]
            })
        elif name == "trusttunnel":
            # TrustTunnel route: TLS termination -> local HTTP server (reverse_proxy to sing-box + error decoy)
            decoy_port = _DECOY_HTTP_PORTS["trusttunnel"]
            l4_routes.append({
                "match": [{"tls": {"sni": [domain]}}],
                "handle": [
                    {"handler": "tls"},
                    {"handler": "proxy", "upstreams": [{"dial": [f"127.0.0.1:{decoy_port}"]}]}
                ]
            })
        elif name == "sub_server":
            # Subscription server route: simple TCP proxy to sub_server port (no termination here)
            l4_routes.append({
                "match": [{"tls": {"sni": [domain]}}],
                "handle": [
                    {"handler": "proxy", "upstreams": [{"dial": [f"127.0.0.1:{port}"]}]}
                ]
            })

    # Default fallback route for unrecognized SNI (routes to naive_server decoy)
    naive_backend = next((b for b in backends if b["name"] == "naive"), None)
    if naive_backend:
        l4_routes.append({
            "handle": [
                {"handler": "tls"},
                {"handler": "proxy", "upstreams": [{"dial": [f"127.0.0.1:{_INTERNAL_PORTS['naive']}"]}]}
            ]
        })

    l4_app = {
        "servers": {
            "tls_mux": {
                "listen": [":443"],
                "routes": l4_routes
            }
        }
    }

    # 4. HTTP app (decoy websites & forward_proxy)
    http_servers = {}

    # Naive HTTP server (hosts forward_proxy + decoy-a)
    if any(b["name"] == "naive" for b in backends):
        # Build users credentials for forward_proxy
        naive_users = []
        for user in state.users:
            if user.blocked:
                continue
            # derive credentials identically to naive plugin
            from hydra.utils.crypto import derive_hex_key
            clean = user.email.split("@")[0]
            username = "".join(c for c in clean if c.isalnum() or c in ("_", "-")) or user.email
            password = derive_hex_key("naive-pass", user.uuid)[:24]
            naive_users.append({
                "username": username,
                "password": password
            })

        # Generate forward_proxy route config
        fp_route = {
            "handle": [
                {
                    "handler": "forward_proxy",
                    "hide_ip": True,
                    "hide_via": True,
                    "probe_resistance": {}
                }
            ]
        }
        # Add auth if users exist
        if naive_users:
            fp_route["handle"][0]["auth_user_deprecated"] = naive_users[0]["username"]
            fp_route["handle"][0]["auth_pass_deprecated"] = naive_users[0]["password"]

        http_servers["naive_server"] = {
            "listen": [f"127.0.0.1:{_INTERNAL_PORTS['naive']}"],
            "routes": [
                {
                    "handle": [
                        {
                          "handler": "subroute",
                          "routes": [
                            fp_route,
                            {
                              "handle": [
                                {"handler": "file_server", "root": "/var/www/decoy-a"}
                              ]
                            }
                          ]
                        }
                    ]
                }
            ],
            "logs": {
                "logger_names": {state.network.domain: "decoy"}
            }
        }

    # AnyTLS Decoy HTTP server
    if any(b["name"] == "anytls" for b in backends):
        anytls_backend = next(b for b in backends if b["name"] == "anytls")
        http_servers["anytls_decoy"] = {
            "listen": [f"127.0.0.1:{_DECOY_HTTP_PORTS['anytls']}"],
            "routes": [
                {
                    "handle": [
                        {"handler": "file_server", "root": "/var/www/decoy-b"}
                    ]
                }
            ],
            "logs": {
                "logger_names": {anytls_backend["domain"]: "decoy"}
            }
        }

    # TrustTunnel Decoy/Proxy HTTP server
    if any(b["name"] == "trusttunnel" for b in backends):
        tt_backend = next(b for b in backends if b["name"] == "trusttunnel")
        tt_port = _INTERNAL_PORTS["trusttunnel"]
        http_servers["trusttunnel_decoy"] = {
            "listen": [f"127.0.0.1:{_DECOY_HTTP_PORTS['trusttunnel']}"],
            "routes": [
                {
                    "handle": [
                        {
                            "handler": "subroute",
                            "routes": [
                                {
                                    "handle": [
                                        {
                                            "handler": "reverse_proxy",
                                            "upstreams": [{"dial": f"127.0.0.1:{tt_port}"}],
                                            "transport": {
                                                "protocol": "http",
                                                "versions": ["h2c", "2"]
                                            },
                                            "handle_response": [
                                                {
                                                    "match": {"status_code": [502, 503]},
                                                    "routes": [
                                                        {
                                                            "handle": [
                                                                {"handler": "file_server", "root": "/var/www/decoy-c"}
                                                            ]
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "errors": {
                        "routes": [
                            {
                                "handle": [
                                    {"handler": "file_server", "root": "/var/www/decoy-c"}
                                ]
                            }
                        ]
                    }
                }
            ],
            "logs": {
                "logger_names": {tt_backend["domain"]: "decoy"}
            }
        }

    http_app = {}
    if http_servers:
        http_app["servers"] = http_servers

    apps = {
        "layer4": l4_app
    }
    if tls_app:
        apps["tls"] = tls_app
    if http_app:
        apps["http"] = http_app

    return {
        "logging": logging,
        "apps": apps
    }


def rebuild(state: AppState) -> bool:
    """Rebuilds the Caddy L4 config and reloads/starts the service."""
    backends = _collect_backends(state)

    if len(backends) < 2 and not _has_sub_domain(state):
        stop()
        return True

    # 1. Ensure Caddy L4 is installed
    if not is_installed():
        if not install():
            return False

    # 2. Ensure decoy site files exist
    from hydra.core.decoy import ensure_decoy_site
    for b in backends:
        if b["name"] != "sub_server":
            try:
                ensure_decoy_site(b["name"])
            except Exception as e:
                print(f"  Error generating decoy for {b['name']}: {e}")

    # 3. Generate configuration
    config = _generate_config(backends, state)
    CADDY_CFG_DIR.mkdir(parents=True, exist_ok=True)
    CADDY_LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    CADDY_CFG.write_text(json.dumps(config, indent=2), encoding="utf-8")

    # 4. Validate config
    r = subprocess.run([
        str(CADDY_BIN), "validate", "--config", str(CADDY_CFG)
    ], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  Caddy L4 config validation error: {r.stderr or r.stdout}")
        return False

    # 5. Write systemd service file
    _install_service()

    # 6. Apply block-firewall rules for loopback isolation
    try:
        for b in backends:
            port = b["port"]
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
        
        # Block decoy ports from external access too
        for decoy_port in _DECOY_HTTP_PORTS.values():
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(decoy_port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(decoy_port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
    except Exception:
        pass

    # 7. Enable and reload/restart service
    subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)
    r = subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
    return r.returncode == 0


def stop() -> None:
    """Stops and disables the Caddy L4 service."""
    try:
        if is_installed():
            subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
            subprocess.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)
        
        # Remove firewall blocks
        for port in _INTERNAL_PORTS.values():
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
        for decoy_port in _DECOY_HTTP_PORTS.values():
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(decoy_port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
    except Exception:
        pass


def uninstall_haproxy() -> None:
    """Stops, disables, and removes the old HAProxy service."""
    try:
        subprocess.run(["systemctl", "stop", "haproxy"], capture_output=True)
        subprocess.run(["systemctl", "disable", "haproxy"], capture_output=True)
        # Clear iptables rules previously set for HAProxy internal ports
        for port in (10443, 10444, 10445, 9443):
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
    except Exception:
        pass


def _install_service() -> None:
    """Generates the systemd unit file for caddy-l4."""
    unit_content = f"""[Unit]
Description=Caddy L4 (TLS multiplexer + decoy)
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=notify
ExecStart={CADDY_BIN} run --config {CADDY_CFG}
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure
RestartSec=1
TimeoutStopSec=5
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    try:
        SERVICE_FILE.parent.mkdir(parents=True, exist_ok=True)
        SERVICE_FILE.write_text(unit_content, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    except OSError:
        pass
