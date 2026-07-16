"""hydra/core/sni_router.py — Caddy L4 (Multiplexer + Decoy) management.

Replaces HAProxy, providing SNI-based routing, TLS termination, and decoy fallbacks.
"""
from __future__ import annotations

import os
import json
import shutil
import base64
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

def _hash_password_caddy(password: str) -> str:
    """Uses Caddy's built-in command to generate a bcrypt password hash."""
    if not CADDY_BIN.exists():
        return "$2a$10$MockedBcryptHashForTestingOnlyValueThisIsNotReal"
    try:
        r = subprocess.run([
            str(CADDY_BIN), "hash-password", "--plaintext", password
        ], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return ""

def _get_adapted_forward_proxy_config(naive_users: list[dict]) -> dict:
    """Adapts a temporary Caddyfile using the caddy-l4 binary to get a correct JSON config for forward_proxy."""
    if not CADDY_BIN.exists():
        return {
            "handler": "forward_proxy",
            "hide_ip": True,
            "hide_via": True,
            "probe_resistance": {},
            "auth_user": naive_users[0]["username"] if naive_users else "",
            "auth_pass": naive_users[0]["password"] if naive_users else ""
        }

    dummy_user = "DUMMYUSER"
    dummy_pass = "DUMMYPASS"
    auth_line = f"basic_auth {dummy_user} {dummy_pass}" if naive_users else ""
    caddyfile_content = f"""{{
    order forward_proxy before file_server
}}

:10443 {{
    forward_proxy {{
        {auth_line}
        hide_ip
        hide_via
        probe_resistance
    }}
    file_server {{
        root /var/www/decoy-a
    }}
}}"""
    
    tmp_cf = Path("/tmp/naive_caddyfile_tmp")
    try:
        tmp_cf.write_text(caddyfile_content, encoding="utf-8")
        r = subprocess.run([
            str(CADDY_BIN), "adapt", "--config", str(tmp_cf), "--adapter", "caddyfile"
        ], capture_output=True, text=True)
    except Exception as e:
        class MockResult:
            returncode = 1
            stdout = ""
            stderr = f"Exception during subprocess run: {e}"
        r = MockResult()
    finally:
        try:
            tmp_cf.unlink(missing_ok=True)
        except Exception:
            pass

    if r.returncode != 0:
        try:
            CADDY_LOG_DIR.mkdir(parents=True, exist_ok=True)
            debug_log = CADDY_LOG_DIR / "adapt_debug.log"
            debug_log.write_text(
                f"Adaptation failed! returncode={getattr(r, 'returncode', 'N/A')}\n"
                f"Stdout: {getattr(r, 'stdout', 'N/A')}\n"
                f"Stderr: {getattr(r, 'stderr', 'N/A')}\n",
                encoding="utf-8"
            )
        except Exception:
            pass
        return {
            "handler": "forward_proxy",
            "hide_ip": True,
            "hide_via": True,
            "probe_resistance": {},
            "auth_user": naive_users[0]["username"] if naive_users else "",
            "auth_pass": naive_users[0]["password"] if naive_users else ""
        }
        
    try:
        adapted = json.loads(r.stdout)
        servers = adapted.get("apps", {}).get("http", {}).get("servers", {})
        server_key = list(servers.keys())[0] if servers else ""
        routes = servers[server_key].get("routes", []) if server_key else []
        
        fp_handler = None
        
        def find_handler(node):
            nonlocal fp_handler
            if isinstance(node, dict):
                if node.get("handler") == "forward_proxy":
                    fp_handler = node
                    return
                for k, v in node.items():
                    find_handler(v)
            elif isinstance(node, list):
                for item in node:
                    find_handler(item)
                    
        find_handler(routes)
        
        if fp_handler:
            if "auth_credentials" in fp_handler:
                real_creds = []
                for u in naive_users:
                    cred = f"{u['username']}:{u['password']}"
                    cred_b64 = base64.b64encode(cred.encode("utf-8")).decode("utf-8")
                    cred_b64_2 = base64.b64encode(cred_b64.encode("utf-8")).decode("utf-8")
                    real_creds.append(cred_b64_2)
                fp_handler["auth_credentials"] = real_creds
                return fp_handler
            elif "credentials" in fp_handler:
                real_creds = []
                for u in naive_users:
                    bcrypt_hash = _hash_password_caddy(u["password"])
                    if bcrypt_hash:
                        cred = f"{u['username']}:{bcrypt_hash}"
                        cred_b64 = base64.b64encode(cred.encode("utf-8")).decode("utf-8")
                        real_creds.append(cred_b64)
                fp_handler["credentials"] = real_creds
                return fp_handler
            elif "auth_user_deprecated" in fp_handler:
                if naive_users:
                    fp_handler["auth_user_deprecated"] = naive_users[0]["username"]
                    fp_handler["auth_pass_deprecated"] = naive_users[0]["password"]
                else:
                    fp_handler.pop("auth_user_deprecated", None)
                    fp_handler.pop("auth_pass_deprecated", None)
                return fp_handler
            elif "auth_user" in fp_handler:
                if naive_users:
                    fp_handler["auth_user"] = naive_users[0]["username"]
                    fp_handler["auth_pass"] = naive_users[0]["password"]
                else:
                    fp_handler.pop("auth_user", None)
                    fp_handler.pop("auth_pass", None)
                return fp_handler
            elif "basic_auth" in fp_handler:
                real_creds = []
                for u in naive_users:
                    bcrypt_hash = _hash_password_caddy(u["password"])
                    if bcrypt_hash:
                        cred = f"{u['username']}:{bcrypt_hash}"
                        cred_b64 = base64.b64encode(cred.encode("utf-8")).decode("utf-8")
                        real_creds.append(cred_b64)
                fp_handler["basic_auth"] = real_creds
                return fp_handler
            
            # If no matches, log for debugging
            try:
                CADDY_LOG_DIR.mkdir(parents=True, exist_ok=True)
                debug_log = CADDY_LOG_DIR / "adapt_debug.log"
                debug_log.write_text(
                    f"No matching fields found in fp_handler!\n"
                    f"fp_handler keys: {list(fp_handler.keys())}\n"
                    f"fp_handler: {json.dumps(fp_handler)}\n",
                    encoding="utf-8"
                )
            except Exception:
                pass
    except Exception as e:
        try:
            CADDY_LOG_DIR.mkdir(parents=True, exist_ok=True)
            debug_log = CADDY_LOG_DIR / "adapt_debug.log"
            debug_log.write_text(f"Parsing Exception: {e}\n", encoding="utf-8")
        except Exception:
            pass

    # Default fallback if parsing did not return
    return {
        "handler": "forward_proxy",
        "hide_ip": True,
        "hide_via": True,
        "probe_resistance": {},
        "auth_user": naive_users[0]["username"] if naive_users else "",
        "auth_pass": naive_users[0]["password"] if naive_users else ""
    }


def is_installed() -> bool:
    """Checks if Caddy L4 binary exists."""
    return CADDY_BIN.exists() or shutil.which("caddy-l4") is not None


def _ensure_modern_go() -> bool:
    """Ensures a Go compiler version >= 1.21 is installed.

    If not, downloads and installs the official Go binary.
    """
    # Prepend /usr/local/go/bin to PATH to prioritize the official installed Go
    os.environ["PATH"] = f"/usr/local/go/bin:{os.environ.get('PATH', '')}"

    go_bin = shutil.which("go")
    if go_bin:
        try:
            r = subprocess.run([go_bin, "version"], capture_output=True, text=True)
            if r.returncode == 0:
                parts = r.stdout.split()
                if len(parts) >= 3 and parts[2].startswith("go"):
                    ver_str = parts[2][2:]
                    ver_parts = [int(x) for x in ver_str.split(".") if x.isdigit()]
                    if ver_parts and ver_parts[0] >= 1 and (len(ver_parts) < 2 or ver_parts[1] >= 21):
                        return True
        except Exception:
            pass

    print("  Modern Go compiler (>= 1.21) not found. Installing official Go 1.22...")
    # Clean up old install
    subprocess.run(["rm", "-rf", "/usr/local/go"], capture_output=True)

    # Download Go tarball
    go_tar = Path("/tmp/go.tar.gz")
    from hydra.utils.net import detect_arch
    arch = detect_arch()
    go_arch = arch if arch in ("amd64", "arm64") else "amd64"
    go_url = f"https://go.dev/dl/go1.22.5.linux-{go_arch}.tar.gz"

    from hydra.utils.downloader import download
    if download(go_url, go_tar):
        print("  Extracting Go compiler to /usr/local/go...")
        try:
            subprocess.run(["tar", "-C", "/usr/local", "-xzf", str(go_tar)], capture_output=True)
            os.environ["PATH"] = f"/usr/local/go/bin:{os.environ.get('PATH', '')}"
            return True
        except Exception as e:
            print(f"  Failed to extract Go: {e}")
        finally:
            if go_tar.exists():
                go_tar.unlink()
    return False


def install(state: AppState | None = None) -> bool:
    """Builds and installs caddy-l4 with optional forwardproxy using xcaddy."""
    if is_installed():
        return True

    # Определяем, нужен ли forwardproxy-naive модуль
    need_naive_fp = False
    if state:
        naive_proto = state.protocols.get("naive")
        need_naive_fp = naive_proto and naive_proto.enabled

    print("  Installing Go compiler...")
    if not _ensure_modern_go():
        print("  Failed to install a modern Go compiler. Trying apt fallback...")
        subprocess.run(["apt-get", "update"], capture_output=True)
        subprocess.run(["apt-get", "install", "-y", "golang-go"], capture_output=True)

    print("  Installing xcaddy and building caddy-l4...")
    # Install xcaddy in a local path to avoid global permissions issues
    go_path = "/usr/local/share/go"
    os.makedirs(go_path, exist_ok=True)
    env = {**os.environ, "GOPATH": go_path, "GOBIN": f"{go_path}/bin"}
    
    xcaddy_bin = f"{go_path}/bin/xcaddy"
    if not os.path.exists(xcaddy_bin):
        from hydra.utils.downloader import download_github_asset
        from hydra.utils.net import detect_arch
        import tarfile
        
        xcaddy_tar = Path("/tmp/xcaddy.tar.gz")
        print("  Downloading precompiled xcaddy from GitHub...")
        arch = detect_arch()
        asset_pattern = f"linux_{arch}.tar.gz"
        if download_github_asset("caddyserver/xcaddy", asset_pattern, xcaddy_tar):
            try:
                with tarfile.open(xcaddy_tar, "r:gz") as tar:
                    tar.extract("xcaddy", path=f"{go_path}/bin")
                os.chmod(xcaddy_bin, 0o755)
                print("  Successfully downloaded and extracted xcaddy.")
            except Exception as e:
                print(f"  Failed to extract xcaddy: {e}")
            finally:
                if xcaddy_tar.exists():
                    xcaddy_tar.unlink()
        else:
            print("  Downloading precompiled xcaddy failed.")

    if not os.path.exists(xcaddy_bin):
        # Fallback to go install if download failed
        print("  Trying go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest...")
        subprocess.run([
            "go", "install", "github.com/caddyserver/xcaddy/cmd/xcaddy@latest"
        ], capture_output=True, env=env)

    if not os.path.exists(xcaddy_bin):
        xcaddy_bin = shutil.which("xcaddy") or "xcaddy"

    # Build Caddy с УСЛОВНЫМ набором модулей
    build_args = [xcaddy_bin, "build", "--with", "github.com/mholt/caddy-l4"]
    
    if need_naive_fp:
        build_args += [
            "--with",
            "github.com/caddyserver/forwardproxy@caddy2=github.com/Michaol/forwardproxy-naive@caddy2",
        ]
    
    build_args += ["--output", str(CADDY_BIN)]
    
    r = subprocess.run(build_args, capture_output=True, text=True, env=env)

    if r.returncode != 0 and need_naive_fp:
        # Fallback: попробовать без naive-форка
        build_args_fallback = [
            xcaddy_bin, "build",
            "--with", "github.com/mholt/caddy-l4",
            "--with", "github.com/caddyserver/forwardproxy@caddy2",
            "--output", str(CADDY_BIN)
        ]
        r = subprocess.run(build_args_fallback, capture_output=True, text=True, env=env)

    if r.returncode != 0 and need_naive_fp:
        # Fallback 2: вообще без forwardproxy
        r = subprocess.run([
            xcaddy_bin, "build",
            "--with", "github.com/mholt/caddy-l4",
            "--output", str(CADDY_BIN)
        ], capture_output=True, text=True, env=env)

    if r.returncode != 0:
        print(f"  [Ошибка build caddy-l4] Код возврата: {r.returncode}")
        print(f"  Вывод ошибок:\n{r.stderr or r.stdout or ''}")

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
    """Returns True if multiplexing is required.

    Multiplexing is required if:
    - anytls or trusttunnel is enabled (to provide fallback decoy protection via Caddy L4)
    - OR 2+ TLS plugins are active
    - OR sub_domain is configured
    """
    for name in ("anytls", "trusttunnel"):
        proto = state.protocols.get(name)
        if proto and proto.enabled:
            if proto.config.get("domain"):
                return True

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
                    "network_mode": (
                        proto.config.get("network", "tcp") if name == "naive"
                        else ""
                    ),
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
        if b["name"] in ("anytls", "trusttunnel") and b["cert_file"] and b["key_file"]:
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
            # Naive route: TLS passthrough -> dial caddy-naive directly
            l4_routes.append({
                "match": [{"tls": {"sni": [domain]}}],
                "handle": [
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

    # Default fallback route for unrecognized SNI (routes to anytls decoy or trusttunnel decoy)
    fallback_backend = next((b for b in backends if b["name"] in ("anytls", "trusttunnel")), None)
    if fallback_backend:
        decoy_port = _DECOY_HTTP_PORTS[fallback_backend["name"]]
        l4_routes.append({
            "handle": [
                {"handler": "tls"},
                {"handler": "proxy", "upstreams": [{"dial": [f"127.0.0.1:{decoy_port}"]}]}
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

    # QUIC (UDP) для NaiveProxy
    naive_backend = next((b for b in backends if b["name"] == "naive"), None)
    naive_needs_quic = naive_backend and naive_backend.get("network_mode") in ("quic", "both")

    if naive_needs_quic:
        quic_routes = [{
            "handle": [
                {
                    "handler": "proxy",
                    "upstreams": [{"dial": [f"udp/127.0.0.1:{naive_backend['port']}"]}]
                }
            ]
        }]
        l4_app["servers"]["quic_mux"] = {
            "listen": ["udp/:443"],
            "routes": quic_routes
        }

    # 4. HTTP app (decoy websites & forward_proxy)
    http_servers = {}

    # AnyTLS Decoy HTTP server
    if any(b["name"] == "anytls" for b in backends):
        anytls_backend = next(b for b in backends if b["name"] == "anytls")
        http_servers["anytls_decoy"] = {
            "listen": [f"127.0.0.1:{_DECOY_HTTP_PORTS['anytls']}"],
            "automatic_https": {
                "disable": True,
                "disable_redirects": True
            },
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
            "automatic_https": {
                "disable": True,
                "disable_redirects": True
            },
            "routes": [
                {
                    "match": [
                        {
                            "method": ["CONNECT"]
                        }
                    ],
                    "handle": [
                        {
                            "handler": "reverse_proxy",
                            "upstreams": [{"dial": f"127.0.0.1:{tt_port}"}],
                            "transport": {
                                "protocol": "http",
                                "versions": ["2"],
                                "tls": {
                                    "insecure_skip_verify": True
                                }
                            },
                            "headers": {
                                "request": {
                                    "set": {
                                        "Proxy-Authorization": ["{http.request.header.Proxy-Authorization}"],
                                        "Authorization": ["{http.request.header.Authorization}"],
                                        "Host": ["{http.request.hostport}"]
                                    }
                                }
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
                },
                {
                    "handle": [
                        {"handler": "file_server", "root": "/var/www/decoy-c"}
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
            },
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

    if not needs_mux(state):
        stop()
        return True

    # 1. Ensure Caddy L4 is installed
    if not is_installed():
        if not install(state=state):
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
            if b["name"] == "naive" and b.get("network_mode") in ("quic", "both"):
                subprocess.run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
                subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
        
        # Block decoy ports from external access too
        for decoy_port in _DECOY_HTTP_PORTS.values():
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(decoy_port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(decoy_port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
    except Exception:
        pass

    # Open UDP:443 for QUIC if naive needs it
    needs_udp = False
    naive_proto = state.protocols.get("naive")
    if naive_proto and naive_proto.enabled and naive_proto.config.get("network") in ("quic", "both"):
        needs_udp = True

    if needs_udp:
        from hydra.utils.firewall import open_udp
        open_udp(443, "udp-quic-mux")

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
            subprocess.run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
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
