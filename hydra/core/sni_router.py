"""hydra/core/sni_router.py — Caddy L4 (Multiplexer + Decoy) management.

Replaces HAProxy, providing SNI-based routing, TLS termination, and decoy fallbacks.
"""
from __future__ import annotations

import os
import json
import shutil
import base64
import subprocess
import tempfile
from pathlib import Path
from hydra.core.state import AppState

CADDY_BIN = Path("/usr/local/bin/caddy-l4")
CADDY_CFG = Path("/etc/caddy-l4/config.json")
CADDY_CFG_DIR = Path("/etc/caddy-l4")
CADDY_LOG_DIR = Path("/var/log/caddy-l4")
DECOY_LOG = CADDY_LOG_DIR / "decoy-access.log"
SERVICE_NAME = "caddy-l4"
SERVICE_FILE = Path("/etc/systemd/system/caddy-l4.service")
SOURCE_SERVICE_NAME = "hydra-caddy-source"
SOURCE_SERVICE_FILE = Path(f"/etc/systemd/system/{SOURCE_SERVICE_NAME}.service")
FRONTEND_PORT = 443
CADDY_L4_VERSION = "42db5690dea199f930a6f08005fe2e4aab10dcc9"
GO_VERSION = "1.25.1"

_INTERNAL_PORTS = {
    "naive": 10443,       # Caddy HTTP app (forward_proxy + file_server)
    "anytls": 20444,      # sing-box anytls (tls OFF)
    "trusttunnel": 20445, # sing-box TrustTunnel TCP/UDP backend (TLS ON)
    "shadowtls": 20446,   # sing-box ShadowTLS v3
    "hysteria2": 20447,   # Decoy-only TCP route; Hysteria2 itself stays on UDP
    "sub_server": 9443,
}

_DECOY_HTTP_PORTS = {
    "anytls": 10801,
    "trusttunnel": 10802,
    "hysteria2": 10803,
}

_SOURCE_PRESERVED_BACKENDS = frozenset({"naive", "anytls", "trusttunnel", "shadowtls"})
# Disabled after production smoke tests showed that non-local loopback source
# binding breaks Caddy backend return traffic on supported server kernels.
# Keep the transactional cleanup code so hosts that applied the experimental
# routing are restored automatically on their next configuration rebuild.
SOURCE_PRESERVATION_ENABLED = False


def _proxy_handler(address: str, *, preserve_source: bool = False) -> dict:
    """Build a Caddy L4 proxy handler.

    ``l4.conn.remote_addr`` includes the original source port and is expanded
    for every connection by current caddy-l4 builds.  Binding the loopback
    upstream socket to it makes protocol authentication logs usable by
    Fail2ban; source_transparency routes the backend replies back to Caddy.
    """
    upstream = {"dial": [address]}
    if preserve_source and SOURCE_PRESERVATION_ENABLED:
        upstream["local_address"] = ["{l4.conn.remote_addr}"]
    return {"handler": "proxy", "upstreams": [upstream]}

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
    """Ensures a Go compiler version compatible with pinned Caddy L4.

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
                    if ver_parts and tuple((ver_parts + [0, 0])[:2]) >= (1, 25):
                        return True
        except Exception:
            pass

    print(f"  Modern Go compiler (>= 1.25) not found. Installing official Go {GO_VERSION}...")
    # Download and validate the replacement before moving the existing Go
    # installation. The prior tree is retained as a recoverable backup.
    go_tar = Path(f"/tmp/hydra-go-{os.getpid()}.tar.gz")
    from hydra.utils.net import detect_arch
    arch = detect_arch()
    go_arch = arch if arch in ("amd64", "arm64") else "amd64"
    go_url = f"https://go.dev/dl/go{GO_VERSION}.linux-{go_arch}.tar.gz"

    from hydra.utils.downloader import download
    if download(go_url, go_tar):
        extract_root = Path(tempfile.mkdtemp(prefix="hydra-go-", dir="/tmp"))
        current_go = Path("/usr/local/go")
        backup_go = Path(f"/usr/local/go.hydra-previous-{os.getpid()}")
        try:
            extracted = subprocess.run(
                ["tar", "-C", str(extract_root), "-xzf", str(go_tar)],
                capture_output=True,
            )
            candidate = extract_root / "go"
            if extracted.returncode != 0 or not (candidate / "bin" / "go").exists():
                return False
            if current_go.exists():
                shutil.move(str(current_go), str(backup_go))
            shutil.move(str(candidate), str(current_go))
            os.environ["PATH"] = f"/usr/local/go/bin:{os.environ.get('PATH', '')}"
            check = subprocess.run(
                [str(current_go / "bin" / "go"), "version"],
                capture_output=True, text=True,
            )
            if check.returncode == 0 and f"go{GO_VERSION}" in check.stdout:
                return True
            if current_go.exists():
                shutil.move(str(current_go), str(extract_root / "failed-go"))
            if backup_go.exists():
                shutil.move(str(backup_go), str(current_go))
        except Exception as e:
            print(f"  Failed to extract Go: {e}")
            if not current_go.exists() and backup_go.exists():
                shutil.move(str(backup_go), str(current_go))
        finally:
            go_tar.unlink(missing_ok=True)
            shutil.rmtree(extract_root, ignore_errors=True)
    return False


def install(state: AppState | None = None, *, force: bool = False) -> bool:
    """Builds and installs caddy-l4 with optional forwardproxy using xcaddy."""
    if is_installed() and not force:
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
        from hydra.utils.downloader import download_github_asset, extract_tarball
        from hydra.utils.net import detect_arch
        
        xcaddy_tar = Path("/tmp/xcaddy.tar.gz")
        print("  Downloading precompiled xcaddy from GitHub...")
        arch = detect_arch()
        asset_pattern = f"linux_{arch}.tar.gz"
        if download_github_asset("caddyserver/xcaddy", asset_pattern, xcaddy_tar):
            try:
                extract_tarball(xcaddy_tar, Path(f"{go_path}/bin"))
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
    pending_binary = CADDY_BIN.with_suffix(".pending")
    pending_binary.unlink(missing_ok=True)
    build_args = [
        xcaddy_bin, "build", "--with",
        f"github.com/mholt/caddy-l4@{CADDY_L4_VERSION}",
    ]
    
    if need_naive_fp:
        build_args += [
            "--with",
            "github.com/caddyserver/forwardproxy@caddy2=github.com/Michaol/forwardproxy-naive@caddy2",
        ]
    
    build_args += ["--output", str(pending_binary)]
    
    r = subprocess.run(build_args, capture_output=True, text=True, env=env)

    if r.returncode != 0 and need_naive_fp:
        # Fallback: попробовать без naive-форка
        build_args_fallback = [
            xcaddy_bin, "build",
            "--with", f"github.com/mholt/caddy-l4@{CADDY_L4_VERSION}",
            "--with", "github.com/caddyserver/forwardproxy@caddy2",
            "--output", str(pending_binary)
        ]
        r = subprocess.run(build_args_fallback, capture_output=True, text=True, env=env)

    if r.returncode != 0 and need_naive_fp:
        # Fallback 2: вообще без forwardproxy
        r = subprocess.run([
            xcaddy_bin, "build",
            "--with", f"github.com/mholt/caddy-l4@{CADDY_L4_VERSION}",
            "--output", str(pending_binary)
        ], capture_output=True, text=True, env=env)

    if r.returncode != 0:
        print(f"  [Ошибка build caddy-l4] Код возврата: {r.returncode}")
        print(f"  Вывод ошибок:\n{r.stderr or r.stdout or ''}")

    if r.returncode == 0 and pending_binary.exists():
        modules = subprocess.run(
            [str(pending_binary), "list-modules"], capture_output=True, text=True,
        )
        required = ["layer4.handlers.proxy"]
        if need_naive_fp:
            required.append("http.handlers.forward_proxy")
        if modules.returncode != 0 or any(name not in modules.stdout for name in required):
            pending_binary.unlink(missing_ok=True)
            print("  Built Caddy binary is missing required Hydra modules")
            return False
        pending_binary.chmod(0o755)
        if CADDY_BIN.exists():
            shutil.copy2(CADDY_BIN, CADDY_BIN.with_suffix(".previous"))
        pending_binary.replace(CADDY_BIN)
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
    - anytls, trusttunnel or hysteria2 is enabled (to provide a browser-visible decoy via Caddy L4)
    - OR 2+ TLS plugins are active
    - OR sub_domain is configured
    """
    for name in ("anytls", "trusttunnel", "hysteria2"):
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
            if name == "naive":
                domain = state.network.domain
            elif name == "shadowtls":
                domain = proto.config.get("handshake_sni")
            else:
                domain = proto.config.get("domain")
            if domain:
                count += 1
    sub_domain = getattr(state.network, "sub_domain", "")
    if sub_domain:
        count += 1
    return count >= 2 or bool(sub_domain)


def get_quic_owners(state: AppState, prospective: str | None = None) -> list[str]:
    """Возвращает HYDRA-протоколы, претендующие на внешний UDP/443."""
    owners: list[str] = []
    naive = state.protocols.get("naive")
    if naive and (naive.enabled or prospective == "naive"):
        if naive.config.get("network", "tcp") in ("quic", "both"):
            owners.append("naive")

    trusttunnel = state.protocols.get("trusttunnel")
    if trusttunnel and (trusttunnel.enabled or prospective == "trusttunnel"):
        if trusttunnel.config.get("transport", "tcp") in ("quic", "both"):
            owners.append("trusttunnel")
    return owners


def get_quic_owner(state: AppState, prospective: str | None = None) -> str | None:
    """Определяет единственного raw UDP backend или отклоняет конфликт."""
    owners = get_quic_owners(state, prospective=prospective)
    if len(owners) > 1:
        labels = ", ".join(owners)
        raise ValueError(
            f"UDP/443 одновременно запрошен несколькими QUIC-протоколами: {labels}"
        )
    return owners[0] if owners else None


def _caddy_config_had_quic_proxy() -> bool:
    try:
        current = json.loads(CADDY_CFG.read_text(encoding="utf-8"))
        servers = current.get("apps", {}).get("layer4", {}).get("servers", {})
        return "quic_mux" in servers
    except (OSError, ValueError, TypeError):
        return False



def _has_sub_domain(state: AppState) -> bool:
    return bool(getattr(state.network, "sub_domain", ""))


def _collect_backends(state: AppState) -> list[dict]:
    backends = []
    for name, port in _INTERNAL_PORTS.items():
        if name == "sub_server":
            continue
        proto = state.protocols.get(name)
        if proto and proto.enabled:
            if name == "naive":
                domain = state.network.domain
            elif name == "shadowtls":
                domain = proto.config.get("handshake_sni", "")
            else:
                domain = proto.config.get("domain", "")
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
                        else (
                            proto.config.get("transport", "tcp")
                            if name == "trusttunnel" else ""
                        )
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
        if b["name"] in ("anytls", "trusttunnel", "hysteria2") and b["cert_file"] and b["key_file"]:
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
                    _proxy_handler(f"127.0.0.1:{port}", preserve_source=True)
                ]
            })
        elif name == "shadowtls":
            # ShadowTLS: TLS passthrough -> dial sing-box shadowtls directly
            l4_routes.append({
                "match": [{"tls": {"sni": [domain]}}],
                "handle": [
                    _proxy_handler(f"127.0.0.1:{port}", preserve_source=True)
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
                                    _proxy_handler(f"127.0.0.1:{port}", preserve_source=True)
                                ]
                            },
                            {
                                "handle": [
                                    _proxy_handler(f"127.0.0.1:{decoy_port}", preserve_source=True)
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
                    _proxy_handler(f"127.0.0.1:{decoy_port}", preserve_source=True)
                ]
            })
        elif name == "hysteria2":
            # Browsers probe TCP/443, while Hysteria2 itself listens on UDP.
            # Terminate regular HTTPS here and serve the same decoy used by
            # the protocol's native HTTP/3 masquerade.
            decoy_port = _DECOY_HTTP_PORTS["hysteria2"]
            l4_routes.append({
                "match": [{"tls": {"sni": [domain]}}],
                "handle": [
                    {"handler": "tls"},
                    _proxy_handler(f"127.0.0.1:{decoy_port}", preserve_source=True)
                ]
            })
        elif name == "sub_server":
            # Subscription server route: simple TCP proxy to sub_server port (no termination here)
            l4_routes.append({
                "match": [{"tls": {"sni": [domain]}}],
                "handle": [
                    _proxy_handler(f"127.0.0.1:{port}")
                ]
            })

    # Default fallback route for unrecognized SNI (routes to anytls decoy or trusttunnel decoy)
    fallback_backend = next((b for b in backends if b["name"] in ("anytls", "trusttunnel")), None)
    if fallback_backend:
        decoy_port = _DECOY_HTTP_PORTS[fallback_backend["name"]]
        l4_routes.append({
            "handle": [
                {"handler": "tls"},
                _proxy_handler(f"127.0.0.1:{decoy_port}", preserve_source=True)
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

    # Raw UDP proxy. Это не QUIC-SNI multiplexer: UDP/443 может иметь только
    # одного владельца, выбранного get_quic_owner().
    quic_owner = get_quic_owner(state)
    if quic_owner:
        quic_backend = next(
            (b for b in backends if b["name"] == quic_owner), None,
        )
        if not quic_backend:
            raise ValueError(f"QUIC backend {quic_owner} отсутствует в Caddy config")
        quic_routes = [{
            "handle": [
                _proxy_handler(
                    f"udp/127.0.0.1:{quic_backend['port']}",
                    preserve_source=quic_backend["name"] in _SOURCE_PRESERVED_BACKENDS,
                )
            ]
        }]
        l4_app["servers"]["quic_mux"] = {
            "listen": ["udp/:443"],
            "routes": quic_routes
        }

    # 4. HTTP app (decoy websites & forward_proxy)
    http_servers = {
        "https_redirect": {
            "listen": [":80"],
            "automatic_https": {
                "disable": True,
                "disable_redirects": True
            },
            "routes": [
                {
                    "handle": [
                        {
                            "handler": "static_response",
                            "status_code": 308,
                            "headers": {
                                "Location": [
                                    "https://{http.request.host}{http.request.uri}"
                                ]
                            }
                        }
                    ]
                }
            ]
        }
    }

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

    # Hysteria2 browser-visible HTTPS decoy. The Hysteria2 inbound continues
    # to serve this directory itself for authenticated-layer HTTP/3 probes.
    if any(b["name"] == "hysteria2" for b in backends):
        hysteria2_backend = next(b for b in backends if b["name"] == "hysteria2")
        http_servers["hysteria2_decoy"] = {
            "listen": [f"127.0.0.1:{_DECOY_HTTP_PORTS['hysteria2']}"],
            "automatic_https": {
                "disable": True,
                "disable_redirects": True
            },
            "routes": [
                {
                    "handle": [
                        {"handler": "file_server", "root": "/var/www/decoy-hysteria2"}
                    ]
                }
            ],
            "logs": {
                "logger_names": {hysteria2_backend["domain"]: "decoy"}
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


def _has_source_preservation(config: dict) -> bool:
    if isinstance(config, dict):
        if config.get("local_address") == ["{l4.conn.remote_addr}"]:
            return True
        return any(_has_source_preservation(value) for value in config.values())
    if isinstance(config, list):
        return any(_has_source_preservation(value) for value in config)
    return False


def _source_preservation_ports(backends: list[dict], quic_owner: str | None) -> tuple[set[int], set[int]]:
    if not SOURCE_PRESERVATION_ENABLED:
        return set(), set()
    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()
    names = {backend["name"] for backend in backends}
    if "naive" in names:
        tcp_ports.add(_INTERNAL_PORTS["naive"])
    if "anytls" in names:
        tcp_ports.update((_INTERNAL_PORTS["anytls"], _DECOY_HTTP_PORTS["anytls"]))
    if "trusttunnel" in names:
        # TCP terminates at this HTTP server. Its access log supplies the
        # original address for the TrustTunnel 407 authentication jail.
        tcp_ports.add(_DECOY_HTTP_PORTS["trusttunnel"])
    if quic_owner in _SOURCE_PRESERVED_BACKENDS:
        udp_ports.add(_INTERNAL_PORTS[quic_owner])
    return tcp_ports, udp_ports


def _restore_previous_caddy_binary() -> bool:
    backup = CADDY_BIN.with_suffix(".previous")
    if not backup.exists():
        return False
    rollback = CADDY_BIN.with_suffix(".failed")
    try:
        if CADDY_BIN.exists():
            CADDY_BIN.replace(rollback)
        shutil.copy2(backup, CADDY_BIN)
        CADDY_BIN.chmod(0o755)
        rollback.unlink(missing_ok=True)
        return True
    except OSError:
        if rollback.exists() and not CADDY_BIN.exists():
            rollback.replace(CADDY_BIN)
        return False


def _install_source_service(tcp_ports: set[int], udp_ports: set[int]) -> None:
    tcp = ",".join(str(port) for port in sorted(tcp_ports))
    udp = ",".join(str(port) for port in sorted(udp_ports))
    project_root = Path(__file__).resolve().parent.parent.parent
    unit = f"""[Unit]
Description=Hydra Caddy source-address reply routing
After=network-online.target
Before={SERVICE_NAME}.service

[Service]
Type=oneshot
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
ExecStart=/usr/bin/python3 -m hydra.core.source_transparency apply --tcp {tcp} --udp {udp}
ExecStop=/usr/bin/python3 -m hydra.core.source_transparency clear
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    SOURCE_SERVICE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SOURCE_SERVICE_FILE.write_text(unit, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    result = subprocess.run(
        ["systemctl", "enable", SOURCE_SERVICE_NAME], capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot enable persistent Caddy source routing")


def _remove_source_service() -> None:
    subprocess.run(
        ["systemctl", "disable", "--now", SOURCE_SERVICE_NAME], capture_output=True,
    )
    SOURCE_SERVICE_FILE.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)


def _restore_unit_file(path: Path, content: bytes | None) -> None:
    if content is None:
        path.unlink(missing_ok=True)
    else:
        rollback = path.with_suffix(path.suffix + ".rollback")
        rollback.write_bytes(content)
        rollback.replace(path)


def rebuild(state: AppState) -> bool:
    """Rebuilds the Caddy L4 config and reloads/starts the service."""
    # Fail fast before touching files, firewall or services.
    quic_owner = get_quic_owner(state)
    had_quic_proxy = _caddy_config_had_quic_proxy()
    backends = _collect_backends(state)

    if not needs_mux(state):
        if had_quic_proxy and not quic_owner:
            from hydra.utils.firewall import close_udp
            close_udp(443, "udp-quic-mux")
        stop()
        return True

    # 1. Ensure Caddy L4 is installed
    if not is_installed():
        if not install(state=state):
            return False

    # 2. Ensure decoy site files exist
    from hydra.core.decoy import ensure_decoy_site
    for b in backends:
        if b["name"] not in ("sub_server", "shadowtls"):
            try:
                ensure_decoy_site(b["name"])
            except Exception as e:
                print(f"  Error generating decoy for {b['name']}: {e}")

    # 3. Generate configuration
    config = _generate_config(backends, state)
    CADDY_CFG_DIR.mkdir(parents=True, exist_ok=True)
    CADDY_LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    pending_config = CADDY_CFG.with_suffix(".json.pending")
    pending_config.write_text(json.dumps(config, indent=2), encoding="utf-8")

    # 4. Validate config
    upgraded_binary = False
    r = subprocess.run([
        str(CADDY_BIN), "validate", "--config", str(pending_config)
    ], capture_output=True, text=True)
    if r.returncode != 0 and "local_address" in f"{r.stderr}\n{r.stdout}":
        print("  Updating Caddy L4 for source-address preservation...")
        upgraded_binary = install(state=state, force=True)
        if upgraded_binary:
            r = subprocess.run([
                str(CADDY_BIN), "validate", "--config", str(pending_config)
            ], capture_output=True, text=True)
    if r.returncode != 0:
        if upgraded_binary:
            _restore_previous_caddy_binary()
        pending_config.unlink(missing_ok=True)
        print(f"  Caddy L4 config validation error: {r.stderr or r.stdout}")
        return False

    previous_config = CADDY_CFG.read_bytes() if CADDY_CFG.exists() else None
    previous_caddy_unit = SERVICE_FILE.read_bytes() if SERVICE_FILE.exists() else None
    previous_source_unit = SOURCE_SERVICE_FILE.read_bytes() if SOURCE_SERVICE_FILE.exists() else None
    previous_transparency = False
    if previous_config is not None:
        try:
            previous_transparency = _has_source_preservation(json.loads(previous_config))
        except (TypeError, ValueError):
            pass

    # Source routing must exist before Caddy opens a non-local backend socket.
    from hydra.core import source_transparency
    tcp_ports, udp_ports = _source_preservation_ports(backends, quic_owner)
    try:
        if tcp_ports or udp_ports:
            source_transparency.apply(tcp_ports, udp_ports)
            _install_source_service(tcp_ports, udp_ports)
        else:
            _remove_source_service()
            source_transparency.clear()
        if not _install_service(source_required=bool(tcp_ports or udp_ports)):
            raise RuntimeError("cannot install Caddy L4 systemd unit")
    except Exception as exc:
        if upgraded_binary:
            _restore_previous_caddy_binary()
        _restore_unit_file(SERVICE_FILE, previous_caddy_unit)
        _restore_unit_file(SOURCE_SERVICE_FILE, previous_source_unit)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        if not previous_transparency:
            _remove_source_service()
            source_transparency.clear()
        else:
            subprocess.run(["systemctl", "restart", SOURCE_SERVICE_NAME], capture_output=True)
        pending_config.unlink(missing_ok=True)
        print(f"  Caddy source-preservation routing error: {exc}")
        return False

    pending_config.replace(CADDY_CFG)

    # 5. Apply block-firewall rules for loopback isolation
    try:
        for b in backends:
            port = b["port"]
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
            if b["name"] == quic_owner:
                subprocess.run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
                subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", str(port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
        
        # Block decoy ports from external access too
        for decoy_port in _DECOY_HTTP_PORTS.values():
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(decoy_port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(decoy_port), "!", "-i", "lo", "-j", "DROP"], capture_output=True)
    except Exception:
        pass

    if quic_owner:
        from hydra.utils.firewall import open_udp
        open_udp(443, "udp-quic-mux")
    elif had_quic_proxy:
        from hydra.utils.firewall import close_udp
        close_udp(443, "udp-quic-mux")

    # 7. Enable and reload/restart service
    subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)
    r = subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
    if r.returncode == 0 and is_active():
        return True

    # A valid JSON configuration can still fail at runtime (for example due to
    # kernel routing support). Restore the exact prior Caddy config and service.
    try:
        if previous_config is None:
            CADDY_CFG.unlink(missing_ok=True)
        else:
            rollback = CADDY_CFG.with_suffix(".json.rollback")
            rollback.write_bytes(previous_config)
            rollback.replace(CADDY_CFG)
        subprocess.run(["systemctl", "restart", SERVICE_NAME], capture_output=True)
    finally:
        _restore_unit_file(SERVICE_FILE, previous_caddy_unit)
        _restore_unit_file(SOURCE_SERVICE_FILE, previous_source_unit)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        if upgraded_binary:
            _restore_previous_caddy_binary()
        if not previous_transparency:
            _remove_source_service()
            source_transparency.clear()
        else:
            subprocess.run(["systemctl", "restart", SOURCE_SERVICE_NAME], capture_output=True)
        if previous_config is not None:
            subprocess.run(["systemctl", "restart", SERVICE_NAME], capture_output=True)
    return False


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
    try:
        _remove_source_service()
        from hydra.core import source_transparency
        source_transparency.clear()
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


def _install_service(*, source_required: bool = False) -> bool:
    """Generates the systemd unit file for caddy-l4."""
    source_after = f" {SOURCE_SERVICE_NAME}.service" if source_required else ""
    source_requires = f"Requires={SOURCE_SERVICE_NAME}.service\n" if source_required else ""
    unit_content = f"""[Unit]
Description=Caddy L4 (TLS multiplexer + decoy)
After=network-online.target sing-box.service{source_after}
Wants=network-online.target
{source_requires}

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
        result = subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        return result.returncode == 0
    except OSError:
        return False
