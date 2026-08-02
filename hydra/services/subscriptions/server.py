"""HTTPS adapter for serving generated subscriptions."""
from __future__ import annotations

import json
import ipaddress
import re
import ssl
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from hydra.core.state import load_state
from hydra.core.state_models import AppState
from hydra.services.subscriptions.access import SubscriptionPluginAccess
from hydra.services.subscriptions.certificates import find_any_cert
from hydra.services.subscriptions.client_configs import (
    generate_nekobox_sub,
    generate_singbox_config,
    generate_throne_sub,
)
from hydra.services.subscriptions.proxy_protocol import read_source_address
from hydra.services.subscriptions.devices import (
    hydrabox_client_fingerprint,
    register_subscription_device,
    subscription_fingerprint,
)
from hydra.services.subscriptions.links import generate_base64_sub
from hydra.services.subscriptions.hydrabox import (
    HYDRABOX_MEDIA_TYPE,
    generate_hydrabox_subscription,
)
from hydra.services.subscriptions.jwe import (
    JWE_MEDIA_TYPE,
    encrypt_hydrabox_subscription,
)
from hydra.services.subscriptions.metadata import (
    SUPPORTED_SUBSCRIPTION_FORMATS,
    generate_userinfo_header,
    is_user_valid,
    resolve_subscription_format,
)


class SubscriptionHandler(BaseHTTPRequestHandler):
    """HTTP handler with explicitly configured plugin access."""

    plugins: SubscriptionPluginAccess | None = None

    def log_message(self, format, *args):
        del format, args

    def finish(self) -> None:
        try:
            if hasattr(self.request, "unwrap"):
                self.request.settimeout(1.0)
                self.request.unwrap()
        except Exception:
            pass
        try:
            super().finish()
        except Exception:
            pass

    def _send_error(self, code: int, message: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(message.encode())

    def _subscription(
        self,
        response_format: str,
        user,
        state: AppState,
        plugins: SubscriptionPluginAccess,
    ) -> tuple[str, str, str]:
        if response_format == "nekobox":
            return (
                generate_nekobox_sub(user, state, plugins=plugins),
                "text/plain; charset=utf-8",
                "nekobox.txt",
            )
        if response_format == "throne":
            return (
                generate_throne_sub(user, state, plugins=plugins),
                "text/plain; charset=utf-8",
                "throne.txt",
            )
        if response_format in ("singbox", "sing-box", "json"):
            content = json.dumps(
                generate_singbox_config(user, state, plugins=plugins),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            return content, "application/json; charset=utf-8", "singbox.json"
        if response_format == "hydrabox":
            content = encrypt_hydrabox_subscription(
                generate_hydrabox_subscription(
                    user,
                    state,
                    plugins=plugins,
                ),
                user.hydrabox_jwe_key,
            )
            return (
                content,
                JWE_MEDIA_TYPE,
                "subscription.hbx.jwe.json",
            )
        return (
            generate_base64_sub(user, state, plugins=plugins),
            "text/plain; charset=utf-8",
            "sub.txt",
        )

    def do_GET(self):
        plugins = self.plugins
        if plugins is None:
            self._send_error(503, "Subscription service is not configured")
            return
        request = urllib.parse.urlparse(self.path)
        parameters = urllib.parse.parse_qs(request.query)
        requested_format = parameters.get("format", [None])[0]
        if not requested_format and HYDRABOX_MEDIA_TYPE in self.headers.get(
            "Accept",
            "",
        ).lower():
            requested_format = "hydrabox"
        response_format = resolve_subscription_format(
            requested_format,
            self.headers.get("User-Agent", ""),
        )
        if response_format not in SUPPORTED_SUBSCRIPTION_FORMATS:
            self._send_error(400, "Unsupported subscription format")
            return

        parts = request.path.strip("/").split("/")
        token = (
            parts[1]
            if len(parts) >= 2 and parts[0] == "sub"
            else parameters.get("token", [None])[0]
        )
        if not token:
            self._send_error(404, "Not found")
            return

        client_ip = str(self.client_address[0] if self.client_address else "")
        try:
            fingerprint = (
                hydrabox_client_fingerprint(self.headers, client_ip)
                if response_format == "hydrabox"
                else subscription_fingerprint(
                    self.headers,
                    client_ip,
                    parameters,
                )
            )
        except ValueError as exc:
            self._send_error(400, str(exc))
            return
        state, _, device_status = register_subscription_device(
            token,
            fingerprint,
        )
        if device_status == "limit":
            self._send_error(403, "Device limit reached")
            return

        user = next(
            (
                candidate
                for candidate in state.users
                if candidate.uuid == token and is_user_valid(candidate, state)
            ),
            None,
        )
        if user is None:
            self._send_error(403, "Invalid, expired or blocked token")
            return

        try:
            content, content_type, suffix = self._subscription(
                response_format,
                user,
                state,
                plugins,
            )
        except Exception:
            self._send_error(500, "Subscription generation failed")
            return
        safe_email = (
            re.sub(r"[^A-Za-z0-9._@+-]+", "_", user.email).strip("._")
            or "user"
        )
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if response_format == "hydrabox":
            self.send_header("Cache-Control", "private, no-store")
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="hydra-{safe_email}-{suffix}"',
        )
        self.send_header(
            "Subscription-Userinfo",
            generate_userinfo_header(user, state),
        )
        self.send_header("Profile-Update-Interval", "6")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))


def _is_loopback(address: tuple[object, ...]) -> bool:
    try:
        return ipaddress.ip_address(str(address[0])).is_loopback
    except ValueError:
        return False


class _ProxyTLSHTTPServer(HTTPServer):
    """Consume a trusted PROXY preamble before starting the TLS handshake."""

    def __init__(
        self,
        server_address,
        handler_class,
        tls_context: ssl.SSLContext,
    ) -> None:
        self.tls_context = tls_context
        super().__init__(server_address, handler_class)

    def get_request(self):
        connection, address = super().get_request()
        try:
            source = (
                read_source_address(connection)
                if _is_loopback(address)
                else None
            )
            tls_connection = self.tls_context.wrap_socket(
                connection,
                server_side=True,
            )
        except Exception:
            connection.close()
            raise
        return tls_connection, source or address


def run_standalone(
    plugins: SubscriptionPluginAccess,
    host: str = "0.0.0.0",
    port: int = 9443,
) -> None:
    """Run the HTTPS subscription adapter with explicit plugin access."""
    state = load_state()
    SubscriptionHandler.plugins = plugins

    certificate, key = find_any_cert(state)
    if not certificate or not key:
        print(
            "ERROR: SSL certificates not found! "
            "Subscription server requires HTTPS/TLS.",
        )
        return

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certificate, keyfile=key)
    except Exception as exc:
        print(f"Failed to wrap socket with SSL: {exc}")
        return

    try:
        server = _ProxyTLSHTTPServer(
            (host, port),
            SubscriptionHandler,
            context,
        )
    except OSError as exc:
        print(f"Failed to bind subscription server to {host}:{port}: {exc}")
        return

    print(f"SSL/HTTPS enabled using cert: {certificate}")
    print(f"Starting subscription server on https://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    print("Server stopped.")
