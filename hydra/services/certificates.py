"""Non-interactive TLS certificate provisioning for application use-cases."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess
from typing import Protocol, Sequence

from hydra.core.errors import HostOperationError
from hydra.utils.firewall import temporary_open_port
from hydra.utils.tls import resolve_tls_material


class CertificateHost(Protocol):
    """Minimal host capability required by certificate provisioning."""

    def which(self, executable: str) -> str | None: ...

    def run(
        self,
        args: Sequence[object],
        **kwargs: object,
    ) -> CompletedProcess: ...


@dataclass(frozen=True)
class CertificateProvisioner:
    """Acquire TLS material without reading presentation input."""

    host: CertificateHost

    def ensure(self, domain: str, config: dict) -> tuple[str, str]:
        normalized = str(domain).strip().lower().rstrip(".")
        if (
            not normalized
            or "://" in normalized
            or any(character.isspace() for character in normalized)
        ):
            raise ValueError("Корректный домен обязателен для TLS")

        cert, key = self._existing(normalized, config)
        if cert and key:
            return cert, key
        if not self._obtain(normalized):
            raise RuntimeError(
                f"TLS-сертификат для {normalized} не найден и certbot завершился ошибкой",
            )
        cert, key = self._existing(normalized, {})
        if not cert or not key:
            raise RuntimeError(
                f"certbot не создал ожидаемый сертификат для {normalized}",
            )
        return cert, key

    def _obtain(self, domain: str) -> bool:
        if not self.host.which("certbot"):
            update = self.host.run(["apt-get", "update", "-qq"], timeout=120)
            install = self.host.run(
                ["apt-get", "install", "-y", "-qq", "certbot"],
                timeout=180,
            )
            if update.returncode != 0 or install.returncode != 0:
                return False

        stopped: list[str] = []
        services = ("caddy-l4", "caddy-naive", "nginx", "apache2")
        try:
            for service in services:
                status = self.host.run(
                    ["systemctl", "is-active", service],
                    capture_output=True,
                    text=True,
                )
                if str(status.stdout or "").strip() != "active":
                    continue
                result = self.host.run(
                    ["systemctl", "stop", service],
                    capture_output=True,
                )
                if result.returncode == 0:
                    stopped.append(service)

            with temporary_open_port("tcp", 80, "temp-certbot"):
                result = self.host.run(
                    [
                        "certbot",
                        "certonly",
                        "--standalone",
                        "-d",
                        domain,
                        "--non-interactive",
                        "--agree-tos",
                        "--register-unsafely-without-email",
                        "--keep-until-expiring",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
            return result.returncode == 0
        except (OSError, HostOperationError):
            return False
        finally:
            for service in stopped:
                self.host.run(
                    ["systemctl", "start", service],
                    capture_output=True,
                )

    @staticmethod
    def _existing(domain: str, config: dict) -> tuple[str, str]:
        cert, key = resolve_tls_material(domain, config)
        if cert and key and Path(cert).is_file() and Path(key).is_file():
            return cert, key
        return "", ""


__all__ = ["CertificateProvisioner", "resolve_tls_material"]
