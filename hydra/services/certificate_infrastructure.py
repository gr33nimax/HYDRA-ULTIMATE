"""Local Certbot inventory and bounded host operations for certificate maintenance."""
from __future__ import annotations

import configparser
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from hydra.core.host import HostBackend
from hydra.core.state_models import AppState
from hydra.services.certificate_audit import CertificateInspection
from hydra.services.certificate_files import CertificateFiles, CertificateSnapshot
from hydra.services.certificate_management import IssuedCertificate


TLS_SERVICES = ("caddy-l4", "caddy-naive", "nginx", "apache2", "haproxy", "sing-box", "hydra-sub")
FRONTENDS = frozenset(TLS_SERVICES[:5])


@dataclass(frozen=True)
class CertificateInfrastructure:
    host: HostBackend
    files: CertificateFiles
    inspector: CertificateInspection
    open_http: Callable[[], AbstractContextManager]

    def inventory(self, state: AppState) -> list[IssuedCertificate]:
        self.files.scopes("validation")
        names = set()
        for directory in ("live", "archive"):
            names.update(path.name for path in (self.files.root / directory).glob("*") if path.is_dir())
        names.update(path.stem for path in (self.files.root / "renewal").glob("*.conf"))
        if len(names) > 1024:
            raise ValueError("Слишком много сертификатов в каталоге Certbot")
        entries = [self._record(name, state) for name in sorted(names)]
        managed_paths = {str(path) for name in names for path in self.files.scopes(name)[:2]}
        for status in self.inspector.inspect(state):
            path = Path(status.certificate)
            if any(path.is_relative_to(Path(directory)) for directory in managed_paths):
                continue
            entries.append(IssuedCertificate(f"external:{status.owner}", (status.domain,), status.certificate,
                                             status.status, status.detail, status.days_left, (status.owner,), False))
        return entries

    def _record(self, name: str, state: AppState) -> IssuedCertificate:
        live, _, renewal = self.files.scopes(name)
        domains: tuple[str, ...] = ()
        expires, days_left, status = "", None, "unreadable"
        try:
            certificate = x509.load_pem_x509_certificate(self.files.read(name, "fullchain.pem"))
            domains = tuple(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
            expiry = certificate.not_valid_after_utc
            days_left = (expiry - datetime.now(timezone.utc)).days
            expires = expiry.isoformat()
            status = "expired" if days_left < 0 else "expiring" if days_left <= 30 else "ok"
            self.files.read(name, "privkey.pem")
        except FileNotFoundError:
            status = "missing"
        except (ValueError, OSError, x509.ExtensionNotFound):
            status = "unreadable"
        return IssuedCertificate(name, domains, str(live / "fullchain.pem"), status, expires, days_left,
                                 self._used_by(name, state), renewal.is_file() and not renewal.is_symlink())

    def _used_by(self, name: str, state: AppState) -> tuple[str, ...]:
        scopes = self.files.scopes(name)[:2]

        def belongs(path: Path) -> bool:
            try:
                return any(path.is_relative_to(scope) or path.resolve().is_relative_to(scope) for scope in scopes)
            except (OSError, RuntimeError):
                return False

        def default(domain: str) -> Path:
            return self.files.root / "live" / domain.strip().lower().rstrip(".") / "fullchain.pem"

        uses = set()
        for owner, protocol in state.protocols.items():
            config = protocol.config or {}
            cert, key = (str(config.get(field, "")).strip() for field in ("cert_file", "key_file"))
            paths = [Path(cert), Path(key)] if cert and key else [
                default(str(config[field])) for field in ("domain", "origin_domain", "web_domain") if config.get(field)
            ]
            if any(belongs(path) for path in paths):
                uses.add(owner if protocol.enabled else f"{owner} (отключён)")
        if state.network.sub_domain:
            subscription = default(state.network.sub_domain)
        else:
            domains = [state.network.domain, *(str(p.config.get("domain", "")) for p in state.protocols.values())]
            subscription = next((default(domain) for domain in domains if domain and default(domain).is_file()
                                 and default(domain).with_name("privkey.pem").is_file()), None)
        if subscription is not None and belongs(subscription):
            uses.add("subscriptions")
        return tuple(sorted(uses))

    def snapshot(self, name: str) -> CertificateSnapshot:
        self._renewal(name)
        return self.files.snapshot(name)

    def restore(self, snapshot: CertificateSnapshot) -> None:
        self.files.restore(snapshot)

    def _renewal(self, name: str) -> configparser.RawConfigParser:
        live, archive, renewal = self.files.scopes(name)
        try:
            text = self.host.read_bytes(renewal, max_bytes=128 * 1024).decode("utf-8")
            config = configparser.RawConfigParser()
            config.read_string("[lineage]\n" + text)
            values = [Path(config.get("lineage", key)) for key in ("archive_dir", "cert", "privkey", "chain", "fullchain")]
        except (configparser.Error, UnicodeError) as exc:
            raise ValueError("Некорректный renewal config сертификата") from exc
        for value in values:
            if not value.is_absolute() or not any(value.resolve().is_relative_to(scope) for scope in (live, archive)):
                raise ValueError("Renewal config ссылается за пределы lineage")
        return config

    def active_services(self) -> tuple[str, ...]:
        active = []
        for unit in TLS_SERVICES:
            result = self.host.run(["systemctl", "is-active", unit], text=True, timeout=10)
            if result.returncode == 0 and str(result.stdout).strip() == "active":
                active.append(unit)
            elif result.returncode not in (0, 3, 4):
                raise RuntimeError(f"Не удалось проверить службу {unit}")
        return tuple(active)

    def reissue(self, certificate: IssuedCertificate, active: tuple[str, ...], touched: set[str]) -> None:
        if not self.host.which("certbot"):
            raise RuntimeError("Certbot не установлен")
        config = self._renewal(certificate.name)
        hooks = ("pre_hook", "post_hook", "renew_hook", "deploy_hook", "manual_auth_hook", "manual_cleanup_hook")
        if any(config.get("renewalparams", key, fallback="").strip() for key in hooks):
            raise RuntimeError("Пользовательские hooks Certbot требуют ручного обслуживания вне HYDRA")
        installer = config.get("renewalparams", "installer", fallback="none").strip().lower()
        authenticator = config.get("renewalparams", "authenticator", fallback="").strip().lower()
        if installer not in ("none", "") or authenticator in {"nginx", "apache", "manual"}:
            raise RuntimeError("Installer/интерактивный authenticator Certbot требует ручного обслуживания вне HYDRA")
        standalone = authenticator == "standalone"
        stopped = set()
        try:
            previous = self.files.read(certificate.name, "fullchain.pem")
        except FileNotFoundError:
            previous = b""
        with self.open_http() if standalone else nullcontext():
            if standalone:
                for unit in active:
                    if unit in FRONTENDS:
                        touched.add(unit)
                        stopped.add(unit)
                        self._unit("stop", unit)
            self._certbot("renew", certificate.name, ["--force-renewal", "--no-random-sleep-on-renew"])
            new = self.files.read(certificate.name, "fullchain.pem")
            self._validate_pair(certificate, new)
            if new == previous:
                raise RuntimeError("Certbot не изменил сертификат при принудительном перевыпуске")
            for unit in active:
                if unit in stopped or certificate.used_by:
                    touched.add(unit)
                    self._unit("restart", unit)

    def _validate_pair(self, original: IssuedCertificate, content: bytes) -> None:
        certificate = x509.load_pem_x509_certificate(content)
        key = serialization.load_pem_private_key(self.files.read(original.name, "privkey.pem"), password=None)
        encoding = serialization.Encoding.DER
        form = serialization.PublicFormat.SubjectPublicKeyInfo
        now = datetime.now(timezone.utc)
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise RuntimeError("Новый сертификат недействителен")
        if certificate.public_key().public_bytes(encoding, form) != key.public_key().public_bytes(encoding, form):
            raise RuntimeError("Новый сертификат не соответствует закрытому ключу")
        domains = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        if not set(original.domains).issubset(domains):
            raise RuntimeError("Новый сертификат не покрывает прежние домены")

    def restore_services(self, active: tuple[str, ...], touched: set[str]) -> None:
        failures = []
        for unit in reversed(active):
            if unit not in touched:
                continue
            try:
                self._unit("restart", unit)
            except Exception:
                failures.append(unit)
        if failures:
            raise RuntimeError("Не удалось восстановить службы: " + ", ".join(failures))

    def delete(self, name: str) -> None:
        self._renewal(name)
        self._certbot("delete", name, [])
        if any(path.exists() or path.is_symlink() for path in self.files.scopes(name)):
            raise RuntimeError("Certbot оставил файлы удаляемого сертификата")

    def _unit(self, action: str, unit: str) -> None:
        result = self.host.run(["systemctl", action, unit], timeout=30)
        if result.returncode:
            raise RuntimeError(f"systemctl {action} {unit}: код {result.returncode}")
        if action == "restart":
            status = self.host.run(["systemctl", "is-active", unit], text=True, timeout=10)
            if status.returncode or str(status.stdout).strip() != "active":
                raise RuntimeError(f"TLS-служба {unit} неактивна после перезапуска")

    def _certbot(self, action: str, name: str, options: list[str]) -> None:
        self.files.scopes(name)
        if not self.host.which("certbot"):
            raise RuntimeError("Certbot не установлен")
        result = self.host.run(["certbot", action, "--cert-name", name, "--config-dir", str(self.files.root),
                                "--config", "/dev/null", "--no-directory-hooks", "--non-interactive", *options],
                               text=True, timeout=240)
        if result.returncode:
            # Certbot logs can contain hook/plugin secrets; don't return raw output to adapters.
            raise RuntimeError(f"Certbot {action} завершился с кодом {result.returncode}; подробности в журнале Certbot")
