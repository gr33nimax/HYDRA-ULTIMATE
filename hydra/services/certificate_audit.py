"""Read-only expiry audit of every TLS certificate the server relies on."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from hydra.core.errors import HostOperationError
from hydra.core.state_models import AppState
from hydra.services.certificates import CertificateHost
from hydra.utils.tls import resolve_tls_material


RENEW_BEFORE_DAYS = 30

STATUS_OK = "ok"
STATUS_EXPIRING = "expiring"
STATUS_EXPIRED = "expired"
STATUS_MISSING = "missing"
STATUS_UNREADABLE = "unreadable"

_ACTIONABLE = frozenset({STATUS_EXPIRING, STATUS_EXPIRED, STATUS_MISSING})


@dataclass(frozen=True)
class CertificateStatus:
    """One audited certificate and the reason it needs attention."""

    owner: str
    domain: str
    certificate: str
    status: str
    days_left: int | None = None
    detail: str = ""

    @property
    def needs_renewal(self) -> bool:
        return self.status in _ACTIONABLE

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    def describe(self) -> str:
        if self.status == STATUS_EXPIRED:
            return f"{self.domain} ({self.owner}): сертификат истёк"
        if self.status == STATUS_EXPIRING:
            return (
                f"{self.domain} ({self.owner}): истекает через "
                f"{self.days_left} дн."
            )
        if self.status == STATUS_MISSING:
            return f"{self.domain} ({self.owner}): {self.detail}"
        if self.status == STATUS_UNREADABLE:
            return f"{self.domain} ({self.owner}): {self.detail}"
        return f"{self.domain} ({self.owner}): {self.days_left} дн."


class CertificateReader(Protocol):
    """Filesystem capability the audit needs, isolated for tests."""

    def is_file(self, path: str) -> bool: ...


@dataclass(frozen=True)
class RealCertificateReader:
    def is_file(self, path: str) -> bool:
        return Path(path).is_file()


def collect_domains(state: AppState) -> list[tuple[str, str, dict]]:
    """Return (owner, domain, config) for every enabled TLS endpoint."""
    endpoints: list[tuple[str, str, dict]] = []
    seen: set[tuple[str, str]] = set()
    for name, protocol in sorted(state.protocols.items()):
        if not protocol.enabled:
            continue
        config = dict(protocol.config)
        owns_material = bool(
            str(config.get("cert_file", "")).strip()
            or str(config.get("key_file", "")).strip(),
        )
        # A protocol without its own domain audits the network domain only
        # when it actually stores certificate material for it; a transport
        # serving a borrowed handshake owns no certificate at all.
        domain = str(
            config.get("domain")
            or (getattr(state.network, "domain", "") if owns_material else "")
            or "",
        ).strip().lower().rstrip(".")
        if not domain:
            continue
        key = (domain, str(config.get("cert_file", "")))
        if key in seen:
            continue
        seen.add(key)
        endpoints.append((name, domain, config))

    sub_domain = str(
        getattr(state.network, "sub_domain", "") or "",
    ).strip().lower().rstrip(".")
    if sub_domain and not any(domain == sub_domain for _, domain, _ in endpoints):
        endpoints.append(("subscriptions", sub_domain, {}))
    return endpoints


@dataclass(frozen=True)
class CertificateInspector:
    """Report the expiry state of every certificate without changing it."""

    host: CertificateHost
    reader: CertificateReader = RealCertificateReader()
    renew_before_days: int = RENEW_BEFORE_DAYS

    def inspect(self, state: AppState) -> list[CertificateStatus]:
        now = datetime.now(timezone.utc)
        return [
            self._inspect_one(owner, domain, config, now)
            for owner, domain, config in collect_domains(state)
        ]

    def _inspect_one(
        self,
        owner: str,
        domain: str,
        config: dict,
        now: datetime,
    ) -> CertificateStatus:
        certificate, key = resolve_tls_material(domain, config)
        if not certificate or not key:
            return CertificateStatus(
                owner,
                domain,
                certificate,
                STATUS_MISSING,
                detail="TLS-материал не настроен",
            )
        for path in (certificate, key):
            if not self.reader.is_file(path):
                return CertificateStatus(
                    owner,
                    domain,
                    certificate,
                    STATUS_MISSING,
                    detail=f"файл отсутствует: {path}",
                )
        expires_at = self._expiry(certificate)
        if expires_at is None:
            return CertificateStatus(
                owner,
                domain,
                certificate,
                STATUS_UNREADABLE,
                detail="не удалось прочитать срок действия",
            )
        days_left = (expires_at - now).days
        if days_left < 0:
            status = STATUS_EXPIRED
        elif days_left <= self.renew_before_days:
            status = STATUS_EXPIRING
        else:
            status = STATUS_OK
        return CertificateStatus(
            owner,
            domain,
            certificate,
            status,
            days_left=days_left,
            detail=expires_at.date().isoformat(),
        )

    def _expiry(self, certificate: str) -> datetime | None:
        if not self.host.which("openssl"):
            return None
        try:
            result = self.host.run(
                [
                    "openssl",
                    "x509",
                    "-enddate",
                    "-noout",
                    "-in",
                    certificate,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, HostOperationError):
            return None
        if getattr(result, "returncode", 1) != 0:
            return None
        return parse_not_after(str(getattr(result, "stdout", "") or ""))


def parse_not_after(output: str) -> datetime | None:
    """Parse the ``notAfter=`` line printed by ``openssl x509 -enddate``."""
    _, separator, value = output.strip().partition("=")
    if not separator:
        return None
    text = value.strip().removesuffix(" GMT").strip()
    for pattern in ("%b %d %H:%M:%S %Y", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(text, pattern).replace(
                tzinfo=timezone.utc,
            )
        except ValueError:
            continue
    return None


class CertificateInspection(Protocol):
    """Application port exposing the certificate audit."""

    def inspect(self, state: AppState) -> list[CertificateStatus]: ...


@dataclass(frozen=True)
class UnavailableCertificateInspection:
    """Safe default for manually assembled application facades."""

    def inspect(self, state: AppState) -> list[CertificateStatus]:
        raise RuntimeError("certificate audit service is unavailable")


def summarize(statuses: list[CertificateStatus]) -> str:
    """Return one operator-facing line describing an audit run."""
    if not statuses:
        return "TLS-сертификаты: проверять нечего"
    problems = [status for status in statuses if status.needs_renewal]
    unreadable = [
        status for status in statuses if status.status == STATUS_UNREADABLE
    ]
    if not problems and not unreadable:
        soonest = min(
            (status.days_left for status in statuses if status.days_left is not None),
            default=None,
        )
        tail = f", ближайший истекает через {soonest} дн." if soonest is not None else ""
        return f"TLS-сертификаты: проверено {len(statuses)}, все действительны{tail}"
    return (
        f"TLS-сертификаты: проверено {len(statuses)}, "
        f"требуют внимания {len(problems) + len(unreadable)}"
    )


__all__ = [
    "RENEW_BEFORE_DAYS",
    "STATUS_EXPIRED",
    "STATUS_EXPIRING",
    "STATUS_MISSING",
    "STATUS_OK",
    "STATUS_UNREADABLE",
    "CertificateInspection",
    "CertificateInspector",
    "CertificateReader",
    "CertificateStatus",
    "RealCertificateReader",
    "UnavailableCertificateInspection",
    "collect_domains",
    "parse_not_after",
    "summarize",
]
