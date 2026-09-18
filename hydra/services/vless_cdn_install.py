"""Установка протокола VLESS через CDN: два имени и сертификат origin.

Пока сертификат для origin-имени не выпущен, установка не записывает в состояние
ничего. Маршрут строится из состояния, поэтому «нет состояния — нет маршрута»: при
сбое certbot на сервере не появляется опубликованный, но нерабочий вход.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from cryptography import x509

from hydra.core.host import HOST
from hydra.core.state_models import AppState, PluginState
from hydra.contracts.vless_cdn import (
    DEFAULT_ENCRYPTION_MODE,
    DEFAULT_XHTTP_PATH,
    PROTOCOL_NAME,
    as_int,
    generate_encryption_keypair,
    normalize_hostname,
    normalize_path,
)
from hydra.services.certificates import CertificateHost, CertificateProvisioner

PortAllocator = Callable[[], int]


class CertificateIssuer(Protocol):
    """То, что установке нужно от сервиса сертификатов.

    Установка не зависит от конкретного класса: в тестах достаточно подставить
    свой выдаватель, а в жизни используется сервис на реальном хосте.
    """

    def ensure(self, domain: str, config: dict) -> tuple[str, str]: ...


def host_provisioner() -> CertificateProvisioner:
    """Провижинер на реальном хосте — та же сборка, что в bootstrap.

    Хост умеет именно те вызовы, которые нужны сервису сертификатов; приведение
    типа фиксирует это на границе, где протокол описан шире реального API.
    """
    return CertificateProvisioner(cast(CertificateHost, HOST))


@dataclass(frozen=True)
class InstallOutcome:
    """Итог установки: либо отказ с причиной, либо всё, что нужно оператору."""

    ok: bool
    detail: str = ""
    cdn_domain: str = ""
    origin_host: str = ""
    xhttp_path: str = ""
    core_port: int = 0
    certificate_until: str = ""

    def lines(self) -> list[str]:
        """Строки для показа оператору."""
        if not self.ok:
            return [self.detail or "Установка не выполнена"]
        lines = [
            f"CDN-домен: {self.cdn_domain}",
            f"Origin-имя: {self.origin_host}",
            f"XHTTP путь: {self.xhttp_path}",
            f"Локальный порт ядра: {self.core_port}",
        ]
        if self.certificate_until:
            lines.append(f"Сертификат origin действует до: {self.certificate_until}")
        else:
            lines.append("Сертификат origin: срок прочитать не удалось")
        return lines


def pick_local_port() -> int:
    """Порт, свободный прямо сейчас: ядро слушает только localhost."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])
    except OSError as exc:
        raise RuntimeError(f"Не удалось подобрать свободный порт: {exc}") from exc


def certificate_not_after(cert_file: str) -> str:
    """Срок действия сертификата в читаемом виде либо пустая строка."""
    if not cert_file:
        return ""
    try:
        certificate = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
    except (OSError, ValueError):
        return ""
    return certificate.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC")


def install_protocol(
    state: AppState,
    *,
    cdn_domain: str,
    origin_host: str,
    xhttp_path: str | None = None,
    provisioner: CertificateIssuer | None = None,
    port_allocator: PortAllocator = pick_local_port,
) -> InstallOutcome:
    """Проверить входные данные, выпустить сертификат и только затем писать состояние."""
    try:
        cdn = normalize_hostname(cdn_domain, field="CDN-домен")
        origin = normalize_hostname(origin_host, field="Origin-имя")
        path = normalize_path(xhttp_path or DEFAULT_XHTTP_PATH)
    except ValueError as exc:
        return InstallOutcome(ok=False, detail=str(exc))

    if cdn == origin:
        return InstallOutcome(
            ok=False,
            detail="CDN-домен и origin-имя должны быть разными именами",
        )

    # Порт выбирается до похода за сертификатом: дешёвая проверка не должна идти
    # после дорогой операции, а отказ должен случаться до любых записей.
    protocol = state.protocols.get(PROTOCOL_NAME)
    existing_port = as_int(protocol.config.get("core_port")) if protocol else 0
    try:
        core_port = existing_port or port_allocator()
    except RuntimeError as exc:
        return InstallOutcome(ok=False, detail=str(exc))

    certificates = provisioner or host_provisioner()
    try:
        cert_file, key_file = certificates.ensure(origin, {})
    except (RuntimeError, ValueError) as exc:
        return InstallOutcome(ok=False, detail=f"Сертификат origin не выпущен: {exc}")

    if protocol is None:
        protocol = PluginState()
        state.protocols[PROTOCOL_NAME] = protocol

    config = protocol.config

    # Ключи выпускаются один раз: переустановка не должна молча обесценить уже
    # выданные клиентские профили.
    mode = str(config.get("encryption_mode") or DEFAULT_ENCRYPTION_MODE)
    private_key = str(config.get("encryption_private_key", "")).strip()
    public_key = str(config.get("encryption_public_key", "")).strip()
    if not (private_key and public_key):
        private_key, public_key = generate_encryption_keypair()

    protocol.config.update(
        {
            "cdn_domain": cdn,
            "origin_host": origin,
            "xhttp_path": path,
            "core_port": core_port,
            "cert_file": cert_file,
            "key_file": key_file,
            "encryption_mode": mode,
            "encryption_private_key": private_key,
            "encryption_public_key": public_key,
        },
    )
    return InstallOutcome(
        ok=True,
        cdn_domain=cdn,
        origin_host=origin,
        xhttp_path=path,
        core_port=core_port,
        certificate_until=certificate_not_after(cert_file),
    )


__all__ = [
    "CertificateIssuer",
    "InstallOutcome",
    "certificate_not_after",
    "host_provisioner",
    "install_protocol",
    "pick_local_port",
]
