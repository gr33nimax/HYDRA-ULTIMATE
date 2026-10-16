"""Certificate inventory and explicit, transactional operator maintenance."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from hydra.core.apply_transaction import ApplyTransaction
from hydra.core.state_models import AppState
from hydra.services.admin import AdminCommandResult
from hydra.services.certificate_audit import CertificateInspection, CertificateStatus, UnavailableCertificateInspection
from hydra.services.certificate_files import CertificateSnapshot
from hydra.services.creator_lock_infrastructure import CreatorFileLock


@dataclass(frozen=True)
class IssuedCertificate:
    name: str
    domains: tuple[str, ...]
    certificate: str
    status: str
    expires: str = ""
    days_left: int | None = None
    used_by: tuple[str, ...] = ()
    managed: bool = True


class CertificateManagement(CertificateInspection, Protocol):
    def inventory(self) -> list[IssuedCertificate]: ...
    def reissue(self, name: str) -> AdminCommandResult: ...
    def delete(self, name: str, *, confirmation: str) -> AdminCommandResult: ...


class UnavailableCertificateManagement(UnavailableCertificateInspection):
    def inventory(self) -> list[IssuedCertificate]:
        raise RuntimeError("Управление сертификатами не настроено")

    def reissue(self, name: str) -> AdminCommandResult:
        return AdminCommandResult(False, "unavailable", "Управление сертификатами не настроено")

    def delete(self, name: str, *, confirmation: str) -> AdminCommandResult:
        return self.reissue(name)


class CertificateRuntime(Protocol):
    def inventory(self, state: AppState) -> list[IssuedCertificate]: ...
    def snapshot(self, name: str) -> CertificateSnapshot: ...
    def restore(self, snapshot: CertificateSnapshot) -> None: ...
    def active_services(self) -> tuple[str, ...]: ...
    def reissue(self, certificate: IssuedCertificate, active: tuple[str, ...], touched: set[str]) -> None: ...
    def restore_services(self, active: tuple[str, ...], touched: set[str]) -> None: ...
    def delete(self, name: str) -> None: ...


@dataclass(frozen=True)
class CertificateManager:
    inspector: CertificateInspection
    runtime: CertificateRuntime
    read_state: Callable[[], AppState]
    lock: CreatorFileLock
    journal: Callable[..., None]

    def inspect(self, state: AppState) -> list[CertificateStatus]:
        return self.inspector.inspect(state)

    def inventory(self) -> list[IssuedCertificate]:
        return self.runtime.inventory(self.read_state())

    def reissue(self, name: str) -> AdminCommandResult:
        return self._change("reissue", name)

    def delete(self, name: str, *, confirmation: str) -> AdminCommandResult:
        if confirmation != name or not name:
            return AdminCommandResult(False, "confirmation_required", "Для удаления введите точное имя сертификата")
        return self._change("delete", name)

    def _change(self, operation: str, name: str) -> AdminCommandResult:
        try:
            lease = self.lock.try_acquire()
        except OSError:
            return AdminCommandResult(False, "lock_failed", "Не удалось получить блокировку конфигурации")
        if lease is None:
            return AdminCommandResult(False, "busy", "Другая операция с конфигурацией уже выполняется")
        transaction = ApplyTransaction()
        try:
            # Refresh under the apply lock: never trust stale menu ownership or paths.
            certificate = next((item for item in self.inventory() if item.name == name), None)
            if certificate is None or not certificate.managed:
                return AdminCommandResult(False, "unmanaged", "Сертификат не найден или не управляется Certbot")
            snapshot = self.runtime.snapshot(name)
            active = self.runtime.active_services() if operation == "reissue" else ()
            touched: set[str] = set()
            self.journal("certificate_started", operation=operation, certificate=name)
            transaction.add_rollback("TLS lineage", lambda: self.runtime.restore(snapshot), priority=10)
            transaction.add_rollback("TLS services", lambda: self.runtime.restore_services(active, touched), priority=20)
            transaction.advance("mutate")
            if operation == "delete":
                self.runtime.delete(name)
            else:
                self.runtime.reissue(certificate, active, touched)
            self.journal("certificate_committed", operation=operation, certificate=name)
            transaction.commit()
            message = "Сертификат перевыпущен; работающие TLS-службы обновлены" if operation == "reissue" else "Сертификат удалён из Certbot; настройки протоколов не изменены"
            return AdminCommandResult(True, operation, message)
        except Exception as exc:
            failures = transaction.rollback()
            message = f"Операция не выполнена: {str(exc)[:300]}"
            try:
                self.journal("certificate_failed", operation=operation, certificate=name,
                             error=str(exc)[:300], rollback_failed=[item.action for item in failures])
            except Exception:
                message += "; журнал операции недоступен"
            if failures:
                message += "; откат не завершён — проверьте TLS-файлы и службы"
            return AdminCommandResult(False, "rollback_failed" if failures else "operation_failed", message)
        finally:
            lease.release()
