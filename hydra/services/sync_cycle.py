"""Independent phases of one background synchronization cycle."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

from hydra.core.state_models import AppState, User
from hydra.services.sync_ports import SyncOperations


ResultT = TypeVar("ResultT")
StateMutator = Callable[[AppState], ResultT]
StateUpdater = Callable[
    [StateMutator[Any]],
    tuple[AppState, Any],
]
Logger = Callable[[str], None]


def _restriction_reason(
    user: User,
    exceeded: set[str],
    now: datetime,
    log: Logger,
) -> str:
    if user.email in exceeded:
        return "traffic limit exceeded"
    if not user.expiry_date:
        return ""
    try:
        value = user.expiry_date
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        expiry = datetime.fromisoformat(value)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return "subscription expired" if expiry <= now else ""
    except (TypeError, ValueError):
        log(f"User {user.email} has an invalid expiry date")
        return ""


def _sync_user_limits(
    state: AppState,
    *,
    enabled: bool,
    now: datetime,
    operations: SyncOperations,
    update_state: StateUpdater,
    log: Logger,
) -> tuple[AppState, dict[str, str], list[str]]:
    if not enabled:
        log("Sync: User limits check is disabled by settings")
        return state, {}, []

    def refresh_and_block(latest: AppState) -> dict[str, str]:
        exceeded = set(operations.check_traffic_limits(latest))
        blocked_users: dict[str, str] = {}
        for user in latest.users:
            if user.blocked:
                continue
            reason = _restriction_reason(user, exceeded, now, log)
            if reason:
                user.blocked = True
                blocked_users[user.email] = reason
        if blocked_users:
            latest.install["sync_config_pending"] = True
        return blocked_users

    state, blocked = update_state(refresh_and_block)
    failures: list[str] = []
    for email, reason in blocked.items():
        log(f"User {email} blocked: {reason}")
        user = next(
            (item for item in state.users if item.email == email),
            None,
        )
        if user is None:
            continue
        for failure in operations.protocols.notify_user_block(state, user):
            log(f"Plugin block hook failed for {email}: {failure}")
            failures.append(f"плагин {failure}")
    return state, blocked, failures


def _elapsed_seconds(timestamp: str) -> float:
    value = datetime.fromisoformat(timestamp)
    now = datetime.now(value.tzinfo) if value.tzinfo else datetime.now()
    return (now - value).total_seconds()


def _sync_plugin_maintenance(
    state: AppState,
    *,
    forced: bool,
    operations: SyncOperations,
    update_state: StateUpdater,
    log: Logger,
) -> tuple[AppState, list[str]]:
    outcomes = operations.run_maintenance(state, forced)
    failures: list[str] = []
    apply_required = False
    for outcome in outcomes:
        title = outcome.job.title
        if outcome.status == "disabled":
            log(f"{title}: disabled by settings")
        elif outcome.status == "plugin_disabled":
            log(f"{title}: plugin is disabled")
        elif outcome.status == "fresh":
            log(f"{title}: no update is due")
        elif outcome.status == "success":
            detail = f": {outcome.message}" if outcome.message else ""
            log(f"{title}: completed{detail}")
            apply_required = apply_required or outcome.apply_required
        else:
            detail = outcome.message or "unknown error"
            log(f"{title}: failed: {detail}")
            failures.append(f"{title}: {detail}")
    if apply_required:
        def mark_pending(latest: AppState) -> None:
            latest.install["sync_config_pending"] = True

        state, _ = update_state(mark_pending)
        log("Plugin maintenance queued a server config apply")
    return state, failures


def _certificates_due(state: AppState, *, forced: bool) -> bool:
    if forced:
        return True
    last_check = state.install.get("certificates_last_check")
    if not last_check:
        return True
    try:
        return _elapsed_seconds(str(last_check)) >= 86400
    except (TypeError, ValueError):
        return True


def _sync_certificates(
    state: AppState,
    *,
    enabled: bool,
    forced: bool,
    operations: SyncOperations,
    update_state: StateUpdater,
    log: Logger,
) -> tuple[AppState, list[str]]:
    """Audit every TLS certificate once a day and queue renewals."""
    from hydra.services.certificate_audit import summarize

    if not enabled and not forced:
        log("Sync: Certificate check is disabled by settings")
        return state, []
    if not _certificates_due(state, forced=forced):
        return state, []
    try:
        statuses = list(operations.inspect_certificates(state))
    except Exception as exc:
        log(f"Certificates: audit failed: {exc}")
        return state, [f"проверка сертификатов: {exc}"]

    renewable = [status for status in statuses if status.needs_renewal]
    for status in statuses:
        if status.status != "ok":
            log(f"Certificates: {status.describe()}")
    log(f"Certificates: {summarize(statuses)}")

    # Protocol certificates are reissued by the shared apply preflight; the
    # subscription endpoint is not a plugin and has to be renewed directly.
    by_apply = [
        status for status in renewable if status.owner != "subscriptions"
    ]
    failures = [
        failure
        for status in renewable
        if status.owner == "subscriptions"
        for failure in _renew_subscription(status, operations, log)
    ]

    def record(latest: AppState) -> None:
        latest.install["certificates_last_check"] = (
            datetime.now(timezone.utc).isoformat()
        )
        latest.install["certificates_report"] = [
            status.as_dict() for status in statuses
        ]
        if by_apply and not latest.install.get("sync_config_pending"):
            latest.install["sync_config_pending"] = True
            latest.install["sync_config_pending_source"] = "certificates"

    state, _ = update_state(record)
    if by_apply:
        log(
            "Certificates: queued a config apply to renew "
            + ", ".join(status.domain for status in by_apply),
        )
    return state, failures


def _renew_subscription(
    status: object,
    operations: SyncOperations,
    log: Logger,
) -> list[str]:
    """Reissue the subscription certificate and report a failure once."""
    domain = getattr(status, "domain", "")
    try:
        ok, message = operations.renew_subscription_certificate(domain)
    except Exception as exc:
        ok, message = False, str(exc) or exc.__class__.__name__
    if ok:
        log(f"Certificates: renewed the subscription certificate for {domain}")
        return []
    detail = message or "unknown error"
    log(f"Certificates: subscription renewal failed for {domain}: {detail}")
    return [f"обновление сертификата подписок: {detail}"]


def _apply_pending_config(
    state: AppState,
    *,
    operations: SyncOperations,
    update_state: StateUpdater,
    log: Logger,
) -> tuple[AppState, list[str]]:
    if not state.install.get("sync_config_pending"):
        return state, []
    try:
        applied = operations.apply(state)
    except Exception as exc:
        applied = False
        log(f"Server config apply failed: {exc}")
    if not applied:
        if state.install.get("sync_config_pending_source") == "certificates":
            # Certbot stops the TLS front end on every attempt and Let's
            # Encrypt rate-limits failed validations, so a failed renewal
            # waits for tomorrow's audit instead of retrying every cycle.
            def defer_renewal(latest: AppState) -> None:
                latest.install.pop("sync_config_pending", None)
                latest.install.pop("sync_config_pending_source", None)

            state, _ = update_state(defer_renewal)
            log(
                "Certificate renewal apply failed; deferred to the next "
                "daily check",
            )
            return state, [
                "не удалось обновить сертификаты",
            ]
        log("Server config apply failed; will retry on the next run")
        return state, [
            "не удалось применить конфигурацию сервера",
        ]

    def clear_pending(latest: AppState) -> bool:
        latest.install.pop("sync_config_pending_source", None)
        return latest.install.pop("sync_config_pending", None) is not None

    state, _ = update_state(clear_pending)
    log("Applied pending server config")
    return state, []


def _singbox_update_due(
    state: AppState,
    *,
    forced: bool,
) -> bool:
    if forced:
        return True
    last_check = state.install.get("singbox_last_update_check")
    if not last_check:
        return True
    try:
        return _elapsed_seconds(str(last_check)) >= 86400
    except (TypeError, ValueError):
        return True


def _sync_singbox_update(
    state: AppState,
    *,
    enabled: bool,
    forced: bool,
    update_state: StateUpdater,
    log: Logger,
) -> tuple[AppState, list[str]]:
    if not enabled and not forced:
        log("Sync: Sing-Box update check is disabled by settings")
        return state, []
    try:
        from hydra.core.singbox import (
            EXTENDED_REPO,
            get_version,
            parse_version,
        )
        from hydra.utils.downloader import latest_release

        if not _singbox_update_due(state, forced=forced):
            return state, []
        log("Sing-Box Update: Checking for updates...")
        latest_version = latest_release(EXTENDED_REPO)
        if not latest_version or latest_version == "unknown":
            log(
                "Sing-Box Update: Failed to get latest version from GitHub",
            )
            return state, [
                "не удалось получить последнюю версию Sing-Box",
            ]

        current_version = get_version()
        update_available = (
            parse_version(latest_version) > parse_version(current_version)
        )
        log(
            "Sing-Box Update: "
            f"Current version: {current_version}, "
            f"latest version on GitHub: {latest_version}, "
            f"update available: {update_available}",
        )

        def save_update_info(latest: AppState) -> bool:
            latest.install["singbox_last_update_check"] = (
                datetime.now(timezone.utc).isoformat()
            )
            latest.install["singbox_update_available"] = update_available
            latest.install["singbox_latest_version"] = latest_version
            return True

        state, _ = update_state(save_update_info)
        return state, []
    except Exception as exc:
        log(f"Sing-Box Update: Update check failed: {exc}")
        return state, [
            f"проверка обновления Sing-Box: {exc}",
        ]


def run_sync_cycle(
    state: AppState,
    *,
    operations: SyncOperations,
    update_state: StateUpdater,
    log: Logger,
    force_update_check: bool = False,
    force_all_checks: bool = False,
) -> tuple[bool, str]:
    """Run independent policy phases and combine their failures."""
    limits_enabled = force_all_checks or state.install.get(
        "sync_limits_enabled",
        True,
    )
    updates_enabled = force_all_checks or state.install.get(
        "sync_updates_enabled",
        True,
    )
    certificates_enabled = force_all_checks or state.install.get(
        "sync_certificates_enabled",
        True,
    )
    log(
        "Sync started"
        + (" (manual full check)" if force_all_checks else ""),
    )
    state, blocked, failures = _sync_user_limits(
        state,
        enabled=limits_enabled,
        now=datetime.now(timezone.utc),
        operations=operations,
        update_state=update_state,
        log=log,
    )
    state, phase_failures = _sync_plugin_maintenance(
        state,
        forced=force_all_checks,
        operations=operations,
        update_state=update_state,
        log=log,
    )
    failures.extend(phase_failures)
    state, phase_failures = _sync_certificates(
        state,
        enabled=certificates_enabled,
        forced=force_all_checks,
        operations=operations,
        update_state=update_state,
        log=log,
    )
    failures.extend(phase_failures)
    state, phase_failures = _apply_pending_config(
        state,
        operations=operations,
        update_state=update_state,
        log=log,
    )
    failures.extend(phase_failures)
    state, phase_failures = _sync_singbox_update(
        state,
        enabled=updates_enabled,
        forced=force_update_check,
        update_state=update_state,
        log=log,
    )
    failures.extend(phase_failures)

    summary = (
        f"Sync completed: newly blocked users={len(blocked)}, "
        f"config pending={bool(state.install.get('sync_config_pending'))}, "
        f"failures={len(failures)}"
    )
    log(summary)
    return (False, "; ".join(failures)) if failures else (True, summary)


__all__ = ["run_sync_cycle"]
