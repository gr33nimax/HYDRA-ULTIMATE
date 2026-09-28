"""Transactional full-pool Calls enable and rotation operation."""

from __future__ import annotations

import copy
from typing import Any, cast

from hydra.contracts.calls_configuration import (
    CALL_MODE_VK_PARASITE,
    CALL_COUNT,
    DEFAULT_CALL_PORT,
    call_mode,
    public_endpoint,
    workers as configured_workers,
)
from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.core.state_kernel_models import KERNEL_HYDRACORE
from hydra.core.state_models import get_protocol
from hydra.services.configuration import restore_state_in_place
from hydra.services.creator_sessions import CreatorSessionRequest
from hydra.utils.crypto import gen_token
from hydra.utils.net import public_ip


def run_native_transition(service: Any, state: Any, *, rotate: bool) -> ServiceResult:
    lease, failure = service._begin_operation()
    if failure is not None:
        return failure
    if state.kernel.provider != KERNEL_HYDRACORE:
        service._end_operation(lease)
        return failed_result(
            RuntimeError("native VK Calls require the Hydracore kernel; stock Sing-Box Extended is not supported"),
            fallback=ErrorCode.OPERATION_FAILED,
        )
    if not service._vk_parasite_supported():
        service._end_operation(lease)
        return failed_result(
            RuntimeError(
                "installed Hydracore does not expose the exact call_vk_parasite wire-v9 recovery capability contract"
            ),
            fallback=ErrorCode.OPERATION_FAILED,
        )
    try:
        call_mode(state)
    except ValueError as exc:
        service._end_operation(lease)
        return failed_result(exc)
    snapshot = copy.deepcopy(state)
    session_group = None
    close_error = ""
    finalized = False
    try:
        installer = getattr(service.runtime, "ensure_creator_installed", None)
        if callable(installer):
            installed_result = installer()
            if not isinstance(installed_result, tuple) or len(installed_result) != 2:
                raise RuntimeError("VK creator installer returned an invalid result")
            installed, install_message = installed_result
            if not installed:
                raise RuntimeError(str(install_message))
        desired = get_protocol(state, "calls")
        count = configured_workers(desired.config)
        desired.config.update(
            {
                "mode": CALL_MODE_VK_PARASITE,
                "listen_port": desired.config.get("listen_port", DEFAULT_CALL_PORT),
                "max_sessions_per_user": desired.config.get("max_sessions_per_user", 1),
                "workers": count,
                "public_endpoint": public_endpoint(state, public_ip),
            }
        )
        desired.config.pop("room_count", None)
        desired.config.pop("max_workers_per_session", None)
        desired.config.pop("read_buffer", None)
        desired.config.setdefault("obfs_password", gen_token(32))
        session_group = service.creator.create(
            CreatorSessionRequest(
                provider="vk",
                consumer="calls",
                lifetime="managed",
                count=CALL_COUNT,
                previous_tokens=tuple(service.runtime.load_native_join_tokens()),
            )
        )
        room_links = [endpoint.uri.strip() for endpoint in session_group.endpoints]
        if (
            len(room_links) != CALL_COUNT
            or any(not link or len(link) > 2048 for link in room_links)
            or len(set(room_links)) != CALL_COUNT
        ):
            raise RuntimeError("VK creator returned an incomplete Calls room pool")
        service.creator.commit(session_group)
        if not desired.installed:
            applied = service.protocols.activate(state, "calls")
        elif not desired.enabled:
            applied = service.protocols.enable(state, "calls")
        else:
            applied = service.apply_config(state)
        if not applied:
            raise RuntimeError(service.last_apply_error() or "failed to apply native VK Calls configuration")
        if not service.runtime.singbox_running():
            raise RuntimeError("Hydracore VK parasite listener is not running")
        service.creator.finalize(session_group)
        finalized = True
        result = ServiceResult(
            True,
            value={
                "operation": "rotate" if rotate else "enable",
                "profile": "admin",
                "mode": CALL_MODE_VK_PARASITE,
                "rooms": len(session_group.endpoints),
            },
        )
    except OSError as exc:
        result = _failed_transition(service, state, snapshot, session_group, finalized, exc)
    except RuntimeError as exc:
        result = _failed_transition(service, state, snapshot, session_group, finalized, exc)
    except ValueError as exc:
        result = _failed_transition(service, state, snapshot, session_group, finalized, exc)
    finally:
        service._end_operation(lease)
    if result and close_error:
        value = dict(cast(dict[str, object], result.value or {}))
        value["cleanup_warning"] = close_error
        return ServiceResult(True, value=value)
    return result


def _failed_transition(
    service: Any, state: Any, snapshot: Any, group: Any, finalized: bool, error: Exception
) -> ServiceResult:
    if group is not None and not finalized:
        try:
            service.creator.rollback(group)
        except OSError:
            pass
        except RuntimeError:
            pass
        except ValueError:
            pass
    restore_state_in_place(state, snapshot)
    try:
        service.save_state(state)
    except Exception:
        pass
    try:
        service.apply_config(state)
    except Exception:
        pass
    return failed_result(error, fallback=ErrorCode.OPERATION_FAILED)
