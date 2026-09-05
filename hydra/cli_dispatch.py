"""Command handlers for the HYDRA CLI transport adapter."""
from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from hydra.core.state_models import AppState, User, validate_state
from hydra.core.status import public_user
from hydra.services.application import ApplicationService


@dataclass(frozen=True)
class CommandResult:
    payload: object
    exit_code: int = 0


def _result(payload: object, *, negative_key: str | None = None) -> CommandResult:
    if isinstance(payload, dict):
        if payload.get("ok") is False:
            return CommandResult(payload, 1)
        if negative_key is not None and payload.get(negative_key) is False:
            return CommandResult(payload, 1)
    return CommandResult(payload)


def _structured(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        return as_dict()
    return value


def _service_payload(result: object) -> dict[str, object]:
    payload = _structured(result)
    if not isinstance(payload, dict):
        return {"ok": bool(result), "value": payload}
    error = payload.get("error")
    if payload.get("ok") is False and isinstance(error, dict):
        return {
            "ok": False,
            "error": str(error.get("message", "operation failed")),
            "error_details": error,
        }
    return payload


def _parameters(raw_parameters: list[str]) -> dict[str, object]:
    parameters: dict[str, object] = {}
    for item in raw_parameters:
        name, separator, raw_value = item.partition("=")
        name = name.strip()
        if not separator or not name or not name.isidentifier():
            raise ValueError(
                f"invalid --param {item!r}; expected NAME=JSON",
            )
        if name in parameters:
            raise ValueError(f"duplicate --param: {name}")
        try:
            parameters[name] = json.loads(raw_value)
        except json.JSONDecodeError:
            parameters[name] = raw_value
    return parameters


def _operator_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    if args.command_id == "status":
        return _result(app.status(state))
    if args.command_id == "check" or args.dry_run:
        return _result(app.check(state))
    require_root()
    return _result(_service_payload(app.apply_result(state)))


def _backup_command(
    args: argparse.Namespace,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    if args.command_id == "backup.inspect":
        return _result(
            app.backups.inspect(args.archive),
            negative_key="valid",
        )
    require_root()
    if args.command_id == "backup.create":
        return _result(app.backups.create(args.output or None))
    if not args.dry_run and not args.yes:
        raise ValueError(
            "restore requires --yes; use --dry-run to inspect the archive",
        )
    return _result(
        app.backups.restore(args.archive, dry_run=args.dry_run),
        negative_key="valid",
    )


def _upgrade_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    if args.command_id == "upgrade.check":
        return _result(
            app.system.upgrade_check(state),
            negative_key="ready",
        )
    require_root()
    return _result(app.system.migrate_state())


def _kernel_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    if args.command_id == "kernel.status":
        return _result(app.kernel.status(state).as_dict())
    require_root()
    result = app.kernel.switch(
        state,
        args.provider,
        channel=args.channel,
        force=args.force,
    )
    return _result(result.as_dict())


def _new_user(args: argparse.Namespace) -> User:
    user = User(
        email=args.email,
        uuid=args.uuid or str(uuid.uuid4()),
        traffic_limit_gb=args.traffic_limit_gb,
        expiry_date=args.expiry_date,
        device_limit=args.device_limit,
    )
    validate_state(AppState(users=[user]))
    return user


def _user_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> dict[str, object]:
    action = args.user_action
    if action == "list":
        return {"users": [public_user(user) for user in app.users.list(state)]}
    if action == "show":
        user = app.users.get(state, args.email)
        if user is None:
            raise ValueError(f"User {args.email} not found")
        return {"user": public_user(user)}
    require_root()
    if action == "add":
        user = _new_user(args)
        app.add_user(state, user)
        return {"ok": True, "user": public_user(user)}
    if action == "ensure-default":
        if state.users:
            return {
                "ok": True,
                "created": False,
                "user": public_user(state.users[0]),
            }
        user = User(
            email="default",
            uuid=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        app.add_user(state, user)
        return {"ok": True, "created": True, "user": public_user(user)}
    if action == "rename":
        user = app.rename_user(state, args.email, args.new_email)
        return {
            "ok": True,
            "old_email": args.email,
            "user": public_user(user),
        }
    if action == "set-device-limit":
        user = app.set_user_device_limit(
            state,
            args.email,
            args.limit,
            reset=args.reset,
        )
        return {"ok": True, "user": public_user(user)}
    if action == "rotate-hydrabox-key":
        user = app.rotate_user_hydrabox_key(state, args.email)
        return {"ok": True, "user": public_user(user)}
    operations = {
        "block": app.block_user,
        "unblock": app.unblock_user,
        "remove": app.remove_user,
    }
    operations[action](state, args.email)
    return {"ok": True, "email": args.email, "action": action}


def _plugin_read_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
) -> CommandResult:
    if args.command_id == "plugin.list":
        return _result(
            {
                "plugins": app.protocols.inventory(
                    state,
                    category=args.category,
                ),
            },
        )
    if args.command_id == "plugin.show":
        inventory = app.protocols.inventory(state)
        plugin = next(
            (item for item in inventory if item["name"] == args.name),
            None,
        )
        if plugin is None:
            raise ValueError(f"unknown plugin: {args.name}")
        return _result({"plugin": plugin})
    if args.command_id == "plugin.status":
        return _result(
            {
                "name": args.name,
                "status": _structured(app.protocols.status(args.name, state)),
            },
        )
    health = app.protocols.health(state, args.name)
    health_payload = _structured(health)
    healthy = (
        bool(health_payload.get("healthy"))
        if isinstance(health_payload, dict)
        else bool(getattr(health, "healthy", False))
    )
    payload = {
        "ok": healthy,
        "name": args.name,
        "health": health_payload,
    }
    return _result(payload)


def _plugin_invoke_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    parameters = _parameters(args.param)
    if args.command_id == "plugin.command":
        require_root()
        changed = app.plugin_command(
            state,
            args.name,
            args.operation,
            **parameters,
        )
        return _result(
            {
                "ok": True,
                "plugin": args.name,
                "command": args.operation,
                "changed": bool(changed),
            },
        )
    if args.with_state:
        if "state" in parameters:
            raise ValueError("--with-state conflicts with --param state=...")
        parameters["state"] = state
    if args.command_id == "plugin.query":
        value = app.plugin_query(
            args.name,
            args.operation,
            **parameters,
        )
        return _result(
            {
                "plugin": args.name,
                "query": args.operation,
                "result": _structured(value),
            },
        )
    require_root()
    value = app.plugin_action(
        args.name,
        args.operation,
        **parameters,
    )
    payload = {
        "ok": value is not False,
        "plugin": args.name,
        "action": args.operation,
        "result": _structured(value),
    }
    return _result(payload)


def _plugin_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    if args.plugin_action in {"list", "show", "status", "health"}:
        return _plugin_read_command(args, state, app)
    if args.plugin_action in {"command", "query", "action"}:
        return _plugin_invoke_command(args, state, app, require_root)
    require_root()
    service_result = app.protocols.lifecycle_result(
        state,
        args.plugin_action,
        args.name,
    )
    return _result(_service_payload(service_result))


def _uninstall_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    require_root()
    return _result(
        app.uninstall(
            state,
            confirmed=args.yes,
            dry_run=args.dry_run,
            keep_data=args.keep_data,
        ),
    )


def _antidpi_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    require_root()
    if args.antidpi_action == "selftest":
        return _result(
            app.plugin_action(
                "antidpi",
                "run_selftest",
                state=state,
                output=args.output or None,
                wait_seconds=args.wait,
                full=args.full,
                protocols=app.protocols,
            ),
        )
    if args.antidpi_action == "capture":
        return _result(
            app.plugin_action(
                "antidpi",
                "capture_external_tests",
                state=state,
                output=args.output or None,
                seconds=args.seconds,
            ),
        )
    installed = app.protocols.install(state, "antidpi")
    health = app.protocols.health(state, "antidpi")
    payload = {
        "ok": bool(installed and health.healthy),
        "error": "" if installed else health.detail,
        "health": health.as_dict(),
    }
    return _result(payload)


def dispatch(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
    require_root: Callable[[], None],
) -> CommandResult:
    domain = args.command_id.split(".", 1)[0]
    if domain in {"status", "check", "apply"}:
        return _operator_command(args, state, app, require_root)
    if domain == "backup":
        return _backup_command(args, app, require_root)
    if domain == "upgrade":
        return _upgrade_command(args, state, app, require_root)
    if domain == "kernel":
        return _kernel_command(args, state, app, require_root)
    if domain == "user":
        return _result(_user_command(args, state, app, require_root))
    if domain == "plugin":
        return _plugin_command(args, state, app, require_root)
    if domain == "uninstall":
        return _uninstall_command(args, state, app, require_root)
    if domain == "antidpi":
        return _antidpi_command(args, state, app, require_root)
    raise ValueError(f"unsupported command: {args.command_id}")


__all__ = ["CommandResult", "_user_command", "dispatch"]
