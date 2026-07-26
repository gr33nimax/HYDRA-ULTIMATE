"""Non-interactive HYDRA command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from dataclasses import asdict
from datetime import datetime, timezone

from hydra.core.state import load_state, save_state
from hydra.core.state_models import AppState, User, validate_state
from hydra.core.errors import ErrorCode, normalize_error
from hydra.core.status import public_user
from hydra.bootstrap import production_application
from hydra.services.application import ApplicationService




def _print(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _require_root() -> None:
    if os.name != "nt" and os.geteuid() != 0:
        raise PermissionError("Команда, изменяющая систему, требует root")


def build_plan(state: AppState, app: ApplicationService) -> dict:
    """Build and validate configuration on a copy without changing runtime state."""
    return app.plan(state)


def _status(state: AppState, app: ApplicationService) -> dict:
    return app.status(state)


def _user_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
) -> dict:
    if args.user_action == "list":
        return {"users": [public_user(user) for user in app.users.list(state)]}
    _require_root()
    if args.user_action == "add":
        user = User(
            email=args.email,
            uuid=args.uuid or str(uuid.uuid4()),
            traffic_limit_gb=args.traffic_limit_gb,
            expiry_date=args.expiry_date,
            device_limit=args.device_limit,
        )
        validate_state(AppState(users=[user]))
        app.add_user(state, user)
        return {"ok": True, "user": asdict(user)}
    if args.user_action == "ensure-default":
        if state.users:
            return {"ok": True, "created": False, "user": asdict(state.users[0])}
        user = User(
            email="default",
            uuid=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        state.users.append(user)
        save_state(state)
        return {"ok": True, "created": True, "user": asdict(user)}
    if args.user_action == "rename":
        user = app.rename_user(state, args.email, args.new_email)
        return {"ok": True, "old_email": args.email, "user": asdict(user)}
    if args.user_action == "set-device-limit":
        user = app.set_user_device_limit(
            state,
            args.email,
            args.limit,
            reset=args.reset,
        )
        return {"ok": True, "user": asdict(user)}
    actions = {
        "block": app.block_user,
        "unblock": app.unblock_user,
        "remove": app.remove_user,
    }
    actions[args.user_action](state, args.email)
    return {"ok": True, "email": args.email, "action": args.user_action}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="hydra", description="HYDRA headless management CLI")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show runtime and plugin status as JSON")
    commands.add_parser("validate", help="Validate persisted state")
    commands.add_parser("plan", help="Build a side-effect-free apply plan")
    commands.add_parser("doctor", help="Run read-only host readiness checks")
    reconcile = commands.add_parser("reconcile", help="Show or apply safe runtime drift corrections")
    reconcile.add_argument("--apply", action="store_true", help="Apply planned enable/disable operations")
    backup = commands.add_parser("backup", help="Create a state and service configuration backup")
    backup.add_argument("--output", type=str, default="", help="Archive path or destination directory")
    restore = commands.add_parser("restore", help="Validate or restore a HYDRA backup")
    restore.add_argument("archive", type=str)
    restore.add_argument("--dry-run", action="store_true", help="Validate and show the restore plan")
    restore.add_argument("--yes", action="store_true", help="Confirm overwriting files from the archive")
    upgrade = commands.add_parser("upgrade", help="Check upgrade readiness")
    upgrade_commands = upgrade.add_subparsers(dest="upgrade_action", required=True)
    upgrade_commands.add_parser("check")
    upgrade_commands.add_parser(
        "migrate-state",
        help="Atomically persist every pending state schema migration",
    )
    apply = commands.add_parser("apply", help="Apply configuration")
    apply.add_argument("--dry-run", action="store_true")
    uninstall = commands.add_parser("uninstall", help="Completely remove HYDRA")
    uninstall.add_argument("--yes", action="store_true", help="Confirm removal")
    uninstall.add_argument("--dry-run", action="store_true", help="Show the removal plan")
    uninstall.add_argument("--keep-data", action="store_true", help="Keep state and logs")

    antidpi = commands.add_parser("antidpi", help="AntiDPI diagnostics")
    antidpi_commands = antidpi.add_subparsers(dest="antidpi_action", required=True)
    selftest = antidpi_commands.add_parser("selftest", help="Probe native protocol error logging")
    selftest.add_argument("--output", default="", help="Diagnostic archive path or destination directory")
    selftest.add_argument("--wait", type=float, default=2.0, help="Journal collection delay per protocol (0-10 seconds)")
    selftest.add_argument(
        "--full", action="store_true",
        help="Also run temporary native clients with invalid authentication",
    )
    capture = antidpi_commands.add_parser(
        "capture", help="Capture an external invalid-auth test window",
    )
    capture.add_argument("--seconds", type=float, default=120.0, help="Capture window (10-600 seconds)")
    capture.add_argument("--output", default="", help="Diagnostic archive path or destination directory")
    antidpi_commands.add_parser(
        "sync", help="Install/update AntiDPI telemetry and restart its collector",
    )

    users = commands.add_parser("user", help="Manage users")
    user_commands = users.add_subparsers(dest="user_action", required=True)
    user_commands.add_parser("list")
    add = user_commands.add_parser("add")
    add.add_argument("email")
    add.add_argument("--uuid", default="")
    add.add_argument("--traffic-limit-gb", type=float, default=0)
    add.add_argument("--expiry-date", default="")
    add.add_argument("--device-limit", type=int, default=0, help="0 means unlimited")
    user_commands.add_parser(
        "ensure-default",
        help="Create the default user when the state has no users",
    )
    rename = user_commands.add_parser("rename")
    rename.add_argument("email")
    rename.add_argument("new_email")
    device_limit = user_commands.add_parser("set-device-limit")
    device_limit.add_argument("email")
    device_limit.add_argument("limit", type=int)
    device_limit.add_argument("--reset", action="store_true", help="Forget registered devices")
    for action in ("block", "unblock", "remove"):
        command = user_commands.add_parser(action)
        command.add_argument("email")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    app = production_application()
    try:
        state = load_state()
        if args.command == "status":
            payload = _status(state, app)
        elif args.command == "validate":
            validate_state(state)
            payload = {"valid": True, "schema_version": state.version}
        elif args.command == "plan" or (args.command == "apply" and args.dry_run):
            payload = build_plan(state, app)
        elif args.command == "backup":
            _require_root()
            payload = app.backups.create(args.output or None)
        elif args.command == "restore":
            _require_root()
            if not args.dry_run and not args.yes:
                raise ValueError("restore requires --yes; use --dry-run to inspect the archive")
            payload = app.backups.restore(
                args.archive,
                dry_run=args.dry_run,
            )
        elif args.command == "doctor":
            from hydra.core.doctor import run_doctor
            payload = run_doctor(state, app.protocols)
        elif args.command == "reconcile":
            service = app.protocols.reconciliation()
            if args.apply:
                _require_root()
                from dataclasses import asdict
                report = service.apply(state)
                payload = {
                    "planned": [asdict(action) for action in report.planned],
                    "applied": report.applied,
                    "failed": report.failed,
                }
            else:
                from dataclasses import asdict
                payload = {"planned": [asdict(action) for action in service.plan(state)]}
        elif args.command == "upgrade" and args.upgrade_action == "check":
            from hydra.core.upgrade import check_upgrade
            payload = check_upgrade(state)
        elif args.command == "upgrade" and args.upgrade_action == "migrate-state":
            _require_root()
            from hydra.core.state import migrate_persisted_state

            payload = migrate_persisted_state()
        elif args.command == "apply":
            _require_root()
            ok = app.apply(state)
            if ok:
                payload = {"ok": True, "error": ""}
            else:
                detail = normalize_error(
                    RuntimeError(app.apply_error() or "configuration apply failed"),
                    fallback=ErrorCode.OPERATION_FAILED,
                )
                payload = {"ok": False, "error": detail.message, "error_details": detail.as_dict()}
            _print(payload)
            return 0 if ok else 1
        elif args.command == "uninstall":
            _require_root()
            payload = app.uninstall(
                state,
                confirmed=args.yes,
                dry_run=args.dry_run,
                keep_data=args.keep_data,
            )
        elif args.command == "antidpi" and args.antidpi_action == "selftest":
            _require_root()
            payload = app.plugin_action(
                "antidpi",
                "run_selftest",
                state=state,
                output=args.output or None,
                wait_seconds=args.wait,
                full=args.full,
                protocols=app.protocols,
            )
        elif args.command == "antidpi" and args.antidpi_action == "capture":
            _require_root()
            payload = app.plugin_action(
                "antidpi",
                "capture_external_tests",
                state=state,
                output=args.output or None,
                seconds=args.seconds,
            )
        elif args.command == "antidpi" and args.antidpi_action == "sync":
            _require_root()
            ok = app.protocols.install(state, "antidpi")
            health = app.protocols.health(state, "antidpi")
            payload = {
                "ok": bool(ok and health.healthy),
                "error": "" if ok else health.detail,
                "health": health.as_dict(),
            }
            if not payload["ok"]:
                _print(payload)
                return 1
        else:
            payload = _user_command(args, state, app)
        _print(payload)
        return 0
    except Exception as exc:
        detail = normalize_error(exc)
        _print({"ok": False, "error": detail.message, "error_details": detail.as_dict()})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
