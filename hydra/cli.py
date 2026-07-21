"""Non-interactive HYDRA command line interface."""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import uuid
from dataclasses import asdict

from hydra.core.state import AppState, User, load_state, validate_state
from hydra.core.errors import ErrorCode, normalize_error
from hydra.core.status import public_user
from hydra.services.application import production_application




def _print(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _require_root() -> None:
    if os.name != "nt" and os.geteuid() != 0:
        raise PermissionError("Команда, изменяющая систему, требует root")


def build_plan(state: AppState, app=None) -> dict:
    """Build and validate configuration on a copy without changing runtime state."""
    from hydra.core import singbox
    from hydra.plugins import registry

    candidate = copy.deepcopy(state)
    candidate.network.tproxy_enabled = True
    fragments = registry.collect_fragments(candidate)
    config = singbox.generate_config(candidate, fragments)
    conflicts = singbox._preflight_conflicts(config)
    app = app or production_application()
    reconciliation = app.protocols.reconciliation().plan(state)
    from hydra.core.sni_router import audit_routes
    return {
        "valid": not conflicts,
        "conflicts": conflicts,
        "plugins": sorted(fragments),
        "requirements": registry.requirements(candidate),
        "reconciliation": [asdict(action) for action in reconciliation],
        "tls_mux": audit_routes(state).as_dict(),
        "changes": {
            "inbounds": len(config.get("inbounds", [])),
            "outbounds": len(config.get("outbounds", [])),
            "route_rules": len(config.get("route", {}).get("rules", [])),
            "tproxy_ports": sorted({port for fragment in fragments.values() for port in fragment.nft_tproxy_ports}),
        },
    }


def _status(state: AppState, app=None) -> dict:
    return (app or production_application()).status(state)


def _user_command(args: argparse.Namespace, state: AppState, app=None) -> dict:
    app = app or production_application()
    if args.user_action == "list":
        return {"users": [public_user(user) for user in app.users.list(state)]}
    _require_root()
    if args.user_action == "add":
        user = User(
            email=args.email,
            uuid=args.uuid or str(uuid.uuid4()),
            traffic_limit_gb=args.traffic_limit_gb,
            expiry_date=args.expiry_date,
        )
        validate_state(AppState(users=[user]))
        app.add_user(state, user)
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
    apply = commands.add_parser("apply", help="Apply configuration")
    apply.add_argument("--dry-run", action="store_true")

    antidpi = commands.add_parser("antidpi", help="AntiDPI diagnostics")
    antidpi_commands = antidpi.add_subparsers(dest="antidpi_action", required=True)
    selftest = antidpi_commands.add_parser("selftest", help="Probe native protocol error logging")
    selftest.add_argument("--output", default="", help="Diagnostic archive path or destination directory")
    selftest.add_argument("--wait", type=float, default=2.0, help="Journal collection delay per protocol (0-10 seconds)")
    selftest.add_argument(
        "--full", action="store_true",
        help="Also run temporary native clients with invalid authentication",
    )

    users = commands.add_parser("user", help="Manage users")
    user_commands = users.add_subparsers(dest="user_action", required=True)
    user_commands.add_parser("list")
    add = user_commands.add_parser("add")
    add.add_argument("email")
    add.add_argument("--uuid", default="")
    add.add_argument("--traffic-limit-gb", type=float, default=0)
    add.add_argument("--expiry-date", default="")
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
            from hydra.core.backup import create_backup
            payload = create_backup(args.output or None)
        elif args.command == "restore":
            _require_root()
            if not args.dry_run and not args.yes:
                raise ValueError("restore requires --yes; use --dry-run to inspect the archive")
            from hydra.core.backup import restore_backup
            payload = restore_backup(args.archive, dry_run=args.dry_run)
        elif args.command == "doctor":
            from hydra.core.doctor import run_doctor
            payload = run_doctor(state)
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
        elif args.command == "antidpi" and args.antidpi_action == "selftest":
            _require_root()
            from hydra.plugins.antidpi.selftest import run_selftest
            payload = run_selftest(state, args.output or None, args.wait, full=args.full)
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
