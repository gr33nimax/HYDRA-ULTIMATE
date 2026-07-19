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
from hydra.core.status import build_status, public_user


def _print(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _require_root() -> None:
    if os.name != "nt" and os.geteuid() != 0:
        raise PermissionError("Команда, изменяющая систему, требует root")


def build_plan(state: AppState) -> dict:
    """Build and validate configuration on a copy without changing runtime state."""
    from hydra.core import singbox
    from hydra.plugins import registry

    candidate = copy.deepcopy(state)
    candidate.network.tproxy_enabled = True
    fragments = registry.collect_fragments(candidate)
    config = singbox.generate_config(candidate, fragments)
    conflicts = singbox._preflight_conflicts(config)
    return {
        "valid": not conflicts,
        "conflicts": conflicts,
        "plugins": sorted(fragments),
        "requirements": registry.requirements(candidate),
        "changes": {
            "inbounds": len(config.get("inbounds", [])),
            "outbounds": len(config.get("outbounds", [])),
            "route_rules": len(config.get("route", {}).get("rules", [])),
            "tproxy_ports": sorted({port for fragment in fragments.values() for port in fragment.nft_tproxy_ports}),
        },
    }


def _status(state: AppState) -> dict:
    return build_status(state)


def _user_command(args: argparse.Namespace, state: AppState) -> dict:
    from hydra.core import orchestrator

    if args.user_action == "list":
        return {"users": [public_user(user) for user in state.users]}
    _require_root()
    if args.user_action == "add":
        user = User(
            email=args.email,
            uuid=args.uuid or str(uuid.uuid4()),
            traffic_limit_gb=args.traffic_limit_gb,
            expiry_date=args.expiry_date,
        )
        validate_state(AppState(users=[user]))
        orchestrator.add_user(state, user)
        return {"ok": True, "user": asdict(user)}
    actions = {
        "block": orchestrator.block_user,
        "unblock": orchestrator.unblock_user,
        "remove": orchestrator.remove_user,
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
    try:
        state = load_state()
        if args.command == "status":
            payload = _status(state)
        elif args.command == "validate":
            validate_state(state)
            payload = {"valid": True, "schema_version": state.version}
        elif args.command == "plan" or (args.command == "apply" and args.dry_run):
            payload = build_plan(state)
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
        elif args.command == "upgrade" and args.upgrade_action == "check":
            from hydra.core.upgrade import check_upgrade
            payload = check_upgrade(state)
        elif args.command == "apply":
            _require_root()
            from hydra.core.orchestrator import apply_config, last_apply_error
            ok = apply_config(state)
            payload = {"ok": ok, "error": "" if ok else last_apply_error()}
            _print(payload)
            return 0 if ok else 1
        else:
            payload = _user_command(args, state)
        _print(payload)
        return 0
    except Exception as exc:
        _print({"ok": False, "error": str(exc) or exc.__class__.__name__})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
