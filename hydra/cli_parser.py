"""Operator-focused command grammar for the HYDRA headless CLI."""
from __future__ import annotations

import argparse
from collections.abc import Sequence


class CliUsageError(ValueError):
    """A parser failure that can be rendered through the JSON error contract."""

    def __init__(self, message: str, usage: str) -> None:
        super().__init__(message)
        self.usage = usage.removeprefix("usage: ").strip()


class CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliUsageError(message, self.format_usage())


def _subcommands(
    parser: argparse.ArgumentParser,
    *,
    dest: str,
    title: str,
) -> argparse._SubParsersAction:
    return parser.add_subparsers(
        dest=dest,
        required=True,
        title=title,
        metavar="COMMAND",
    )


def _command(
    commands: argparse._SubParsersAction,
    name: str,
    help_text: str,
    command_id: str,
    *,
    aliases: tuple[str, ...] = (),
    usage: str | None = None,
) -> argparse.ArgumentParser:
    parser = commands.add_parser(
        name,
        aliases=list(aliases),
        help=help_text,
        description=help_text,
        usage=usage,
    )
    parser.set_defaults(command_id=command_id)
    return parser


def _add_parameters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="NAME=JSON",
        help="Repeatable typed parameter; bare non-JSON values stay strings",
    )


def _add_backup(root: argparse._SubParsersAction) -> None:
    backup = root.add_parser(
        "backup",
        help="Create, inspect and restore trusted backups",
    )
    commands = _subcommands(backup, dest="backup_action", title="backup")
    create = _command(commands, "create", "Create a backup archive", "backup.create")
    create.add_argument(
        "--output",
        default="",
        help="Archive path or destination directory",
    )
    inspect = _command(
        commands,
        "inspect",
        "Validate and describe an archive without restoring it",
        "backup.inspect",
    )
    inspect.add_argument("archive")
    restore = _command(
        commands,
        "restore",
        "Restore a trusted backup archive",
        "backup.restore",
    )
    restore.add_argument("archive")
    restore.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and show the restore plan",
    )
    restore.add_argument(
        "--yes",
        action="store_true",
        help="Confirm overwriting files from the archive",
    )


def _add_upgrade(root: argparse._SubParsersAction) -> None:
    upgrade = root.add_parser("upgrade", help="Check and migrate an installation")
    commands = _subcommands(upgrade, dest="upgrade_action", title="upgrade")
    _command(commands, "check", "Check upgrade readiness", "upgrade.check")
    _command(
        commands,
        "migrate-state",
        "Atomically persist pending state migrations",
        "upgrade.migrate-state",
    )


def _add_kernel(root: argparse._SubParsersAction) -> None:
    kernel = root.add_parser("kernel", help="Inspect or switch the managed core")
    commands = _subcommands(kernel, dest="kernel_action", title="kernel")
    _command(commands, "status", "Show desired and active core", "kernel.status")
    switch = _command(
        commands,
        "switch",
        "Download, verify and transactionally activate a core",
        "kernel.switch",
    )
    switch.add_argument(
        "provider",
        choices=("sing-box-extended", "hydracore"),
    )
    switch.add_argument(
        "--channel",
        choices=("stable", "preview", "debug"),
        default="stable",
    )
    switch.add_argument("--force", action="store_true")


def _add_user(root: argparse._SubParsersAction) -> None:
    user = root.add_parser("user", aliases=["users"], help="Manage users")
    commands = _subcommands(user, dest="user_action", title="users")
    _command(commands, "list", "List users without secrets", "user.list")
    show = _command(commands, "show", "Show one user without secrets", "user.show")
    show.add_argument("email")
    add = _command(commands, "add", "Add a user transactionally", "user.add")
    add.add_argument("email")
    add.add_argument("--uuid", default="")
    add.add_argument("--traffic-limit-gb", type=float, default=0)
    add.add_argument("--expiry-date", default="")
    add.add_argument("--device-limit", type=int, default=0, help="0 means unlimited")
    _command(
        commands,
        "ensure-default",
        "Create the default user when the state is empty",
        "user.ensure-default",
    )
    rename = _command(commands, "rename", "Rename a user", "user.rename")
    rename.add_argument("email")
    rename.add_argument("new_email")
    limit = _command(
        commands,
        "set-device-limit",
        "Set or reset a subscription device limit",
        "user.set-device-limit",
    )
    limit.add_argument("email")
    limit.add_argument("limit", type=int)
    limit.add_argument("--reset", action="store_true")
    rotate = _command(
        commands,
        "rotate-hydrabox-key",
        "Rotate the HydraBox JWE key and invalidate old links",
        "user.rotate-hydrabox-key",
    )
    rotate.add_argument("email")
    for action in ("block", "unblock", "remove"):
        command = _command(
            commands,
            action,
            f"{action.capitalize()} a user",
            f"user.{action}",
        )
        command.add_argument("email")


def _add_plugin(root: argparse._SubParsersAction) -> None:
    plugin = root.add_parser(
        "plugin",
        aliases=["plugins"],
        help="Inspect and manage plugins",
    )
    commands = _subcommands(plugin, dest="plugin_action", title="plugins")
    listing = _command(commands, "list", "List plugin inventory", "plugin.list")
    listing.add_argument(
        "--category",
        choices=("transport", "enhancement", "security"),
    )
    show = _command(commands, "show", "Show plugin metadata and status", "plugin.show")
    show.add_argument("name")
    status = _command(
        commands,
        "status",
        "Show one plugin runtime status",
        "plugin.status",
        usage="hydra plugin status NAME",
    )
    status.add_argument("name")
    health = _command(commands, "health", "Run one plugin health check", "plugin.health")
    health.add_argument("name")
    for action in ("install", "reinstall", "enable", "disable", "uninstall"):
        lifecycle = _command(
            commands,
            action,
            f"{action.capitalize()} a plugin",
            f"plugin.{action}",
        )
        lifecycle.add_argument("name")
    for kind in ("command", "query", "action"):
        invocation = _command(
            commands,
            kind,
            f"Invoke an allowlisted plugin {kind}",
            f"plugin.{kind}",
        )
        invocation.add_argument("name")
        invocation.add_argument("operation")
        _add_parameters(invocation)
        if kind in {"query", "action"}:
            invocation.add_argument(
                "--with-state",
                action="store_true",
                help="Inject current state into a state-aware hook",
            )


def _add_antidpi(root: argparse._SubParsersAction) -> None:
    antidpi = root.add_parser(
        "antidpi",
        help="Advanced AntiDPI diagnostics",
    )
    commands = _subcommands(antidpi, dest="antidpi_action", title="antidpi")
    selftest = _command(
        commands,
        "selftest",
        "Probe native protocol error logging",
        "antidpi.selftest",
    )
    selftest.add_argument("--output", default="")
    selftest.add_argument("--wait", type=float, default=2.0)
    selftest.add_argument("--full", action="store_true")
    capture = _command(
        commands,
        "capture",
        "Capture an external invalid-auth test window",
        "antidpi.capture",
    )
    capture.add_argument("--seconds", type=float, default=120.0)
    capture.add_argument("--output", default="")
    _command(
        commands,
        "sync",
        "Install or update AntiDPI telemetry",
        "antidpi.sync",
    )


def parser() -> CliArgumentParser:
    root = CliArgumentParser(
        prog="hydra",
        description=(
            "HYDRA management CLI. Start with status, run check before a "
            "change, then use apply."
        ),
    )
    root.add_argument(
        "-V",
        "--version",
        action="store_true",
        help="Show the HYDRA version",
    )
    root.add_argument(
        "--compact",
        action="store_true",
        help="Print single-line JSON for automation",
    )
    root.add_argument(
        "--json",
        action="store_true",
        help="Always print structured JSON",
    )
    commands = root.add_subparsers(
        dest="command",
        title="commands",
        metavar="COMMAND",
    )
    _command(commands, "status", "Show current desired and runtime state", "status")
    _command(
        commands,
        "check",
        "Validate everything and preview pending changes",
        "check",
    )
    apply = _command(
        commands,
        "apply",
        "Apply desired configuration transactionally",
        "apply",
    )
    apply.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the same read-only preflight as check",
    )
    _add_backup(commands)
    _add_user(commands)
    _add_plugin(commands)
    _add_upgrade(commands)
    _add_kernel(commands)
    uninstall = _command(
        commands,
        "uninstall",
        "Completely remove HYDRA",
        "uninstall",
    )
    uninstall.add_argument("--yes", action="store_true", help="Confirm removal")
    uninstall.add_argument("--dry-run", action="store_true", help="Show removal plan")
    uninstall.add_argument("--keep-data", action="store_true", help="Keep state and logs")
    _add_antidpi(commands)
    return root


def _move_global_options(tokens: list[str]) -> list[str]:
    global_options = [
        token
        for token in tokens
        if token in {"--compact", "--json", "--version", "-V"}
    ]
    return [
        *global_options,
        *(
            token
            for token in tokens
            if token not in {"--compact", "--json", "--version", "-V"}
        ),
    ]


def normalize_legacy_argv(argv: Sequence[str]) -> list[str]:
    """Collapse released internal-stage syntax into the operator grammar."""
    tokens = _move_global_options(list(argv))
    command_index = next(
        (
            index
            for index, token in enumerate(tokens)
            if not token.startswith("-")
        ),
        None,
    )
    if command_index is None:
        return tokens
    command = tokens[command_index]
    tail = tokens[command_index + 1 :]
    prefix = tokens[:command_index]

    if command == "config" and tail:
        action, *parameters = tail
        replacement = "apply" if action == "apply" else "check"
        return [*prefix, replacement, *parameters]
    if command == "runtime" and tail:
        action, *parameters = tail
        if action == "status":
            return [*prefix, "status", *parameters]
        if action == "reconcile" and "--apply" in parameters:
            return [
                *prefix,
                "apply",
                *(value for value in parameters if value != "--apply"),
            ]
        return [*prefix, "check", *parameters]
    if command == "system" and tail and tail[0] == "uninstall":
        return [*prefix, "uninstall", *tail[1:]]
    if command in {"validate", "doctor", "plan"}:
        return [*prefix, "check", *tail]
    if command == "reconcile":
        if "--apply" in tail:
            return [
                *prefix,
                "apply",
                *(value for value in tail if value != "--apply"),
            ]
        return [*prefix, "check", *tail]
    if command == "restore":
        return [*prefix, "backup", "restore", *tail]
    if command == "backup" and (not tail or tail[0].startswith("-")):
        return [*prefix, "backup", "create", *tail]
    return tokens


__all__ = [
    "CliUsageError",
    "normalize_legacy_argv",
    "parser",
]
