"""Non-interactive HYDRA command line adapter."""
from __future__ import annotations

import argparse
import json
import os
import sys

from hydra import __version__
from hydra.bootstrap import production_application
from hydra.cli_dispatch import (
    _user_command as dispatch_user_command,
    dispatch,
)
from hydra.cli_parser import (
    CliUsageError,
    normalize_legacy_argv,
    parser as build_parser,
)
from hydra.cli_render import render_calls_telemetry_record, render_human
from hydra.core.errors import normalize_error
from hydra.core.state import load_state, save_state  # compatibility patch seam
from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService


def _print(payload: object, *, compact: bool = False) -> None:
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=None if compact else 2,
            separators=(",", ":") if compact else None,
            default=str,
        ),
    )


def _require_root() -> None:
    if os.name != "nt" and os.geteuid() != 0:
        raise PermissionError("Команда, изменяющая систему, требует root")


def build_plan(state: AppState, app: ApplicationService) -> dict:
    """Compatibility helper for callers that built plans through the CLI."""
    return app.plan(state)


def _status(state: AppState, app: ApplicationService) -> dict:
    return app.status(state)


def _user_command(
    args: argparse.Namespace,
    state: AppState,
    app: ApplicationService,
) -> dict[str, object]:
    """Compatibility seam for focused user-command tests and integrations."""
    return dispatch_user_command(args, state, app, _require_root)


def parser() -> argparse.ArgumentParser:
    """Return the public parser for help generation and adapter tests."""
    return build_parser()


def _error_payload(exc: BaseException, *, usage: str = "") -> dict[str, object]:
    detail = normalize_error(exc)
    details = detail.as_dict()
    if usage:
        details["usage"] = usage
    return {
        "ok": False,
        "error": detail.message,
        "error_details": details,
    }


def _stdout_is_tty() -> bool:
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _color_enabled() -> bool:
    return bool(
        _stdout_is_tty()
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM", "") != "dumb"
    )


def _emit(
    payload: object,
    *,
    command_id: str,
    compact: bool,
    force_json: bool = False,
) -> None:
    if compact:
        _print(payload, compact=True)
    elif force_json or not _stdout_is_tty():
        _print(payload)
    else:
        print(
            render_human(
                command_id,
                payload,
                color=_color_enabled(),
            ),
        )


def _follow_calls_telemetry(
    args: argparse.Namespace,
    app: ApplicationService,
) -> int:
    """Stream the application-owned timeline as human lines or NDJSON."""
    _require_root()
    try:
        records = app.calls_telemetry.follow(
            args.session,
            limit=args.lines,
        )
        for record in records:
            if args.compact or args.json or not _stdout_is_tty():
                _print(record, compact=True)
            else:
                print(
                    render_calls_telemetry_record(
                        record,
                        color=_color_enabled(),
                    ),
                    flush=True,
                )
    except KeyboardInterrupt:
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    normalized = normalize_legacy_argv(raw_argv)
    command_parser = parser()
    try:
        args = command_parser.parse_args(normalized)
        if not args.version and not getattr(args, "command_id", ""):
            raise CliUsageError(
                "the following arguments are required: COMMAND",
                command_parser.format_usage(),
            )
    except CliUsageError as exc:
        compact = "--compact" in raw_argv
        _emit(
            _error_payload(exc, usage=exc.usage),
            command_id="error",
            compact=compact,
            force_json="--json" in raw_argv,
        )
        return 2
    except SystemExit as exc:
        return int(exc.code or 0)

    if args.version:
        _emit(
            {"version": __version__},
            command_id="version",
            compact=args.compact,
            force_json=args.json,
        )
        return 0

    try:
        app = production_application()
        state = load_state()
        if args.command_id == "calls.telemetry.tail" and args.follow:
            return _follow_calls_telemetry(args, app)
        result = dispatch(args, state, app, _require_root)
        _emit(
            result.payload,
            command_id=args.command_id,
            compact=args.compact,
            force_json=args.json,
        )
        return result.exit_code
    except Exception as exc:
        _emit(
            _error_payload(exc),
            command_id="error",
            compact=args.compact,
            force_json=args.json,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
