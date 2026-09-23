"""Сторож медиа-плейлиста: точка входа для systemd.

Ошибка запуска не должна уходить в тишину: сторож держит весь видео-путь прикрытия, и
единственный способ узнать, почему плеер пустой, — строка в журнале.
"""

from __future__ import annotations

import argparse
import sys

from hydra.contracts.vless_cdn import (
    GATE_PORT,
    STREAM_HLS_TIME_DEFAULT,
    STREAM_IDLE_TIMEOUT_DEFAULT,
    STREAM_LIST_SIZE_DEFAULT,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hydra-vless-cdn-media")
    parser.add_argument("--port", type=int, default=GATE_PORT)
    parser.add_argument("--idle-timeout", type=int, default=STREAM_IDLE_TIMEOUT_DEFAULT)
    parser.add_argument("--hls-time", type=int, default=STREAM_HLS_TIME_DEFAULT)
    parser.add_argument("--list-size", type=int, default=STREAM_LIST_SIZE_DEFAULT)
    return parser


def main(argv: list[str] | None = None) -> int:
    from hydra.core.vless_cdn_media import Gate, serve

    args = _parser().parse_args(argv)
    gate = Gate(idle_timeout=args.idle_timeout, hls_time=args.hls_time)
    print(
        f"media gate on port {args.port}: idle_timeout={gate.idle_timeout}s "
        f"hls_time={gate.hls_time}s list_size={args.list_size}",
        file=sys.stderr,
    )
    serve(gate, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
