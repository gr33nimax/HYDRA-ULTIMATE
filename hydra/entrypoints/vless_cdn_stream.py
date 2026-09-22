"""Живой медиапоток прикрытия: непрерывный ffmpeg под systemd.

Долгоживущий процесс: сервис `hydra-vless-cdn-stream` держит его и перезапускает при
падении. Ошибка не должна ронять всё молча — строка в журнале объясняет, что случилось.
"""

from __future__ import annotations

import sys


def main() -> int:
    from hydra.core.state import load_state
    from hydra.services.vless_cdn_stream import run_for_state

    try:
        state = load_state()
        return run_for_state(state)
    except Exception as exc:  # noqa: BLE001 — сервис не должен падать без строки в журнале
        print(f"vless-cdn stream failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
