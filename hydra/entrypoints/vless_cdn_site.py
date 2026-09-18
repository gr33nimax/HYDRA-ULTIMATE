"""Обновление страницы-прикрытия по таймеру.

Ошибка не должна ронять сервис молча: строка в журнале — единственный способ узнать,
почему страница перестала обновляться.
"""

from __future__ import annotations

import sys


def main() -> int:
    from hydra.core.state import load_state
    from hydra.services.vless_cdn_site import refresh_site

    try:
        state = load_state()
        target = refresh_site(state)
    except Exception as exc:
        print(f"vless-cdn site refresh failed: {exc}", file=sys.stderr)
        return 1
    print(f"vless-cdn site refreshed: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
