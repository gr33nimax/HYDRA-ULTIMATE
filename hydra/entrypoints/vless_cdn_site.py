"""Обновление страницы-прикрытия по таймеру.

Ошибка не должна ронять сервис молча: строка в журнале — единственный способ узнать,
почему страница перестала обновляться.
"""

from __future__ import annotations

import sys


def main() -> int:
    from hydra.core.state import update_state
    from hydra.core.yandex_cdn import refresh_prefixes
    from hydra.services.vless_cdn_site import refresh_site

    try:
        prefix_refresh = refresh_prefixes()
        _state, target = update_state(refresh_site)
    except Exception as exc:
        print(f"vless-cdn site refresh failed: {exc}", file=sys.stderr)
        return 1
    if not prefix_refresh.ok:
        print(f"vless-cdn prefix refresh failed: {prefix_refresh.error}", file=sys.stderr)
    print(f"vless-cdn site refreshed: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
