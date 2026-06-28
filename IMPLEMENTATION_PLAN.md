# HYDRA v2.0 — План реализации (исполняемый)

> Документ для ИИ-агентов-исполнителей. Каждый этап самодостаточен: цели → файлы → сигнатуры → пошаговые инструкции → проверка. Выполнять **строго по порядку**. Один этап = ветка `feat/v2-<stage>` + коммиты.

---

## Как пользоваться этим документом

- **Перед этапом**: прочти раздел целиком + открой все файлы из блока «Файлы».
- **Во время**: следуй шагам 1, 2, 3… не пропуская. Каждая функция/класс дан с сигнатурой — реализуй ровно так, чтобы не сломать следующие этапы.
- **После этапа**: прогон `python -m pytest tests/ -q` и `python -m py_compile <изменённые файлы>`. Должно быть зелёным. Иначе — фиксить до коммита.
- **Legacy-логику** (установку/конфиг демонов) сверяй через `git show legacy-reference:vless_installer/modules/<name>.py` (tag ставится на этапе 0).
- **Комментарии и докстринги — на русском** (стиль существующего `hydra/`).
- **Не ломай тесты**: если меняешь сигнатуру (`traffic(state)`, `ProtocolState→PluginState`) — обновляй тесты в том же коммите.

---

## 0. Архитектурные принципы (истина для всех этапов)

1. **sing-box — центральный маршрутизатор.** Все transport-демоны отдают расшифрованный трафик в sing-box. Единый механизм: **nftables TPROXY → sing-box `dokodemo-door` inbound (tproxy)** + явный **SOCKS5 :1080** для демонов с поддержкой upstream. Надстройки (warp/GeoIP/DNSCrypt) применяются централизованно в route-rules sing-box.
2. **Три категории плагинов**:
   - `TRANSPORT` — per-user (каждый юзер = персональные креды/секрет). naive, mieru, awg, telemt, vkturn, wdtt, olcrtc, slipgate, webdav.
   - `ENHANCEMENT` — глобальные надстройки. dnscrypt, warp, porthopping.
   - `SECURITY` — безопасность. fail2ban, honeypot, geoip, ipban.
3. **Единый pipeline**: `orchestrator.apply_config(state)` = collect_fragments → generate_config → nft.apply_tproxy → write_config (валидация) → reload. Один вызов везде, никаких дублей.
4. **User CRUD fan-out**: add/remove/block юзера → `on_user_*` у всех включённых TRANSPORT-плагинов. Никакого special-case для AWG.
5. **Расширяемость через реестр**: новый плагин = `hydra/plugins/<name>/plugin.py` + регистрация. Подписки/трафик/TUI работают автоматически.
6. **Простота**: автоустановка где возможно, минимум ручных шагей, понятный TUI.

---

## Карта целевой структуры

```
hydra/
  core/      state.py(v2) orchestrator.py(NEW) singbox.py systemd.py nft.py(NEW)
  plugins/   base.py(v2) registry.py(discovery) amneziawg/ mieru/ ...
  services/  subscriptions/ traffic.py sync_agent.py telegram/
  utils/     firewall.py(NEW) downloader.py(NEW) crypto.py(NEW) net.py logging.py
  ui/        tui.py menus.py(generic)
main.py  tests/  bootstrap.sh
```

Легаси `vless_installer/` (~29000 строк `_core.py`) удаляется ПОЛНОСТЬЮ; сохраняемые модули переписываются как плагины `hydra/plugins/<name>/`, переиспользуя только сетевую логику установки/конфига.

---

## Порядок и зависимости

```
0 → 1 → 2 → 3 → 4 (orchestrator/registry/nft)
                      ↓
   5 (AWG) ──┐
   6 (mieru) ┤→ 7 (services) → 8 (TUI) → MVP v2.0-beta
             ┘
   9.1–9.7 (остальные транспорты) — независимо, после 8
   10.1–10.7 (надстройки/безопасность) — независимо, после 4
   11 — параллельно с 5–10
```

**MVP v2.0-beta = этапы 0–8** (ядро + AWG + mieru + services + TUI).

---

# ЭТАП 0 — Очистка от xray/vless

**Цель:** убрать мёртвый код, оставить рабочий `hydra/` + `main.py` + `tests/`.
**Риск:** низкий, изолированный.
**Ветка:** `feat/v2-00-cleanup`

### Файлы
- **Удалить:** `vless_installer/` (весь пакет), `hysteria2_main_patch.py`, `hysteria2_state_example.json`, `migrate_awg_to_h2.py`, `verify.py`.
- **Сохранить:** `hydra/`, `main.py`, `tests/`, `bootstrap.sh`, `*.md`, `.github/`, `LICENSE`.

### Шаги
1. **Поставить reference-tag ПЕРЕД удалением** (чтобы на этапах 5–9 подсматривать готовую сетевую логику демонов):
   ```bash
   git tag legacy-reference
   ```
2. Создать ветку: `git checkout -b feat/v2-00-cleanup`.
3. Удалить файлы:
   ```bash
   git rm -r vless_installer/
   git rm hysteria2_main_patch.py hysteria2_state_example.json migrate_awg_to_h2.py verify.py
   ```
4. Проверить отсутствие висячих импортов: в `hydra/` и `main.py` не должно остаться `import vless_installer` / `from vless_installer`. Используй grep.
5. Прогон:
   ```bash
   python -m py_compile main.py hydra/**/*.py
   python -m pytest tests/ -q
   ```
6. Коммит: `refactor: удалить legacy xray/vless ядро (vless_installer)`.

### Проверка
- `git ls-files | grep -i vless` → пусто.
- `git tag | grep legacy-reference` → есть.
- `python main.py` (на Linux-сервере) стартует TUI без ImportError.

---

# ЭТАП 1 — Общие утилиты (foundation)

**Цель:** вынести повторяющуюся сетевую/установочную логику в переиспользуемые utils, чтобы плагины были тонкими.
**Ветка:** `feat/v2-01-utils`

### Файлы (все НОВЫЕ)

#### `hydra/utils/firewall.py`
Вынести логику из legacy `naiveproxy.py`/`mieru.py` (`_ipt_*`/`_ufw_*` — там она идентична).
```python
"""Менеджер firewall: авто-выбор UFW/iptables, persist правил."""
from __future__ import annotations
import shutil, subprocess
from pathlib import Path

def is_ufw_active() -> bool:
    """True если ufw есть и status: active."""

def _ipt_rule_exists(table: str, chain: str, spec: list[str]) -> bool: ...

def open_tcp(port: int, comment: str = "hydra") -> str:
    """Открывает TCP порт через UFW (если активен) иначе iptables. Возвращает описание."""

def open_udp(port: int, comment: str = "hydra") -> str: ...
def open_range(proto: str, start: int, end: int, comment: str = "hydra") -> str: ...
    # proto = "tcp" | "udp"

def close_tcp(port: int) -> None: ...
def close_udp(port: int) -> None: ...
def close_range(proto: str, start: int, end: int) -> None: ...

def persist() -> None:
    """netfilter-persistent save либо /etc/iptables/rules.v4."""
```
**Подсказка по реализации**: смотри `_open_port`/`_close_port` в legacy `naiveproxy.py` (строки ~599–614). Логика: сначала `_ufw_is_active()`, если да — ufw allow/delete, иначе iptables `-I`/`-D` INPUT + `_ipt_persist()`. Помечать правила комментарием `-m comment --comment "<comment>"` для безопасного удаления.

#### `hydra/utils/downloader.py`
```python
"""Скачивание бинарников с GitHub releases."""
from __future__ import annotations
import json, tempfile, urllib.request
from pathlib import Path

def latest_release(repo: str, timeout: int = 10) -> str:
    """Возвращает tag_name (с 'v') последнего релиза. 'unknown' при ошибке.
    repo = 'owner/repo', напр. 'enfein/mieru'."""

def download(url: str, dest: Path, timeout: int = 120) -> bool: ...

def download_github_asset(repo: str, asset_pattern: str, dest: Path) -> bool:
    """Ищет asset по имени (substring) в latest release, скачивает в dest.
    napr. asset_pattern='linux-amd64.deb'."""

def verify_elf(path: Path) -> bool:
    """True если первые 4 байта == b'\\x7fELF'."""

def extract_tarball(archive: Path, dest: Path) -> Path:
    """tar -xzf archive -C dest. Возвращает dest."""
```

#### `hydra/utils/crypto.py`
```python
"""Генерация паролей/токенов и детерминированное выведение ключей."""
from __future__ import annotations
import base64, hashlib, secrets

# Без неоднозначных символов (0/O, 1/l/I) — для ручного ввода с телефона.
_PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

def gen_password(length: int = 16) -> str:
    """Случайный пароль из _PASSWORD_CHARS."""

def gen_token(nbytes: int = 24) -> str:
    """secrets.token_urlsafe(nbytes)."""

def derive_key(purpose: str, seed: str) -> str:
    """Детерминированный ключ: base64(sha256(f'{purpose}|{seed}')).
    Используется AWG и другими плагинами для воспроизводимых per-user кредов."""
    digest = hashlib.sha256(f"{purpose}|{seed}".encode()).digest()
    return base64.b64encode(digest).decode()
```

#### `hydra/utils/net.py` — дополнить существующий
```python
def public_ip() -> str:
    """curl -s -4 api.ipify.org (timeout 5). Fallback: 127.0.0.1."""

def local_ip() -> str:
    """IP основного интерфейса через UDP-сокет к 8.8.8.8 (без отправки пакетов)."""

def detect_arch() -> str:
    """'amd64' | 'arm64' через platform.machine()."""
```

### Шаги
1. Ветка `feat/v2-01-utils` от `main`.
2. Создать 4 файла (firewall, downloader, crypto — новые; net — дополнить). Сверяться с legacy-хелперами через `git show legacy-reference:vless_installer/modules/naiveproxy.py` (раздел «ВСПОМОГАТЕЛЬНЫЕ»).
3. Создать `tests/test_utils.py`:
   - `test_gen_password_length` — длина и символы только из алфавита.
   - `test_derive_key_deterministic` — одинаковый seed → одинаковый ключ.
   - `test_verify_elf` — на моке (Path с байтами `b'\x7fELF...'` → True; `b'xxxx'` → False).
   - `test_detect_arch` — возвращает 'amd64' или 'arm64'.
4. Прогон `pytest tests/test_utils.py -q`.
5. Коммит: `feat(utils): firewall/downloader/crypto/net helpers`.

### Проверка
- `python -c "from hydra.utils import firewall, downloader, crypto, net"` без ошибок.
- `pytest tests/` зелёным.

---

# ЭТАП 2 — State v2 + миграция

**Цель:** расширить модель состояния под per-user креды и tproxy.
**Ветка:** `feat/v2-02-state`

### Файл: `hydra/core/state.py`

### Изменения
1. `User`: добавить поле
   ```python
   credentials: dict[str, dict] = field(default_factory=dict)
   ```
   Per-user секреты по имени плагина. Пример: `user.credentials["mieru"] = {"username": "...", "password": "..."}`. Детерминированные плагины (AWG) могут не использовать — оставляют пустым.

2. `ProtocolState` → переименовать тип в `PluginState` (поля те же: `enabled, port, installed, config`). Обновить все упоминания в `hydra/` (registry.py, singbox.py, menus.py, тесты). Ключ в `state.protocols` оставить строкой (историческое имя ок).

3. `NetworkConfig`: добавить
   ```python
   tproxy_enabled: bool = False
   tproxy_port: int = 1081   # порт dokodemo-door sing-box для TPROXY
   ```

4. `SCHEMA_VERSION = 2`. В `_migrate()` добавить ветку v1→v2:
   ```python
   if from_version < 2:
       for u in data.get("users", []):
           u.setdefault("credentials", {})
       net = data.setdefault("network", {})
       net.setdefault("tproxy_enabled", False)
       net.setdefault("tproxy_port", 1081)
       data["version"] = 2
   ```
   **Важно**: миграция должна правильно проставлять `version` в конце (сейчас v0→v1 только setdefault, без инкремента — исправить).

### Шаги
1. Ветка от main.
2. Правки dataclass + миграция.
3. Обновить `tests/test_state.py`:
   - `test_roundtrip_with_credentials` — сохранить/загрузить User с credentials → совпадает.
   - `test_migrate_v1_to_v2` — подать на вход v1-словарь без credentials/tproxy → после load_state версия 2, поля есть.
4. Прогон `pytest tests/test_state.py -q`.
5. Коммит: `feat(state): v2 schema — credentials, tproxy, миграция`.

### Проверка
- Старый `state.json` (v1) грузится без ошибок, мигрируется до v2.
- `pytest tests/` зелёным.

---

# ЭТАП 3 — Plugin contract v2 (центральный)

**Цель:** формализовать контракт под 3 категории и per-user модель, разделить «сгенерить фрагмент» и «применить».
**Ветка:** `feat/v2-03-contract`
**Это самый важный этап** — от него зависят все следующие.

### Файл: `hydra/plugins/base.py` (переписать)

```python
"""hydra/plugins/base.py — Абстрактный интерфейс плагина v2."""
from __future__ import annotations
import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from hydra.core.state import AppState, User


class PluginCategory(enum.Enum):
    TRANSPORT = "transport"      # per-user: naive, mieru, awg, telemt...
    ENHANCEMENT = "enhancement"  # глобальный: dnscrypt, warp, porthopping
    SECURITY = "security"        # глобальный: fail2ban, geoip...


@dataclass
class PluginMeta:
    name: str
    description: str
    category: PluginCategory
    version: str = "1.0.0"
    needs_domain: bool = False   # для авто-проверок в TUI


@dataclass
class PluginStatus:
    installed: bool
    enabled: bool
    running: bool
    port: int = 0
    info: dict = field(default_factory=dict)


@dataclass
class ConfigFragment:
    """Фрагмент конфига sing-box + маркеры для orchestrator/nft."""
    inbounds: list[dict] = field(default_factory=list)
    outbounds: list[dict] = field(default_factory=list)
    route_rules: list[dict] = field(default_factory=list)
    # Порты демона, чей расшифрованный трафик заворачиваем в sing-box через TPROXY.
    nft_tproxy_ports: list[int] = field(default_factory=list)


class BasePlugin(ABC):
    meta: PluginMeta

    # ── жизненный цикл ──────────────────────────────────────────────
    @abstractmethod
    def install(self) -> bool: ...
    @abstractmethod
    def uninstall(self) -> bool: ...
    @abstractmethod
    def status(self) -> PluginStatus: ...

    # ── конфиг sing-box: ЧИСТАЯ функция, без side-effects ───────────
    @abstractmethod
    def configure(self, state: AppState) -> ConfigFragment: ...

    # ── применение: все side-effects (reload, syncconf, nft) ────────
    def apply(self, state: AppState) -> bool:
        """По умолчанию no-op. Переопределить: перезапуск демона/awg syncconf."""
        return True

    # ── трафик: получает state (исправление старого дизайна) ────────
    def traffic(self, state: AppState) -> dict[str, int]:
        """{email: bytes}. Пустой словарь если не поддерживается."""
        return {}

    # ── TRANSPORT-only: per-user (no-op дефолты для ENHANCEMENT/SECURITY) ──
    def on_user_add(self, user: User, state: AppState) -> None: pass
    def on_user_remove(self, user: User, state: AppState) -> None: pass
    def on_user_block(self, user: User, state: AppState) -> None: pass

    def generate_client_config(self, user: User, state: AppState) -> str:
        """Клиентский .conf / JSON для импорта в приложение."""
        return ""
    def client_link(self, user: User, state: AppState) -> str:
        """Share-ссылка (mierus://, naive+https://, wg:// ...)."""
        return ""
    def connected_clients(self) -> list[dict]:
        """[{email, online, rx, tx, last_handshake, ...}] для статуса."""
        return []

    # ── хуки включения/выключения ───────────────────────────────────
    def on_enable(self, state: AppState) -> None: pass
    def on_disable(self, state: AppState) -> None: pass
```

### Ключевые решения
- **`configure()` — чистая**: генерит фрагмент, не трогает систему. Все side-effects (запись `awg0.conf`, `awg syncconf`, systemd reload) — в `apply()`. AWG больше не нарушает контракт.
- **`traffic(state)`**: получает state → AWG строит pubkey→email из `state.users`, файл `awg_peers.json` убирается (этап 5).
- **`nft_tproxy_ports`** во фрагменте → orchestrator сам строит nft-правила для этих портов (единая точка, этап 4).
- Per-user методы с no-op дефолтами → ENHANCEMENT/SECURITY их не реализуют; orchestrator вызывает только у TRANSPORT.

### Шаги
1. Ветка от main.
2. Переписать `hydra/plugins/base.py` целиком (код выше).
3. Обновить `tests/test_plugins.py`:
   - `MockPlugin` (ENHANCEMENT) — install/configure/status/traffic.
   - `MockTransportPlugin` (TRANSPORT) — реализует `on_user_add` (кладёт креды в `user.credentials["mock"]`), `client_link` возвращает `mock://...`, `connected_clients`.
   - Тест: `test_transport_user_add_creates_credentials`.
4. Прогон `pytest tests/test_plugins.py -q`.
5. Коммит: `feat(contract): plugin v2 — категории, per-user, configure/apply split`.

### Проверка
- `python -c "from hydra.plugins.base import BasePlugin, PluginCategory, ConfigFragment"` без ошибок.
- `pytest tests/` зелёным (старые плагины amneziawg/dnscrypt/warp пока сломаны относительно нового контракта — это ок, починим на этапах 5/10; но MockPlugin и MockTransportPlugin проходят).

> **Важно:** после этого этапа существующие плагины (amneziawg/dnscrypt/warp в `hydra/plugins/`) временно не соответствуют контракту. Это нормально — registry на этапе 4 импортирует их, но `@abstractmethod` не даст инстанцировать. Поэтому **этап 5 (полировка AWG) обязателен до registry**. Чтобы не блокировать работу, можно временно закомментировать старые плагины в registry до этапа 5.

---

# ЭТАП 4 — Orchestrator + Registry discovery + nft

**Цель:** единая точка применения конфига; реестр с фильтром по категориям; nft TPROXY-механика.
**Ветка:** `feat/v2-04-orchestrator`

### Файлы

#### `hydra/plugins/registry.py` (переписать)
```python
"""Реестр плагинов: discovery, фильтры по категориям, сборка фрагментов."""
from __future__ import annotations
from typing import Optional
from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory
from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin   # этап 5
# откладывать импорт mieru до этапа 6
from hydra.core.state import AppState

_PLUGINS: list[BasePlugin] = [
    AmneziaWGPlugin(),
    # MieruPlugin(),  # раскомментировать на этапе 6
]

def all_plugins() -> list[BasePlugin]: return _PLUGINS
def get(name: str) -> Optional[BasePlugin]:
    for p in _PLUGINS:
        if p.meta.name == name: return p
    return None
def transports() -> list[BasePlugin]:  return [p for p in _PLUGINS if p.meta.category == PluginCategory.TRANSPORT]
def enhancements() -> list[BasePlugin]: return [p for p in _PLUGINS if p.meta.category == PluginCategory.ENHANCEMENT]
def security() -> list[BasePlugin]:    return [p for p in _PLUGINS if p.meta.category == PluginCategory.SECURITY]

def enabled(state: AppState, category: PluginCategory | None = None) -> list[BasePlugin]:
    """Включённые плагины (опционально по категории)."""
    pool = _PLUGINS if category is None else [p for p in _PLUGINS if p.meta.category == category]
    return [p for p in pool if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled]

def collect_fragments(state: AppState) -> dict[str, ConfigFragment]:
    fragments: dict[str, ConfigFragment] = {}
    for p in enabled(state):
        try:
            f = p.configure(state)
            if f and (f.inbounds or f.outbounds or f.route_rules or f.nft_tproxy_ports):
                fragments[p.meta.name] = f
        except Exception:
            pass
    return fragments
```

#### `hydra/core/nft.py` (НОВОЕ)
```python
"""nftables TPROXY: заворот трафика транспортов в sing-box."""
from __future__ import annotations
import subprocess
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from hydra.plugins.base import ConfigFragment

NFT_TABLE = "hydra-tproxy"

def apply_tproxy(fragments: dict, tproxy_port: int = 1081) -> None:
    """Собирает nft_tproxy_ports из всех фрагментов, настраивает таблицу
       inet hydra-tproxy: mark + TPROXY входящего трафика этих портов → sing-box.
       Идемпотентно: сначала flush таблицы."""
    # 1. собрать уникальные порты из fragments[*].nft_tproxy_ports
    # 2. nft 'flush table inet hydra-tproxy' (если есть)
    # 3. создать таблицу + chain prerouting (mangle) + chain output
    # 4. для каждого порта: 'meta l4proto {tcp|udp} th dport N tproxy to :tproxy_port accept'
    # Реализовать через subprocess nft -f - (heredoc).

def clear_tproxy() -> None:
    """Удалить таблицу hydra-tproxy целиком."""
    subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], capture_output=True)

def persist() -> None:
    """nft list ruleset > /etc/nftables.conf (или /etc/iptables/rules.v4 fallback)."""
```
**Подсказка**: точный синтаксис sing-box tproxy уточнить через `sing-box check` (см. этап про singbox). Маркер `0x1/0x1` + `tproxy to :PORT`.

#### `hydra/core/orchestrator.py` (НОВОЕ) — единый pipeline
```python
"""Единая точка применения конфигурации и управления плагинами/юзерами."""
from __future__ import annotations
from hydra.core.state import AppState, User, save_state, get_protocol, find_user
from hydra.core import singbox, nft
from hydra.plugins.registry import collect_fragments, enabled, get, transports

def apply_config(state: AppState) -> bool:
    """Единый pipeline. Возвращает True если sing-box перезагружен OK."""
    fragments = collect_fragments(state)
    cfg = singbox.generate_config(state, fragments)
    if not singbox.write_config(cfg):
        return False
    # TPROXY-правила для портов транспортов
    try:
        if state.network.tproxy_enabled:
            nft.apply_tproxy(fragments, state.network.tproxy_port)
        else:
            nft.clear_tproxy()
    except Exception:
        pass
    return singbox.reload()

def install_plugin(state: AppState, name: str) -> bool:
    p = get(name)
    if not p: return False
    ok = p.install()
    proto = get_protocol(state, name)
    proto.installed = ok
    save_state(state)
    return ok

def uninstall_plugin(state: AppState, name: str) -> bool:
    p = get(name)
    if not p: return False
    ok = p.uninstall()
    proto = get_protocol(state, name)
    proto.installed = False; proto.enabled = False
    save_state(state)
    apply_config(state)
    return ok

def enable(state: AppState, name: str) -> bool:
    p = get(name)
    if not p: return False
    p.on_enable(state)
    proto = get_protocol(state, name); proto.enabled = True
    save_state(state)
    return apply_config(state)

def disable(state: AppState, name: str) -> bool:
    p = get(name)
    if not p: return False
    p.on_disable(state)
    proto = get_protocol(state, name); proto.enabled = False
    save_state(state)
    return apply_config(state)

# ── User CRUD fan-out ─────────────────────────────────────────────
def add_user(state: AppState, user: User) -> None:
    from hydra.core.state import add_user as _add
    _add(state, user)
    for p in transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try: p.on_user_add(user, state)
            except Exception: pass
    save_state(state)
    apply_config(state)

def remove_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u: return
    for p in transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try: p.on_user_remove(u, state)
            except Exception: pass
    state.users = [x for x in state.users if x.email != email]
    save_state(state)
    apply_config(state)

def block_user(state: AppState, email: str) -> None:
    u = find_user(state, email)
    if not u: return
    u.blocked = True
    for p in transports():
        if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled:
            try: p.on_user_block(u, state)
            except Exception: pass
    save_state(state)
    apply_config(state)
```

#### `hydra/core/singbox.py` — правки
1. В `_base_config(state)` добавить два базовых inbound'а (если ещё нет):
   ```python
   config["inbounds"].append({
       "type": "direct", "tag": "tproxy-in",
       "listen": "::", "listen_port": state.network.tproxy_port,
       "network": "tcp", "sniff": True,
   })
   config["inbounds"].append({
       "type": "socks", "tag": "socks-in",
       "listen": "127.0.0.1", "listen_port": 1080,
   })
   ```
   > Точный синтаксис tproxy для sing-box 1.12+ уточнить в доках / проверить `sing-box check`. Если tproxy-inbound невалиден — оставить пока только socks-in, tproxy-заворот добавить когда будет проверен.
2. `generate_config(state, fragments)` — теперь принимает `dict[str, ConfigFragment]` напрямую (убрать ручную распаковку dict-of-dict). Итерация:
   ```python
   for name, frag in fragments.items():
       config["inbounds"].extend(frag.inbounds)
       config["outbounds"].extend(frag.outbounds)
       config["route"]["rules"].extend(frag.route_rules)
   ```

### Шаги
1. Ветка от main.
2. Написать `nft.py`, `orchestrator.py`; переписать `registry.py`; правки `singbox.py`.
3. Тесты `tests/test_orchestrator.py` (на моках — подменить registry.collect_fragments и singbox.write_config):
   - `test_apply_config_pipeline` — фрагмент от мока → write_config вызван → reload вызван.
   - `test_add_user_fanout` — add_user вызывает on_user_add у включённого мок-транспорта.
   - `test_block_user_calls_on_user_block`.
4. Прогон `pytest`.
5. Коммит: `feat(core): orchestrator + registry discovery + nft tproxy`.

### Проверка
- `pytest tests/` зелёным.
- (На сервере) `apply_config(state)` с одним плагином пишет валидный `config.json` (`sing-box check -c /etc/sing-box/config.json` OK).

---

# ЭТАП 5 — Полировка AmneziaWG под контракт v2

**Цель:** привести AWG в соответствие с контрактом v2; убрать special-case в меню.
**Ветка:** `feat/v2-05-awg`

### Файл: `hydra/plugins/amneziawg/plugin.py` (переписать под v2)

### Изменения
1. `meta`:
   ```python
   meta = PluginMeta(
       name="amneziawg",
       description="AmneziaWG 2.0: WireGuard с обфускацией (kernel-модуль)",
       category=PluginCategory.TRANSPORT,
       version="2.0.0",
       needs_domain=False,
   )
   ```
2. **Разделить configure/apply** (главное):
   - `configure(state) -> ConfigFragment`: генерит текст секций `[Peer]` (как раньше, из `state.users`), но **НЕ пишет файл и НЕ вызывает syncconf**. Возвращает `ConfigFragment(route_rules=[{"ip_cidr": [network], "outbound": "direct"}])`. **nft_tproxy_ports = []** (AWG терминирует трафик в ядре awg0, TPROXY не нужен).
   - `apply(state) -> bool`: пишет `awg0.conf` (через сохранённый в `self` или пересчитанный peers-текст), `awg syncconf` / `systemctl start awg-quick@awg0`. Бывшая side-effect часть.
   - **Секрет**: чтобы не считать peers дважды, можно в `configure` кешировать `self._pending_conf` (строка) и `apply` пишет его. Или `apply` сам вызывает внутренний `_build_conf(state)` — на выбор, главное сохранить идемпотентность.
3. **Per-user методы**:
   - `on_user_add/remove/block(user, state)` → `self.configure(state); self.apply(state)` (пересобрать пиры и применить вживую).
   - `generate_client_config(user, state)` — оставить как есть.
   - `client_link(user, state)` — оставить.
   - `connected_clients()` — переименовать из `connected_peers()` (возвращаемый dict оставить).
4. **`traffic(state)`**: убрать чтение `PEER_MAP`. Вместо этого — построить `{pubkey: email}` из `state.users`:
   ```python
   pub_to_email = {self._derive_pubkey(u.uuid): u.email for u in state.users if not u.blocked}
   ```
   Удалить `_write_peer_map`/`_read_peer_map` и константу `PEER_MAP`.
5. Зарегистрировать в `registry.py` (уже импортирован в этапе 4).

### Шаги
1. Ветка от main.
2. Переписать plugin.py.
3. Тесты `tests/test_awg_plugin.py` (на моках subprocess — подменить `awg pubkey`/`awg show`):
   - `test_configure_returns_route_rule` — без side-effects (не пишет файл на моке).
   - `test_traffic_uses_state` — fake `state.users` + mock `awg show transfer` → `{email: bytes}`.
   - `test_on_user_add_triggers_apply`.
4. В `hydra/ui/menus.py` убрать `menu_plugin_awg`, `_resync_awg` (они уйдут на этапе 8, но уже сейчас не вызывать `_resync_awg` — оставить TODO). Минимально: закомментировать special-case routing в `menu_protocols`, чтобы AWG шёл через generic `menu_plugin` (этап 8 допилит).
5. Прогон `pytest`.
6. Коммит: `feat(amneziawg): контракт v2 — configure/apply split, traffic(state), убрать PEER_MAP`.

### Проверка
- `pytest tests/` зелёным.
- (На сервере) добавить юзера → `awg show awg0` показывает нового пира; `generate_client_config` валиден; трафик считается через `traffic(state)`.

---

# ЭТАП 6 — Порт mieru (reference TRANSPORT-плагин)

**Цель:** эталонная реализация transport-плагина. После этого этапа mieru = **шаблон**, по которому портятся все остальные (этап 9).
**Ветка:** `feat/v2-06-mieru`

### Файлы (НОВЫЕ): `hydra/plugins/mieru/__init__.py`, `hydra/plugins/mieru/plugin.py`

### Логика (сверять с `git show legacy-reference:vless_installer/modules/mieru.py`)

#### `install()`
- Скачать mita через `utils/downloader` (`.deb` если dpkg, иначе tar.gz). См. legacy `_install_mita_package`.
- Создать системного юзера `mita` (`useradd --system --no-create-home --shell /usr/sbin/nologin mita`).
- Установить chrony через apt (NTP обязателен, ±30 сек) — `utils` + `subprocess`.
- Создать systemd `mita.service` (`ExecStart=mita run`, `Type=simple`, `Restart=on-failure`). См. legacy `_install_service`.
- Открыть порты через `utils/firewall.open_range/udp` (default 2012–2022 TCP).
- Вернуть True если `_is_installed()` (бинок + unit).

#### `configure(state) -> ConfigFragment`
- Сгенерировать `/etc/mita/server.json`: `{portBindings: [{port/portRange, protocol}], users: [{name, password}], loggingLevel, mtu}`. **СДЕЛАТЬ ЧИСТОЙ** — только сборка dict, без `mita apply`.
- Per-user креды **детерминированные** (как AWG): `username = "u" + derive_key("mieru-user", uuid)[:8]`, `password = derive_key("mieru-pass", uuid)`. Не хранить в state (но можно закешировать в `user.credentials["mieru"]` для удобства подписок).
- Вернуть `ConfigFragment(nft_tproxy_ports=[port_start])` — **трафик mita заворачивается в sing-box через TPROXY** (реализация «всё через sing-box»).

#### `apply(state) -> bool`
- `mita apply config <cfg>` (через subprocess) + `systemctl reload-or-restart mita`. См. legacy `_apply_server_config`.

#### Per-user
- `on_user_add(user, state)` → `self.configure(state); self.apply(state)`; закешировать креды в `user.credentials["mieru"]`.
- `on_user_remove/block` → аналогично (пересобрать конфиг).
- `generate_client_config(user, state) -> str` — sing-box outbound JSON (формат из legacy `_gen_singbox_outbound`): `{type:"mieru", tag, server, server_port, transport, username, password, multiplexing:"MULTIPLEXING_HIGH"}`. Обернуть в полный sing-box конфиг для импорта.
- `client_link(user, state) -> str` — `mierus://` для Karing (`_gen_client_share_link`) и NekoBox (`_gen_client_share_link_nekobox`). Отдавать оба (через `\n`) или только Karing-вариант + remark.

#### `traffic(state) -> dict[str, int]`
- Через iptables accounting chain (`CHAIN_IN`/`CHAIN_OUT`, см. legacy `mtproto.py` — там эта техника для telemt; для mita аналогично) либо через mita status API. Перевод по `user.credentials["mieru"]["username"]` → email.

#### `connected_clients() -> list[dict]`
- Из `mita` status / логов.

### Шаги
1. Ветка от main.
2. Создать `hydra/plugins/mieru/__init__.py` (пустой), `hydra/plugins/mieru/plugin.py`.
3. Раскомментировать `MieruPlugin()` в `registry.py`.
4. Тесты `tests/test_mieru_plugin.py`:
   - `test_configure_returns_fragment_with_port` — фрагмент содержит `nft_tproxy_ports=[2012]`.
   - `test_client_link_valid_uri` — начинается с `mierus://`.
   - `test_on_user_add_sets_credentials` — после on_user_add в `user.credentials["mieru"]` есть username/password.
   - `test_deterministic_creds` — одинаковый uuid → одинаковые креды.
5. Прогон `pytest`.
6. Коммит: `feat(mieru): reference TRANSPORT-плагин (mita + nft-tproxy + детерминированные креды)`.

### Проверка
- `pytest tests/` зелёным.
- (На сервере) `enable mieru` → mita поднят, порт в nft-tproxy; добавить юзера → креды сгенерены, `client_link` импортируется в Karing.

---

# ЭТАП 7 — Services на registry (без хардкодов)

**Цель:** подписки/трафик/синк/бот работают с любым плагином через контракт.
**Ветка:** `feat/v2-07-services`

### Файлы

#### `hydra/services/subscriptions/generator.py` (переписать)
```python
from hydra.plugins.registry import transports, enabled
from hydra.core.state import AppState, User

def client_links(user: User, state: AppState) -> list[str]:
    """Список client_link() всех включённых транспортов."""
    return [p.client_link(user, state)
            for p in transports()
            if state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled
            and p.client_link(user, state)]

def client_singbox_config(user: User, state: AppState) -> dict:
    """Единый sing-box конфиг: outbounds из всех включённых транспортов."""
    outbounds = []
    for p in transports():
        if not (state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled):
            continue
        cfg = p.generate_client_config(user, state)
        # распарсить outbound из cfg (плагин отдаёт либо JSON-строку, либо .conf)
        ...  # см. реализацию
    outbounds.append({"type": "direct", "tag": "direct"})
    return {"log": {"level": "info"}, "outbounds": outbounds, "route": {"final": outbounds[0]["tag"] if outbounds else "direct"}}

def generate_base64_sub(user: User, state: AppState) -> str:
    import base64
    return base64.b64encode("\n".join(client_links(user, state)).encode()).decode()
```
- **Убрать** хардкоды naiveproxy/mieru/amneziawg и сломанные `{{AWG_CLIENT_PRIVATE_KEY}}` плейсхолдеры.
- HTTP handler `/sub?token=<uuid>&format=singbox|base64` — оставить, использует новые функции.

#### `hydra/services/traffic.py` (переписать)
```python
from hydra.plugins.registry import transports
from hydra.core.state import AppState

def collect_traffic(state: AppState) -> dict[str, int]:
    """{email: total_bytes} — сумма traffic(state) по включённым транспортам."""
    result: dict[str, int] = {}
    for p in transports():
        if not (state.protocols.get(p.meta.name) and state.protocols[p.meta.name].enabled):
            continue
        try:
            for email, b in p.traffic(state).items():
                result[email] = result.get(email, 0) + b
        except Exception:
            pass
    return result
```
(Использует `transports()` + фильтр enabled, не `get_all()` как раньше.)

#### `hydra/services/sync_agent.py`
- После блокировки юзера по лимиту/TTL вызывать `orchestrator.block_user(state, email)` (это делает reconfigure live). Убрать неиспользуемые импорты.

#### `hydra/services/telegram/bot.py`
- Добавить QR (`qrencode -t UTF8`) в `/link` и `/config`.
- Использует новый generator (`client_links`, `client_singbox_config`).

### Шаги
1. Ветка от main.
2. Переписать 4 файла.
3. Тесты `tests/test_subscriptions.py`:
   - `test_client_links_aggregates_plugins` — мок-транспорт отдаёт link → base64_sub содержит его.
   - `test_collect_traffic_sums_plugins` — два мок-транспорта → сумма.
4. Прогон `pytest`.
5. Коммит: `feat(services): subscriptions/traffic/sync на registry, без хардкодов`.

### Проверка
- `pytest tests/` зелёным.
- (На сервере) HTTP `/sub?token=<uuid>` отдаёт ссылки всех включённых транспортов.

---

# ЭТАП 8 — TUI: generic plugin-меню + единый apply

**Цель:** убрать дублирование apply-pipeline и special-case AWG; единое меню плагинов.
**Ветка:** `feat/v2-08-tui`
**Завершает MVP v2.0-beta.**

### Файл: `hydra/ui/menus.py`

### Изменения
1. **`menu_protocols`** → единый список из `registry.all_plugins()`, сгруппированный по категориям (Транспорты / Надстройки / Безопасность). Пункт «A — Применить конфиг» → `orchestrator.apply_config(state)`.

2. **`menu_plugin(state, plugin)`** — **одна** функция для всех плагинов (включая AWG):
   - Статус-панель из `plugin.status()`.
   - Действия:
     - Установить → `orchestrator.install_plugin(state, name)`.
     - Удалить → `orchestrator.uninstall_plugin(state, name)`.
     - Включить/Выключить → `orchestrator.enable/disable(state, name)`.
     - Статус/Трафик → `plugin.status()` / `plugin.connected_clients()`.
     - Показать клиентский конфиг (для TRANSPORT) → `plugin.generate_client_config` + `plugin.client_link` + QR.

3. **Убрать** `menu_plugin_awg`, `_resync_awg`, и оба дублированных `collect_fragments→generate_config→write_config→reload` (теперь `orchestrator.apply_config(state)`).

4. **`menu_users` → `_add_user`** вызывает `orchestrator.add_user(state, user)` (fan-out по транспортам). `_delete_user`/`_toggle_block` → `orchestrator.remove_user`/`block_user`.

5. **Клиентские ссылки/QR** в показе юзера:
   ```python
   for p in transports():
       if enabled: print(p.client_link(user, state))
   ```

### Шаги
1. Ветка от main.
2. Рефакторинг `menus.py` (файл ~950 строк — переписать меню плагинов/юзеров, оставить menus для telegram/monitoring/security как есть пока).
3. Ручной тест TUI: `python main.py` — все меню работают; включение mieru/awg применяет конфиг за один шаг; добавление юзера создаёт креды у всех включённых транспортов.
4. Коммит: `feat(tui): generic plugin-menu + единый apply pipeline`.

### Проверка
- `python main.py` стартует без ошибок.
- Включить AWG → `awg0` поднят; включить mieru → mita поднят; оба видны в статусе.
- Добавить юзера → у AWG появляется пир, у mieru — креды; обе ссылки показываются.

> 🎉 **MVP v2.0-beta готов.** Дальше — инкрементальное добавление плагинов по шаблону mieru.

---

# ЭТАП 9 — Остальные транспорты (по шаблону mieru)

Каждый подэтап — отдельная ветка `feat/v2-09-<name>`. Строго по матрице mieru (install/configure/apply/per-user/traffic/connected_clients). Источник: `git show legacy-reference:vless_installer/modules/<name>.py`.

| Подэтап | Плагин | Источник | Особенности |
|---|---|---|---|
| 9.1 | `naive` | naiveproxy.py | caddy-forwardproxy-naive; Caddyfile + probe_resistance + фейк-сайт; **needs_domain=True**; basicauth per-user (plaintext для этой сборки — legacy warns bcrypt даёт 401); `nft_tproxy_ports=[443]`; sing-box outbound `type:naive` |
| 9.2 | `telemt` | mtproto.py + telemt_fallback/ios_fix/self_route | Rust MTProto; multi-user secret; в legacy уже iptables-REDIRECT → **заменить на nft-tproxy** (через `nft_tproxy_ports`); telemt_fallback как вспомогательный модуль |
| 9.3 | `vkturn` | turntunnel.py + vkturn_menu.py | FreeTurn (vk-turn-proxy, UDP:56000); single-инстанс, **не per-user креды**, а инструкция/ссылка для клиента FreeTurn |
| 9.4 | `wdtt` | wdtt.py | qWDTT (WG over TURN ВК); парольная модель (главный + до 10 временных с TTL/лимитом устройств); hot-reload SIGHUP; встроенный TG-бот управления паролями |
| 9.5 | `olcrtc` | olcrtc.py | TCP-over-WebRTC; **multi-link** (отдельный systemd-сервис `olcrtc@<name>` на каждый линк!); YAML-конфиг вместо share-link |
| 9.6 | `slipgate` | slipgate.py | DNS-туннели (DNSTT/Noiz/Slipstream/VayDNS); **needs_domain + NS-делегирование**; :53/udp |
| 9.7 | `webdav` | webdav_tunnel.py | SOCKS5 over WebDAV; режимы selfhosted/external; single-login (делиться ссылкой) |

### Для каждого подэтапа (шаблон)
1. Ветка `feat/v2-09-<name>` от main.
2. Создать `hydra/plugins/<name>/__init__.py` + `plugin.py` (category=TRANSPORT).
3. Сверять install/config-логику с legacy через `git show legacy-reference:...`.
4. Зарегистрировать в `registry.py`.
5. Тесты `tests/test_<name>_plugin.py` (configure возвращает фрагмент с правильным портом; client_link валидный; on_user_add создаёт креды/конфиг).
6. `pytest` + коммит `feat(<name>): TRANSPORT-плагин`.

---

# ЭТАП 10 — Надстройки и Безопасность (ENHANCEMENT/SECURITY)

Каждый — отдельная ветка. Category = ENHANCEMENT или SECURITY. Per-user методы не реализуются (no-op). Источник: `git show legacy-reference:...`.

| Подэтап | Плагин | Категория | Что делает |
|---|---|---|---|
| 10.1 | `dnscrypt` | ENHANCEMENT | systemd `dnscrypt-proxy` :5300; sing-box DNS server → `127.0.0.1:5300`; **configure отдаёт DNS-фрагмент** (зафиксировать то, что сейчас мёртвый `_dns_config` в singbox.py) |
| 10.2 | `warp` | ENHANCEMENT | sing-box wireguard-outbound `tag:warp` + route-rules для AI-доменов (openai/anthropic/gemini...); **убрать избыточный wg-quick kernel-интерфейс** (outbound самодостаточен) |
| 10.3 | `porthopping` | ENHANCEMENT | nftables PREROUTING REDIRECT диапазона → реальный порт (переписать с iptables на nft); `configure` отдаёт пустой фрагмент, `apply` ставит правила |
| 10.4 | `fail2ban` | SECURITY | jails: sing-box/caddy/sshd/nginx; `apply` пишет `jail.d/*.local`, `status` сводка банов; legacy `fail2ban_manager.py` |
| 10.5 | `geoip` | SECURITY | nft ipset + страна-блок (РФ по умолчанию); route_rules в sing-box при возможности; legacy `ingress_geoip.py` |
| 10.6 | `honeypot` | SECURITY | ловушка-порты; legacy `honeypot.py` |
| 10.7 | `ipban` | SECURITY | ipset-управление (через `utils/firewall`); legacy `ipban.py` + `ipset_persist.py` |

---

# ЭТАП 11 — Тесты, документация, релиз

### Тесты
- Покрыть: orchestrator, registry, state-v2, mieru/awg (на моках subprocess), subscriptions, utils.
- Цель: >70% строк по `hydra/` (`pytest --cov=hydra`).
- Все системные вызовы (subprocess, Path.write) — через моки/monkeypatch, тесты не требуют root.

### Документация
- `ARCHITECTURE.md` — схема слоёв, контракты, матрица плагинов, диаграмма трафика (клиент → демон → nft-tproxy → sing-box → надстройки → интернет).
- `README.md` — обновить под v2: установка, quickstart, «как добавить плагин» (по шаблону mieru).
- `CHANGELOG.md` — запись v2.0.
- Этот `IMPLEMENTATION_PLAN.md` — оставить как живой чек-лист (отмечать `[x]` выполненные этапы).

### Релиз
- PR `feat/v2-0` в main после этапа 8 (MVP beta).
- Отдельные PR на каждый плагин этапов 9–10.
- Тег `v2.0.0` после этапа 11.

---

## Чек-лист прогресса

- [ ] 0. Очистка от xray/vless
- [ ] 1. Общие утилиты
- [ ] 2. State v2 + миграция
- [ ] 3. Plugin contract v2
- [ ] 4. Orchestrator + Registry + nft
- [ ] 5. Полировка AmneziaWG
- [ ] 6. Порт mieru (reference)
- [ ] 7. Services на registry
- [ ] 8. TUI generic → **MVP v2.0-beta**
- [ ] 9.1 naive / 9.2 telemt / 9.3 vkturn / 9.4 wdtt / 9.5 olcrtc / 9.6 slipgate / 9.7 webdav
- [ ] 10.1 dnscrypt / 10.2 warp / 10.3 porthopping / 10.4 fail2ban / 10.5 geoip / 10.6 honeypot / 10.7 ipban
- [ ] 11. Тесты, доки, релиз
