# \# HYDRA v2.0 — План реализации (исполняемый)

# 

# > Документ для ИИ-агентов-исполнителей. Каждый этап самодостаточен: цели → файлы → сигнатуры → пошаговые инструкции → проверка. Выполнять \*\*строго по порядку\*\*. Один этап = ветка `feat/v2-<stage>` + коммиты.

# 

# \---

# 

# \## Как пользоваться этим документом

# 

# \- \*\*Перед этапом\*\*: прочти раздел целиком + открой все файлы из блока «Файлы».

# \- \*\*Во время\*\*: следуй шагам 1, 2, 3… не пропуская. Каждая функция/класс дан с сигнатурой — реализуй ровно так, чтобы не сломать следующие этапы.

# \- \*\*После этапа\*\*: прогон `python -m pytest tests/ -q` и `python -m py\_compile <изменённые файлы>`. Должно быть зелёным. Иначе — фиксить до коммита.

# \- \*\*Legacy-логику\*\* (установку/конфиг демонов) сверяй через `git show legacy-reference:vless\_installer/modules/<name>.py` (tag ставится на этапе 0).

# \- \*\*Комментарии и докстринги — на русском\*\* (стиль существующего `hydra/`).

# \- \*\*Не ломай тесты\*\*: если меняешь сигнатуру (`traffic(state)`, `ProtocolState→PluginState`) — обновляй тесты в том же коммите.

# 

# \---

# 

# \## 0. Архитектурные принципы (истина для всех этапов)

# 

# 1\. \*\*sing-box — центральный маршрутизатор.\*\* Все transport-демоны отдают расшифрованный трафик в sing-box. Единый механизм: \*\*nftables TPROXY → sing-box `dokodemo-door` inbound (tproxy)\*\* + явный \*\*SOCKS5 :1080\*\* для демонов с поддержкой upstream. Надстройки (warp/GeoIP/DNSCrypt) применяются централизованно в route-rules sing-box.

# 2\. \*\*Три категории плагинов\*\*:

# &#x20;  - `TRANSPORT` — per-user (каждый юзер = персональные креды/секрет). naive, mieru, awg, telemt, vkturn, wdtt, olcrtc, slipgate, webdav.

# &#x20;  - `ENHANCEMENT` — глобальные надстройки. dnscrypt, warp, porthopping.

# &#x20;  - `SECURITY` — безопасность. fail2ban, honeypot, geoip, ipban.

# 3\. \*\*Единый pipeline\*\*: `orchestrator.apply\_config(state)` = collect\_fragments → generate\_config → nft.apply\_tproxy → write\_config (валидация) → reload. Один вызов везде, никаких дублей.

# 4\. \*\*User CRUD fan-out\*\*: add/remove/block юзера → `on\_user\_\*` у всех включённых TRANSPORT-плагинов. Никакого special-case для AWG.

# 5\. \*\*Расширяемость через реестр\*\*: новый плагин = `hydra/plugins/<name>/plugin.py` + регистрация. Подписки/трафик/TUI работают автоматически.

# 6\. \*\*Простота\*\*: автоустановка где возможно, минимум ручных шагей, понятный TUI.

# 

# \---

# 

# \## Карта целевой структуры

# 

# ```

# hydra/

# &#x20; core/      state.py(v2) orchestrator.py(NEW) singbox.py systemd.py nft.py(NEW)

# &#x20; plugins/   base.py(v2) registry.py(discovery) amneziawg/ mieru/ ...

# &#x20; services/  subscriptions/ traffic.py sync\_agent.py telegram/

# &#x20; utils/     firewall.py(NEW) downloader.py(NEW) crypto.py(NEW) net.py logging.py

# &#x20; ui/        tui.py menus.py(generic)

# main.py  tests/  bootstrap.sh

# ```

# 

# Легаси `vless\_installer/` (\~29000 строк `\_core.py`) удаляется ПОЛНОСТЬЮ; сохраняемые модули переписываются как плагины `hydra/plugins/<name>/`, переиспользуя только сетевую логику установки/конфига.

# 

# \---

# 

# \## Порядок и зависимости

# 

# ```

# 0 → 1 → 2 → 3 → 4 (orchestrator/registry/nft)

# &#x20;                     ↓

# &#x20;  5 (AWG) ──┐

# &#x20;  6 (mieru) ┤→ 7 (services) → 8 (TUI) → MVP v2.0-beta

# &#x20;            ┘

# &#x20;  9.1–9.7 (остальные транспорты) — независимо, после 8

# &#x20;  10.1–10.7 (надстройки/безопасность) — независимо, после 4

# &#x20;  11 — параллельно с 5–10

# ```

# 

# \*\*MVP v2.0-beta = этапы 0–8\*\* (ядро + AWG + mieru + services + TUI).

# 

# \---

# 

# \# ЭТАП 0 — Очистка от xray/vless

# 

# \*\*Цель:\*\* убрать мёртвый код, оставить рабочий `hydra/` + `main.py` + `tests/`.

# \*\*Риск:\*\* низкий, изолированный.

# \*\*Ветка:\*\* `feat/v2-00-cleanup`

# 

# \### Файлы

# \- \*\*Удалить:\*\* `vless\_installer/` (весь пакет), `hysteria2\_main\_patch.py`, `hysteria2\_state\_example.json`, `migrate\_awg\_to\_h2.py`, `verify.py`.

# \- \*\*Сохранить:\*\* `hydra/`, `main.py`, `tests/`, `bootstrap.sh`, `\*.md`, `.github/`, `LICENSE`.

# 

# \### Шаги

# 1\. \*\*Поставить reference-tag ПЕРЕД удалением\*\* (чтобы на этапах 5–9 подсматривать готовую сетевую логику демонов):

# &#x20;  ```bash

# &#x20;  git tag legacy-reference

# &#x20;  ```

# 2\. Создать ветку: `git checkout -b feat/v2-00-cleanup`.

# 3\. Удалить файлы:

# &#x20;  ```bash

# &#x20;  git rm -r vless\_installer/

# &#x20;  git rm hysteria2\_main\_patch.py hysteria2\_state\_example.json migrate\_awg\_to\_h2.py verify.py

# &#x20;  ```

# 4\. Проверить отсутствие висячих импортов: в `hydra/` и `main.py` не должно остаться `import vless\_installer` / `from vless\_installer`. Используй grep.

# 5\. Прогон:

# &#x20;  ```bash

# &#x20;  python -m py\_compile main.py hydra/\*\*/\*.py

# &#x20;  python -m pytest tests/ -q

# &#x20;  ```

# 6\. Коммит: `refactor: удалить legacy xray/vless ядро (vless\_installer)`.

# 

# \### Проверка

# \- `git ls-files | grep -i vless` → пусто.

# \- `git tag | grep legacy-reference` → есть.

# \- `python main.py` (на Linux-сервере) стартует TUI без ImportError.

# 

# \---

# 

# \# ЭТАП 1 — Общие утилиты (foundation)

# 

# \*\*Цель:\*\* вынести повторяющуюся сетевую/установочную логику в переиспользуемые utils, чтобы плагины были тонкими.

# \*\*Ветка:\*\* `feat/v2-01-utils`

# 

# \### Файлы (все НОВЫЕ)

# 

# \#### `hydra/utils/firewall.py`

# Вынести логику из legacy `naiveproxy.py`/`mieru.py` (`\_ipt\_\*`/`\_ufw\_\*` — там она идентична).

# ```python

# """Менеджер firewall: авто-выбор UFW/iptables, persist правил."""

# from \_\_future\_\_ import annotations

# import shutil, subprocess

# from pathlib import Path

# 

# def is\_ufw\_active() -> bool:

# &#x20;   """True если ufw есть и status: active."""

# 

# def \_ipt\_rule\_exists(table: str, chain: str, spec: list\[str]) -> bool: ...

# 

# def open\_tcp(port: int, comment: str = "hydra") -> str:

# &#x20;   """Открывает TCP порт через UFW (если активен) иначе iptables. Возвращает описание."""

# 

# def open\_udp(port: int, comment: str = "hydra") -> str: ...

# def open\_range(proto: str, start: int, end: int, comment: str = "hydra") -> str: ...

# &#x20;   # proto = "tcp" | "udp"

# 

# def close\_tcp(port: int) -> None: ...

# def close\_udp(port: int) -> None: ...

# def close\_range(proto: str, start: int, end: int) -> None: ...

# 

# def persist() -> None:

# &#x20;   """netfilter-persistent save либо /etc/iptables/rules.v4."""

# ```

# \*\*Подсказка по реализации\*\*: смотри `\_open\_port`/`\_close\_port` в legacy `naiveproxy.py` (строки \~599–614). Логика: сначала `\_ufw\_is\_active()`, если да — ufw allow/delete, иначе iptables `-I`/`-D` INPUT + `\_ipt\_persist()`. Помечать правила комментарием `-m comment --comment "<comment>"` для безопасного удаления.

# 

# \#### `hydra/utils/downloader.py`

# ```python

# """Скачивание бинарников с GitHub releases."""

# from \_\_future\_\_ import annotations

# import json, tempfile, urllib.request

# from pathlib import Path

# 

# def latest\_release(repo: str, timeout: int = 10) -> str:

# &#x20;   """Возвращает tag\_name (с 'v') последнего релиза. 'unknown' при ошибке.

# &#x20;   repo = 'owner/repo', напр. 'enfein/mieru'."""

# 

# def download(url: str, dest: Path, timeout: int = 120) -> bool: ...

# 

# def download\_github\_asset(repo: str, asset\_pattern: str, dest: Path) -> bool:

# &#x20;   """Ищет asset по имени (substring) в latest release, скачивает в dest.

# &#x20;   napr. asset\_pattern='linux-amd64.deb'."""

# 

# def verify\_elf(path: Path) -> bool:

# &#x20;   """True если первые 4 байта == b'\\\\x7fELF'."""

# 

# def extract\_tarball(archive: Path, dest: Path) -> Path:

# &#x20;   """tar -xzf archive -C dest. Возвращает dest."""

# ```

# 

# \#### `hydra/utils/crypto.py`

# ```python

# """Генерация паролей/токенов и детерминированное выведение ключей."""

# from \_\_future\_\_ import annotations

# import base64, hashlib, secrets

# 

# \# Без неоднозначных символов (0/O, 1/l/I) — для ручного ввода с телефона.

# \_PASSWORD\_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

# 

# def gen\_password(length: int = 16) -> str:

# &#x20;   """Случайный пароль из \_PASSWORD\_CHARS."""

# 

# def gen\_token(nbytes: int = 24) -> str:

# &#x20;   """secrets.token\_urlsafe(nbytes)."""

# 

# def derive\_key(purpose: str, seed: str) -> str:

# &#x20;   """Детерминированный ключ: base64(sha256(f'{purpose}|{seed}')).

# &#x20;   Используется AWG и другими плагинами для воспроизводимых per-user кредов."""

# &#x20;   digest = hashlib.sha256(f"{purpose}|{seed}".encode()).digest()

# &#x20;   return base64.b64encode(digest).decode()

# ```

# 

# \#### `hydra/utils/net.py` — дополнить существующий

# ```python

# def public\_ip() -> str:

# &#x20;   """curl -s -4 api.ipify.org (timeout 5). Fallback: 127.0.0.1."""

# 

# def local\_ip() -> str:

# &#x20;   """IP основного интерфейса через UDP-сокет к 8.8.8.8 (без отправки пакетов)."""

# 

# def detect\_arch() -> str:

# &#x20;   """'amd64' | 'arm64' через platform.machine()."""

# ```

# 

# \### Шаги

# 1\. Ветка `feat/v2-01-utils` от `main`.

# 2\. Создать 4 файла (firewall, downloader, crypto — новые; net — дополнить). Сверяться с legacy-хелперами через `git show legacy-reference:vless\_installer/modules/naiveproxy.py` (раздел «ВСПОМОГАТЕЛЬНЫЕ»).

# 3\. Создать `tests/test\_utils.py`:

# &#x20;  - `test\_gen\_password\_length` — длина и символы только из алфавита.

# &#x20;  - `test\_derive\_key\_deterministic` — одинаковый seed → одинаковый ключ.

# &#x20;  - `test\_verify\_elf` — на моке (Path с байтами `b'\\x7fELF...'` → True; `b'xxxx'` → False).

# &#x20;  - `test\_detect\_arch` — возвращает 'amd64' или 'arm64'.

# 4\. Прогон `pytest tests/test\_utils.py -q`.

# 5\. Коммит: `feat(utils): firewall/downloader/crypto/net helpers`.

# 

# \### Проверка

# \- `python -c "from hydra.utils import firewall, downloader, crypto, net"` без ошибок.

# \- `pytest tests/` зелёным.

# 

# \---

# 

# \# ЭТАП 2 — State v2 + миграция

# 

# \*\*Цель:\*\* расширить модель состояния под per-user креды и tproxy.

# \*\*Ветка:\*\* `feat/v2-02-state`

# 

# \### Файл: `hydra/core/state.py`

# 

# \### Изменения

# 1\. `User`: добавить поле

# &#x20;  ```python

# &#x20;  credentials: dict\[str, dict] = field(default\_factory=dict)

# &#x20;  ```

# &#x20;  Per-user секреты по имени плагина. Пример: `user.credentials\["mieru"] = {"username": "...", "password": "..."}`. Детерминированные плагины (AWG) могут не использовать — оставляют пустым.

# 

# 2\. `ProtocolState` → переименовать тип в `PluginState` (поля те же: `enabled, port, installed, config`). Обновить все упоминания в `hydra/` (registry.py, singbox.py, menus.py, тесты). Ключ в `state.protocols` оставить строкой (историческое имя ок).

# 

# 3\. `NetworkConfig`: добавить

# &#x20;  ```python

# &#x20;  tproxy\_enabled: bool = False

# &#x20;  tproxy\_port: int = 1081   # порт dokodemo-door sing-box для TPROXY

# &#x20;  ```

# 

# 4\. `SCHEMA\_VERSION = 2`. В `\_migrate()` добавить ветку v1→v2:

# &#x20;  ```python

# &#x20;  if from\_version < 2:

# &#x20;      for u in data.get("users", \[]):

# &#x20;          u.setdefault("credentials", {})

# &#x20;      net = data.setdefault("network", {})

# &#x20;      net.setdefault("tproxy\_enabled", False)

# &#x20;      net.setdefault("tproxy\_port", 1081)

# &#x20;      data\["version"] = 2

# &#x20;  ```

# &#x20;  \*\*Важно\*\*: миграция должна правильно проставлять `version` в конце (сейчас v0→v1 только setdefault, без инкремента — исправить).

# 

# \### Шаги

# 1\. Ветка от main.

# 2\. Правки dataclass + миграция.

# 3\. Обновить `tests/test\_state.py`:

# &#x20;  - `test\_roundtrip\_with\_credentials` — сохранить/загрузить User с credentials → совпадает.

# &#x20;  - `test\_migrate\_v1\_to\_v2` — подать на вход v1-словарь без credentials/tproxy → после load\_state версия 2, поля есть.

# 4\. Прогон `pytest tests/test\_state.py -q`.

# 5\. Коммит: `feat(state): v2 schema — credentials, tproxy, миграция`.

# 

# \### Проверка

# \- Старый `state.json` (v1) грузится без ошибок, мигрируется до v2.

# \- `pytest tests/` зелёным.

# 

# \---

# 

# \# ЭТАП 3 — Plugin contract v2 (центральный)

# 

# \*\*Цель:\*\* формализовать контракт под 3 категории и per-user модель, разделить «сгенерить фрагмент» и «применить».

# \*\*Ветка:\*\* `feat/v2-03-contract`

# \*\*Это самый важный этап\*\* — от него зависят все следующие.

# 

# \### Файл: `hydra/plugins/base.py` (переписать)

# 

# ```python

# """hydra/plugins/base.py — Абстрактный интерфейс плагина v2."""

# from \_\_future\_\_ import annotations

# import enum

# from abc import ABC, abstractmethod

# from dataclasses import dataclass, field

# from hydra.core.state import AppState, User

# 

# 

# class PluginCategory(enum.Enum):

# &#x20;   TRANSPORT = "transport"      # per-user: naive, mieru, awg, telemt...

# &#x20;   ENHANCEMENT = "enhancement"  # глобальный: dnscrypt, warp, porthopping

# &#x20;   SECURITY = "security"        # глобальный: fail2ban, geoip...

# 

# 

# @dataclass

# class PluginMeta:

# &#x20;   name: str

# &#x20;   description: str

# &#x20;   category: PluginCategory

# &#x20;   version: str = "1.0.0"

# &#x20;   needs\_domain: bool = False   # для авто-проверок в TUI

# 

# 

# @dataclass

# class PluginStatus:

# &#x20;   installed: bool

# &#x20;   enabled: bool

# &#x20;   running: bool

# &#x20;   port: int = 0

# &#x20;   info: dict = field(default\_factory=dict)

# 

# 

# @dataclass

# class ConfigFragment:

# &#x20;   """Фрагмент конфига sing-box + маркеры для orchestrator/nft."""

# &#x20;   inbounds: list\[dict] = field(default\_factory=list)

# &#x20;   outbounds: list\[dict] = field(default\_factory=list)

# &#x20;   route\_rules: list\[dict] = field(default\_factory=list)

# &#x20;   # Порты демона, чей расшифрованный трафик заворачиваем в sing-box через TPROXY.

# &#x20;   nft\_tproxy\_ports: list\[int] = field(default\_factory=list)

# 

# 

# class BasePlugin(ABC):

# &#x20;   meta: PluginMeta

# 

# &#x20;   # ── жизненный цикл ──────────────────────────────────────────────

# &#x20;   @abstractmethod

# &#x20;   def install(self) -> bool: ...

# &#x20;   @abstractmethod

# &#x20;   def uninstall(self) -> bool: ...

# &#x20;   @abstractmethod

# &#x20;   def status(self) -> PluginStatus: ...

# 

# &#x20;   # ── конфиг sing-box: ЧИСТАЯ функция, без side-effects ───────────

# &#x20;   @abstractmethod

# &#x20;   def configure(self, state: AppState) -> ConfigFragment: ...

# 

# &#x20;   # ── применение: все side-effects (reload, syncconf, nft) ────────

# &#x20;   def apply(self, state: AppState) -> bool:

# &#x20;       """По умолчанию no-op. Переопределить: перезапуск демона/awg syncconf."""

# &#x20;       return True

# 

# &#x20;   # ── трафик: получает state (исправление старого дизайна) ────────

# &#x20;   def traffic(self, state: AppState) -> dict\[str, int]:

# &#x20;       """{email: bytes}. Пустой словарь если не поддерживается."""

# &#x20;       return {}

# 

# &#x20;   # ── TRANSPORT-only: per-user (no-op дефолты для ENHANCEMENT/SECURITY) ──

# &#x20;   def on\_user\_add(self, user: User, state: AppState) -> None: pass

# &#x20;   def on\_user\_remove(self, user: User, state: AppState) -> None: pass

# &#x20;   def on\_user\_block(self, user: User, state: AppState) -> None: pass

# 

# &#x20;   def generate\_client\_config(self, user: User, state: AppState) -> str:

# &#x20;       """Клиентский .conf / JSON для импорта в приложение."""

# &#x20;       return ""

# &#x20;   def client\_link(self, user: User, state: AppState) -> str:

# &#x20;       """Share-ссылка (mierus://, naive+https://, wg:// ...)."""

# &#x20;       return ""

# &#x20;   def connected\_clients(self) -> list\[dict]:

# &#x20;       """\[{email, online, rx, tx, last\_handshake, ...}] для статуса."""

# &#x20;       return \[]

# 

# &#x20;   # ── хуки включения/выключения ───────────────────────────────────

# &#x20;   def on\_enable(self, state: AppState) -> None: pass

# &#x20;   def on\_disable(self, state: AppState) -> None: pass

# ```

# 

# \### Ключевые решения

# \- \*\*`configure()` — чистая\*\*: генерит фрагмент, не трогает систему. Все side-effects (запись `awg0.conf`, `awg syncconf`, systemd reload) — в `apply()`. AWG больше не нарушает контракт.

# \- \*\*`traffic(state)`\*\*: получает state → AWG строит pubkey→email из `state.users`, файл `awg\_peers.json` убирается (этап 5).

# \- \*\*`nft\_tproxy\_ports`\*\* во фрагменте → orchestrator сам строит nft-правила для этих портов (единая точка, этап 4).

# \- Per-user методы с no-op дефолтами → ENHANCEMENT/SECURITY их не реализуют; orchestrator вызывает только у TRANSPORT.

# 

# \### Шаги

# 1\. Ветка от main.

# 2\. Переписать `hydra/plugins/base.py` целиком (код выше).

# 3\. Обновить `tests/test\_plugins.py`:

# &#x20;  - `MockPlugin` (ENHANCEMENT) — install/configure/status/traffic.

# &#x20;  - `MockTransportPlugin` (TRANSPORT) — реализует `on\_user\_add` (кладёт креды в `user.credentials\["mock"]`), `client\_link` возвращает `mock://...`, `connected\_clients`.

# &#x20;  - Тест: `test\_transport\_user\_add\_creates\_credentials`.

# 4\. Прогон `pytest tests/test\_plugins.py -q`.

# 5\. Коммит: `feat(contract): plugin v2 — категории, per-user, configure/apply split`.

# 

# \### Проверка

# \- `python -c "from hydra.plugins.base import BasePlugin, PluginCategory, ConfigFragment"` без ошибок.

# \- `pytest tests/` зелёным (старые плагины amneziawg/dnscrypt/warp пока сломаны относительно нового контракта — это ок, починим на этапах 5/10; но MockPlugin и MockTransportPlugin проходят).

# 

# > \*\*Важно:\*\* после этого этапа существующие плагины (amneziawg/dnscrypt/warp в `hydra/plugins/`) временно не соответствуют контракту. Это нормально — registry на этапе 4 импортирует их, но `@abstractmethod` не даст инстанцировать. Поэтому \*\*этап 5 (полировка AWG) обязателен до registry\*\*. Чтобы не блокировать работу, можно временно закомментировать старые плагины в registry до этапа 5.

# 

# \---

# 

# \# ЭТАП 4 — Orchestrator + Registry discovery + nft

# 

# \*\*Цель:\*\* единая точка применения конфига; реестр с фильтром по категориям; nft TPROXY-механика.

# \*\*Ветка:\*\* `feat/v2-04-orchestrator`

# 

# \### Файлы

# 

# \#### `hydra/plugins/registry.py` (переписать)

# ```python

# """Реестр плагинов: discovery, фильтры по категориям, сборка фрагментов."""

# from \_\_future\_\_ import annotations

# from typing import Optional

# from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory

# from hydra.plugins.amneziawg.plugin import AmneziaWGPlugin   # этап 5

# \# откладывать импорт mieru до этапа 6

# from hydra.core.state import AppState

# 

# \_PLUGINS: list\[BasePlugin] = \[

# &#x20;   AmneziaWGPlugin(),

# &#x20;   # MieruPlugin(),  # раскомментировать на этапе 6

# ]

# 

# def all\_plugins() -> list\[BasePlugin]: return \_PLUGINS

# def get(name: str) -> Optional\[BasePlugin]:

# &#x20;   for p in \_PLUGINS:

# &#x20;       if p.meta.name == name: return p

# &#x20;   return None

# def transports() -> list\[BasePlugin]:  return \[p for p in \_PLUGINS if p.meta.category == PluginCategory.TRANSPORT]

# def enhancements() -> list\[BasePlugin]: return \[p for p in \_PLUGINS if p.meta.category == PluginCategory.ENHANCEMENT]

# def security() -> list\[BasePlugin]:    return \[p for p in \_PLUGINS if p.meta.category == PluginCategory.SECURITY]

# 

# def enabled(state: AppState, category: PluginCategory | None = None) -> list\[BasePlugin]:

# &#x20;   """Включённые плагины (опционально по категории)."""

# &#x20;   pool = \_PLUGINS if category is None else \[p for p in \_PLUGINS if p.meta.category == category]

# &#x20;   return \[p for p in pool if state.protocols.get(p.meta.name) and state.protocols\[p.meta.name].enabled]

# 

# def collect\_fragments(state: AppState) -> dict\[str, ConfigFragment]:

# &#x20;   fragments: dict\[str, ConfigFragment] = {}

# &#x20;   for p in enabled(state):

# &#x20;       try:

# &#x20;           f = p.configure(state)

# &#x20;           if f and (f.inbounds or f.outbounds or f.route\_rules or f.nft\_tproxy\_ports):

# &#x20;               fragments\[p.meta.name] = f

# &#x20;       except Exception:

# &#x20;           pass

# &#x20;   return fragments

# ```

# 

# \#### `hydra/core/nft.py` (НОВОЕ)

# ```python

# """nftables TPROXY: заворот трафика транспортов в sing-box."""

# from \_\_future\_\_ import annotations

# import subprocess

# from typing import TYPE\_CHECKING

# if TYPE\_CHECKING:

# &#x20;   from hydra.plugins.base import ConfigFragment

# 

# NFT\_TABLE = "hydra-tproxy"

# 

# def apply\_tproxy(fragments: dict, tproxy\_port: int = 1081) -> None:

# &#x20;   """Собирает nft\_tproxy\_ports из всех фрагментов, настраивает таблицу

# &#x20;      inet hydra-tproxy: mark + TPROXY входящего трафика этих портов → sing-box.

# &#x20;      Идемпотентно: сначала flush таблицы."""

# &#x20;   # 1. собрать уникальные порты из fragments\[\*].nft\_tproxy\_ports

# &#x20;   # 2. nft 'flush table inet hydra-tproxy' (если есть)

# &#x20;   # 3. создать таблицу + chain prerouting (mangle) + chain output

# &#x20;   # 4. для каждого порта: 'meta l4proto {tcp|udp} th dport N tproxy to :tproxy\_port accept'

# &#x20;   # Реализовать через subprocess nft -f - (heredoc).

# 

# def clear\_tproxy() -> None:

# &#x20;   """Удалить таблицу hydra-tproxy целиком."""

# &#x20;   subprocess.run(\["nft", "delete", "table", "inet", NFT\_TABLE], capture\_output=True)

# 

# def persist() -> None:

# &#x20;   """nft list ruleset > /etc/nftables.conf (или /etc/iptables/rules.v4 fallback)."""

# ```

# \*\*Подсказка\*\*: точный синтаксис sing-box tproxy уточнить через `sing-box check` (см. этап про singbox). Маркер `0x1/0x1` + `tproxy to :PORT`.

# 

# \#### `hydra/core/orchestrator.py` (НОВОЕ) — единый pipeline

# ```python

# """Единая точка применения конфигурации и управления плагинами/юзерами."""

# from \_\_future\_\_ import annotations

# from hydra.core.state import AppState, User, save\_state, get\_protocol, find\_user

# from hydra.core import singbox, nft

# from hydra.plugins.registry import collect\_fragments, enabled, get, transports

# 

# def apply\_config(state: AppState) -> bool:

# &#x20;   """Единый pipeline. Возвращает True если sing-box перезагружен OK."""

# &#x20;   fragments = collect\_fragments(state)

# &#x20;   cfg = singbox.generate\_config(state, fragments)

# &#x20;   if not singbox.write\_config(cfg):

# &#x20;       return False

# &#x20;   # TPROXY-правила для портов транспортов

# &#x20;   try:

# &#x20;       if state.network.tproxy\_enabled:

# &#x20;           nft.apply\_tproxy(fragments, state.network.tproxy\_port)

# &#x20;       else:

# &#x20;           nft.clear\_tproxy()

# &#x20;   except Exception:

# &#x20;       pass

# &#x20;   return singbox.reload()

# 

# def install\_plugin(state: AppState, name: str) -> bool:

# &#x20;   p = get(name)

# &#x20;   if not p: return False

# &#x20;   ok = p.install()

# &#x20;   proto = get\_protocol(state, name)

# &#x20;   proto.installed = ok

# &#x20;   save\_state(state)

# &#x20;   return ok

# 

# def uninstall\_plugin(state: AppState, name: str) -> bool:

# &#x20;   p = get(name)

# &#x20;   if not p: return False

# &#x20;   ok = p.uninstall()

# &#x20;   proto = get\_protocol(state, name)

# &#x20;   proto.installed = False; proto.enabled = False

# &#x20;   save\_state(state)

# &#x20;   apply\_config(state)

# &#x20;   return ok

# 

# def enable(state: AppState, name: str) -> bool:

# &#x20;   p = get(name)

# &#x20;   if not p: return False

# &#x20;   p.on\_enable(state)

# &#x20;   proto = get\_protocol(state, name); proto.enabled = True

# &#x20;   save\_state(state)

# &#x20;   return apply\_config(state)

# 

# def disable(state: AppState, name: str) -> bool:

# &#x20;   p = get(name)

# &#x20;   if not p: return False

# &#x20;   p.on\_disable(state)

# &#x20;   proto = get\_protocol(state, name); proto.enabled = False

# &#x20;   save\_state(state)

# &#x20;   return apply\_config(state)

# 

# \# ── User CRUD fan-out ─────────────────────────────────────────────

# def add\_user(state: AppState, user: User) -> None:

# &#x20;   from hydra.core.state import add\_user as \_add

# &#x20;   \_add(state, user)

# &#x20;   for p in transports():

# &#x20;       if state.protocols.get(p.meta.name) and state.protocols\[p.meta.name].enabled:

# &#x20;           try: p.on\_user\_add(user, state)

# &#x20;           except Exception: pass

# &#x20;   save\_state(state)

# &#x20;   apply\_config(state)

# 

# def remove\_user(state: AppState, email: str) -> None:

# &#x20;   u = find\_user(state, email)

# &#x20;   if not u: return

# &#x20;   for p in transports():

# &#x20;       if state.protocols.get(p.meta.name) and state.protocols\[p.meta.name].enabled:

# &#x20;           try: p.on\_user\_remove(u, state)

# &#x20;           except Exception: pass

# &#x20;   state.users = \[x for x in state.users if x.email != email]

# &#x20;   save\_state(state)

# &#x20;   apply\_config(state)

# 

# def block\_user(state: AppState, email: str) -> None:

# &#x20;   u = find\_user(state, email)

# &#x20;   if not u: return

# &#x20;   u.blocked = True

# &#x20;   for p in transports():

# &#x20;       if state.protocols.get(p.meta.name) and state.protocols\[p.meta.name].enabled:

# &#x20;           try: p.on\_user\_block(u, state)

# &#x20;           except Exception: pass

# &#x20;   save\_state(state)

# &#x20;   apply\_config(state)

# ```

# 

# \#### `hydra/core/singbox.py` — правки

# 1\. В `\_base\_config(state)` добавить два базовых inbound'а (если ещё нет):

# &#x20;  ```python

# &#x20;  config\["inbounds"].append({

# &#x20;      "type": "direct", "tag": "tproxy-in",

# &#x20;      "listen": "::", "listen\_port": state.network.tproxy\_port,

# &#x20;      "network": "tcp", "sniff": True,

# &#x20;  })

# &#x20;  config\["inbounds"].append({

# &#x20;      "type": "socks", "tag": "socks-in",

# &#x20;      "listen": "127.0.0.1", "listen\_port": 1080,

# &#x20;  })

# &#x20;  ```

# &#x20;  > Точный синтаксис tproxy для sing-box 1.12+ уточнить в доках / проверить `sing-box check`. Если tproxy-inbound невалиден — оставить пока только socks-in, tproxy-заворот добавить когда будет проверен.

# 2\. `generate\_config(state, fragments)` — теперь принимает `dict\[str, ConfigFragment]` напрямую (убрать ручную распаковку dict-of-dict). Итерация:

# &#x20;  ```python

# &#x20;  for name, frag in fragments.items():

# &#x20;      config\["inbounds"].extend(frag.inbounds)

# &#x20;      config\["outbounds"].extend(frag.outbounds)

# &#x20;      config\["route"]\["rules"].extend(frag.route\_rules)

# &#x20;  ```

# 

# \### Шаги

# 1\. Ветка от main.

# 2\. Написать `nft.py`, `orchestrator.py`; переписать `registry.py`; правки `singbox.py`.

# 3\. Тесты `tests/test\_orchestrator.py` (на моках — подменить registry.collect\_fragments и singbox.write\_config):

# &#x20;  - `test\_apply\_config\_pipeline` — фрагмент от мока → write\_config вызван → reload вызван.

# &#x20;  - `test\_add\_user\_fanout` — add\_user вызывает on\_user\_add у включённого мок-транспорта.

# &#x20;  - `test\_block\_user\_calls\_on\_user\_block`.

# 4\. Прогон `pytest`.

# 5\. Коммит: `feat(core): orchestrator + registry discovery + nft tproxy`.

# 

# \### Проверка

# \- `pytest tests/` зелёным.

# \- (На сервере) `apply\_config(state)` с одним плагином пишет валидный `config.json` (`sing-box check -c /etc/sing-box/config.json` OK).

# 

# \---

# 

# \# ЭТАП 5 — Полировка AmneziaWG под контракт v2

# 

# \*\*Цель:\*\* привести AWG в соответствие с контрактом v2; убрать special-case в меню.

# \*\*Ветка:\*\* `feat/v2-05-awg`

# 

# \### Файл: `hydra/plugins/amneziawg/plugin.py` (переписать под v2)

# 

# \### Изменения

# 1\. `meta`:

# &#x20;  ```python

# &#x20;  meta = PluginMeta(

# &#x20;      name="amneziawg",

# &#x20;      description="AmneziaWG 2.0: WireGuard с обфускацией (kernel-модуль)",

# &#x20;      category=PluginCategory.TRANSPORT,

# &#x20;      version="2.0.0",

# &#x20;      needs\_domain=False,

# &#x20;  )

# &#x20;  ```

# 2\. \*\*Разделить configure/apply\*\* (главное):

# &#x20;  - `configure(state) -> ConfigFragment`: генерит текст секций `\[Peer]` (как раньше, из `state.users`), но \*\*НЕ пишет файл и НЕ вызывает syncconf\*\*. Возвращает `ConfigFragment(route\_rules=\[{"ip\_cidr": \[network], "outbound": "direct"}])`. \*\*nft\_tproxy\_ports = \[]\*\* (AWG терминирует трафик в ядре awg0, TPROXY не нужен).

# &#x20;  - `apply(state) -> bool`: пишет `awg0.conf` (через сохранённый в `self` или пересчитанный peers-текст), `awg syncconf` / `systemctl start awg-quick@awg0`. Бывшая side-effect часть.

# &#x20;  - \*\*Секрет\*\*: чтобы не считать peers дважды, можно в `configure` кешировать `self.\_pending\_conf` (строка) и `apply` пишет его. Или `apply` сам вызывает внутренний `\_build\_conf(state)` — на выбор, главное сохранить идемпотентность.

# 3\. \*\*Per-user методы\*\*:

# &#x20;  - `on\_user\_add/remove/block(user, state)` → `self.configure(state); self.apply(state)` (пересобрать пиры и применить вживую).

# &#x20;  - `generate\_client\_config(user, state)` — оставить как есть.

# &#x20;  - `client\_link(user, state)` — оставить.

# &#x20;  - `connected\_clients()` — переименовать из `connected\_peers()` (возвращаемый dict оставить).

# 4\. \*\*`traffic(state)`\*\*: убрать чтение `PEER\_MAP`. Вместо этого — построить `{pubkey: email}` из `state.users`:

# &#x20;  ```python

# &#x20;  pub\_to\_email = {self.\_derive\_pubkey(u.uuid): u.email for u in state.users if not u.blocked}

# &#x20;  ```

# &#x20;  Удалить `\_write\_peer\_map`/`\_read\_peer\_map` и константу `PEER\_MAP`.

# 5\. Зарегистрировать в `registry.py` (уже импортирован в этапе 4).

# 

# \### Шаги

# 1\. Ветка от main.

# 2\. Переписать plugin.py.

# 3\. Тесты `tests/test\_awg\_plugin.py` (на моках subprocess — подменить `awg pubkey`/`awg show`):

# &#x20;  - `test\_configure\_returns\_route\_rule` — без side-effects (не пишет файл на моке).

# &#x20;  - `test\_traffic\_uses\_state` — fake `state.users` + mock `awg show transfer` → `{email: bytes}`.

# &#x20;  - `test\_on\_user\_add\_triggers\_apply`.

# 4\. В `hydra/ui/menus.py` убрать `menu\_plugin\_awg`, `\_resync\_awg` (они уйдут на этапе 8, но уже сейчас не вызывать `\_resync\_awg` — оставить TODO). Минимально: закомментировать special-case routing в `menu\_protocols`, чтобы AWG шёл через generic `menu\_plugin` (этап 8 допилит).

# 5\. Прогон `pytest`.

# 6\. Коммит: `feat(amneziawg): контракт v2 — configure/apply split, traffic(state), убрать PEER\_MAP`.

# 

# \### Проверка

# \- `pytest tests/` зелёным.

# \- (На сервере) добавить юзера → `awg show awg0` показывает нового пира; `generate\_client\_config` валиден; трафик считается через `traffic(state)`.

# 

# \---

# 

# \# ЭТАП 6 — Порт mieru (reference TRANSPORT-плагин)

# 

# \*\*Цель:\*\* эталонная реализация transport-плагина. После этого этапа mieru = \*\*шаблон\*\*, по которому портятся все остальные (этап 9).

# \*\*Ветка:\*\* `feat/v2-06-mieru`

# 

# \### Файлы (НОВЫЕ): `hydra/plugins/mieru/\_\_init\_\_.py`, `hydra/plugins/mieru/plugin.py`

# 

# \### Логика (сверять с `git show legacy-reference:vless\_installer/modules/mieru.py`)

# 

# \#### `install()`

# \- Скачать mita через `utils/downloader` (`.deb` если dpkg, иначе tar.gz). См. legacy `\_install\_mita\_package`.

# \- Создать системного юзера `mita` (`useradd --system --no-create-home --shell /usr/sbin/nologin mita`).

# \- Установить chrony через apt (NTP обязателен, ±30 сек) — `utils` + `subprocess`.

# \- Создать systemd `mita.service` (`ExecStart=mita run`, `Type=simple`, `Restart=on-failure`). См. legacy `\_install\_service`.

# \- Открыть порты через `utils/firewall.open\_range/udp` (default 2012–2022 TCP).

# \- Вернуть True если `\_is\_installed()` (бинок + unit).

# 

# \#### `configure(state) -> ConfigFragment`

# \- Сгенерировать `/etc/mita/server.json`: `{portBindings: \[{port/portRange, protocol}], users: \[{name, password}], loggingLevel, mtu}`. \*\*СДЕЛАТЬ ЧИСТОЙ\*\* — только сборка dict, без `mita apply`.

# \- Per-user креды \*\*детерминированные\*\* (как AWG): `username = "u" + derive\_key("mieru-user", uuid)\[:8]`, `password = derive\_key("mieru-pass", uuid)`. Не хранить в state (но можно закешировать в `user.credentials\["mieru"]` для удобства подписок).

# \- Вернуть `ConfigFragment(nft\_tproxy\_ports=\[port\_start])` — \*\*трафик mita заворачивается в sing-box через TPROXY\*\* (реализация «всё через sing-box»).

# 

# \#### `apply(state) -> bool`

# \- `mita apply config <cfg>` (через subprocess) + `systemctl reload-or-restart mita`. См. legacy `\_apply\_server\_config`.

# 

# \#### Per-user

# \- `on\_user\_add(user, state)` → `self.configure(state); self.apply(state)`; закешировать креды в `user.credentials\["mieru"]`.

# \- `on\_user\_remove/block` → аналогично (пересобрать конфиг).

# \- `generate\_client\_config(user, state) -> str` — sing-box outbound JSON (формат из legacy `\_gen\_singbox\_outbound`): `{type:"mieru", tag, server, server\_port, transport, username, password, multiplexing:"MULTIPLEXING\_HIGH"}`. Обернуть в полный sing-box конфиг для импорта.

# \- `client\_link(user, state) -> str` — `mierus://` для Karing (`\_gen\_client\_share\_link`) и NekoBox (`\_gen\_client\_share\_link\_nekobox`). Отдавать оба (через `\\n`) или только Karing-вариант + remark.

# 

# \#### `traffic(state) -> dict\[str, int]`

# \- Через iptables accounting chain (`CHAIN\_IN`/`CHAIN\_OUT`, см. legacy `mtproto.py` — там эта техника для telemt; для mita аналогично) либо через mita status API. Перевод по `user.credentials\["mieru"]\["username"]` → email.

# 

# \#### `connected\_clients() -> list\[dict]`

# \- Из `mita` status / логов.

# 

# \### Шаги

# 1\. Ветка от main.

# 2\. Создать `hydra/plugins/mieru/\_\_init\_\_.py` (пустой), `hydra/plugins/mieru/plugin.py`.

# 3\. Раскомментировать `MieruPlugin()` в `registry.py`.

# 4\. Тесты `tests/test\_mieru\_plugin.py`:

# &#x20;  - `test\_configure\_returns\_fragment\_with\_port` — фрагмент содержит `nft\_tproxy\_ports=\[2012]`.

# &#x20;  - `test\_client\_link\_valid\_uri` — начинается с `mierus://`.

# &#x20;  - `test\_on\_user\_add\_sets\_credentials` — после on\_user\_add в `user.credentials\["mieru"]` есть username/password.

# &#x20;  - `test\_deterministic\_creds` — одинаковый uuid → одинаковые креды.

# 5\. Прогон `pytest`.

# 6\. Коммит: `feat(mieru): reference TRANSPORT-плагин (mita + nft-tproxy + детерминированные креды)`.

# 

# \### Проверка

# \- `pytest tests/` зелёным.

# \- (На сервере) `enable mieru` → mita поднят, порт в nft-tproxy; добавить юзера → креды сгенерены, `client\_link` импортируется в Karing.

# 

# \---

# 

# \# ЭТАП 7 — Services на registry (без хардкодов)

# 

# \*\*Цель:\*\* подписки/трафик/синк/бот работают с любым плагином через контракт.

# \*\*Ветка:\*\* `feat/v2-07-services`

# 

# \### Файлы

# 

# \#### `hydra/services/subscriptions/generator.py` (переписать)

# ```python

# from hydra.plugins.registry import transports, enabled

# from hydra.core.state import AppState, User

# 

# def client\_links(user: User, state: AppState) -> list\[str]:

# &#x20;   """Список client\_link() всех включённых транспортов."""

# &#x20;   return \[p.client\_link(user, state)

# &#x20;           for p in transports()

# &#x20;           if state.protocols.get(p.meta.name) and state.protocols\[p.meta.name].enabled

# &#x20;           and p.client\_link(user, state)]

# 

# def client\_singbox\_config(user: User, state: AppState) -> dict:

# &#x20;   """Единый sing-box конфиг: outbounds из всех включённых транспортов."""

# &#x20;   outbounds = \[]

# &#x20;   for p in transports():

# &#x20;       if not (state.protocols.get(p.meta.name) and state.protocols\[p.meta.name].enabled):

# &#x20;           continue

# &#x20;       cfg = p.generate\_client\_config(user, state)

# &#x20;       # распарсить outbound из cfg (плагин отдаёт либо JSON-строку, либо .conf)

# &#x20;       ...  # см. реализацию

# &#x20;   outbounds.append({"type": "direct", "tag": "direct"})

# &#x20;   return {"log": {"level": "info"}, "outbounds": outbounds, "route": {"final": outbounds\[0]\["tag"] if outbounds else "direct"}}

# 

# def generate\_base64\_sub(user: User, state: AppState) -> str:

# &#x20;   import base64

# &#x20;   return base64.b64encode("\\n".join(client\_links(user, state)).encode()).decode()

# ```

# \- \*\*Убрать\*\* хардкоды naiveproxy/mieru/amneziawg и сломанные `{{AWG\_CLIENT\_PRIVATE\_KEY}}` плейсхолдеры.

# \- HTTP handler `/sub?token=<uuid>\&format=singbox|base64` — оставить, использует новые функции.

# 

# \#### `hydra/services/traffic.py` (переписать)

# ```python

# from hydra.plugins.registry import transports

# from hydra.core.state import AppState

# 

# def collect\_traffic(state: AppState) -> dict\[str, int]:

# &#x20;   """{email: total\_bytes} — сумма traffic(state) по включённым транспортам."""

# &#x20;   result: dict\[str, int] = {}

# &#x20;   for p in transports():

# &#x20;       if not (state.protocols.get(p.meta.name) and state.protocols\[p.meta.name].enabled):

# &#x20;           continue

# &#x20;       try:

# &#x20;           for email, b in p.traffic(state).items():

# &#x20;               result\[email] = result.get(email, 0) + b

# &#x20;       except Exception:

# &#x20;           pass

# &#x20;   return result

# ```

# (Использует `transports()` + фильтр enabled, не `get\_all()` как раньше.)

# 

# \#### `hydra/services/sync\_agent.py`

# \- После блокировки юзера по лимиту/TTL вызывать `orchestrator.block\_user(state, email)` (это делает reconfigure live). Убрать неиспользуемые импорты.

# 

# \#### `hydra/services/telegram/bot.py`

# \- Добавить QR (`qrencode -t UTF8`) в `/link` и `/config`.

# \- Использует новый generator (`client\_links`, `client\_singbox\_config`).

# 

# \### Шаги

# 1\. Ветка от main.

# 2\. Переписать 4 файла.

# 3\. Тесты `tests/test\_subscriptions.py`:

# &#x20;  - `test\_client\_links\_aggregates\_plugins` — мок-транспорт отдаёт link → base64\_sub содержит его.

# &#x20;  - `test\_collect\_traffic\_sums\_plugins` — два мок-транспорта → сумма.

# 4\. Прогон `pytest`.

# 5\. Коммит: `feat(services): subscriptions/traffic/sync на registry, без хардкодов`.

# 

# \### Проверка

# \- `pytest tests/` зелёным.

# \- (На сервере) HTTP `/sub?token=<uuid>` отдаёт ссылки всех включённых транспортов.

# 

# \---

# 

# \# ЭТАП 8 — TUI: generic plugin-меню + единый apply

# 

# \*\*Цель:\*\* убрать дублирование apply-pipeline и special-case AWG; единое меню плагинов.

# \*\*Ветка:\*\* `feat/v2-08-tui`

# \*\*Завершает MVP v2.0-beta.\*\*

# 

# \### Файл: `hydra/ui/menus.py`

# 

# \### Изменения

# 1\. \*\*`menu\_protocols`\*\* → единый список из `registry.all\_plugins()`, сгруппированный по категориям (Транспорты / Надстройки / Безопасность). Пункт «A — Применить конфиг» → `orchestrator.apply\_config(state)`.

# 

# 2\. \*\*`menu\_plugin(state, plugin)`\*\* — \*\*одна\*\* функция для всех плагинов (включая AWG):

# &#x20;  - Статус-панель из `plugin.status()`.

# &#x20;  - Действия:

# &#x20;    - Установить → `orchestrator.install\_plugin(state, name)`.

# &#x20;    - Удалить → `orchestrator.uninstall\_plugin(state, name)`.

# &#x20;    - Включить/Выключить → `orchestrator.enable/disable(state, name)`.

# &#x20;    - Статус/Трафик → `plugin.status()` / `plugin.connected\_clients()`.

# &#x20;    - Показать клиентский конфиг (для TRANSPORT) → `plugin.generate\_client\_config` + `plugin.client\_link` + QR.

# 

# 3\. \*\*Убрать\*\* `menu\_plugin\_awg`, `\_resync\_awg`, и оба дублированных `collect\_fragments→generate\_config→write\_config→reload` (теперь `orchestrator.apply\_config(state)`).

# 

# 4\. \*\*`menu\_users` → `\_add\_user`\*\* вызывает `orchestrator.add\_user(state, user)` (fan-out по транспортам). `\_delete\_user`/`\_toggle\_block` → `orchestrator.remove\_user`/`block\_user`.

# 

# 5\. \*\*Клиентские ссылки/QR\*\* в показе юзера:

# &#x20;  ```python

# &#x20;  for p in transports():

# &#x20;      if enabled: print(p.client\_link(user, state))

# &#x20;  ```

# 

# \### Шаги

# 1\. Ветка от main.

# 2\. Рефакторинг `menus.py` (файл \~950 строк — переписать меню плагинов/юзеров, оставить menus для telegram/monitoring/security как есть пока).

# 3\. Ручной тест TUI: `python main.py` — все меню работают; включение mieru/awg применяет конфиг за один шаг; добавление юзера создаёт креды у всех включённых транспортов.

# 4\. Коммит: `feat(tui): generic plugin-menu + единый apply pipeline`.

# 

# \### Проверка

# \- `python main.py` стартует без ошибок.

# \- Включить AWG → `awg0` поднят; включить mieru → mita поднят; оба видны в статусе.

# \- Добавить юзера → у AWG появляется пир, у mieru — креды; обе ссылки показываются.

# 

# > 🎉 \*\*MVP v2.0-beta готов.\*\* Дальше — инкрементальное добавление плагинов по шаблону mieru.

# 

# \---

# 

# \# ЭТАП 9 — Остальные транспорты (по шаблону mieru)

# 

# Каждый подэтап — отдельная ветка `feat/v2-09-<name>`. Строго по матрице mieru (install/configure/apply/per-user/traffic/connected\_clients). Источник: `git show legacy-reference:vless\_installer/modules/<name>.py`.

# 

# | Подэтап | Плагин | Источник | Особенности |

# |---|---|---|---|

# | 9.1 | `naive` | `hydra/plugins/naive/plugin.py` | ✅ caddy-forwardproxy-naive; Caddyfile + probe\_resistance + фейк-сайт; needs\_domain=True; `nft\_tproxy\_ports=\[443]`; sing-box outbound `type:naive` |

# | 9.2 | `telemt` | `hydra/plugins/telemt/plugin.py` | ✅ Rust MTProto; multi-user secret; TOML-конфиг; TLS domain (SNI); `nft_tproxy_ports`; sing-box outbound `type:mtproto` |

# | 9.3 | `vkturn` | `hydra/plugins/vkturn/plugin.py` | ✅ FreeTurn (vk-turn-proxy, UDP:56000); single-инстанс, не per-user; динамический systemd unit rewrite (порты из config); sing-box outbound `type:vmess` |

# | 9.4 | `wdtt` | `hydra/plugins/wdtt/plugin.py` | ✅ qWDTT (WG over TURN ВК); per-user пароли `derive_key("wdtt-pass", uuid)`; systemd unit; iptables MASQUERADE для WG-подсети; `nft_tproxy_ports=[56000]`; sing-box outbound `type:wireguard`; Go-сборка из SpaceNeuroX/proxy-turn-vk-android |

# | 9.5 | `olcrtc` | `hydra/plugins/olcrtc/plugin.py` | ✅ TCP-over-WebRTC; multi-link (systemd template `olcrtc@.service`); per-user YAML-конфиги, SOCKS :8808; Jitsi auto-room при on_user_add; Go-сборка из openlibrecommunity/olcrtc; без nft_tproxy |

# | 9.6 | `slipgate` | slipgate.py | DNS-туннели (DNSTT/Noiz/Slipstream/VayDNS); \*\*needs\_domain + NS-делегирование\*\*; :53/udp |

# | 9.7 | `webdav` | webdav\_tunnel.py | SOCKS5 over WebDAV; режимы selfhosted/external; single-login (делиться ссылкой) |

# 

# \### Для каждого подэтапа (шаблон)

# 1\. Ветка `feat/v2-09-<name>` от main.

# 2\. Создать `hydra/plugins/<name>/\_\_init\_\_.py` + `plugin.py` (category=TRANSPORT).

# 3\. Сверять install/config-логику с legacy через `git show legacy-reference:...`.

# 4\. Зарегистрировать в `registry.py`.

# 5\. Тесты `tests/test\_<name>\_plugin.py` (configure возвращает фрагмент с правильным портом; client\_link валидный; on\_user\_add создаёт креды/конфиг).

# 6\. `pytest` + коммит `feat(<name>): TRANSPORT-плагин`.

# 

# \---

# 

# \# ЭТАП 10 — Надстройки и Безопасность (ENHANCEMENT/SECURITY)

# 

# Каждый — отдельная ветка. Category = ENHANCEMENT или SECURITY. Per-user методы не реализуются (no-op). Источник: `git show legacy-reference:...`.

# 

# | Подэтап | Плагин | Категория | Что делает |

# |---|---|---|---|

# | 10.1 | `dnscrypt` | ENHANCEMENT | systemd `dnscrypt-proxy` :5300; sing-box DNS server → `127.0.0.1:5300`; \*\*configure отдаёт DNS-фрагмент\*\* (зафиксировать то, что сейчас мёртвый `\_dns\_config` в singbox.py) |

# | 10.2 | `warp` | ENHANCEMENT | sing-box wireguard-outbound `tag:warp` + route-rules для AI-доменов (openai/anthropic/gemini...); \*\*убрать избыточный wg-quick kernel-интерфейс\*\* (outbound самодостаточен) |

# | 10.3 | `porthopping` | ENHANCEMENT | nftables PREROUTING REDIRECT диапазона → реальный порт (переписать с iptables на nft); `configure` отдаёт пустой фрагмент, `apply` ставит правила |

# | 10.4 | `fail2ban` | SECURITY | jails: sing-box/caddy/sshd/nginx; `apply` пишет `jail.d/\*.local`, `status` сводка банов; legacy `fail2ban\_manager.py` |

# | 10.5 | `geoip` | SECURITY | nft ipset + страна-блок (РФ по умолчанию); route\_rules в sing-box при возможности; legacy `ingress\_geoip.py` |

# | 10.6 | `honeypot` | SECURITY | ловушка-порты; legacy `honeypot.py` |

# | 10.7 | `ipban` | SECURITY | ipset-управление (через `utils/firewall`); legacy `ipban.py` + `ipset\_persist.py` |

# 

# \---

# 

# \# ЭТАП 11 — Тесты, документация, релиз

# 

# \### Тесты

# \- Покрыть: orchestrator, registry, state-v2, mieru/awg (на моках subprocess), subscriptions, utils.

# \- Цель: >70% строк по `hydra/` (`pytest --cov=hydra`).

# \- Все системные вызовы (subprocess, Path.write) — через моки/monkeypatch, тесты не требуют root.

# 

# \### Документация

# \- `ARCHITECTURE.md` — схема слоёв, контракты, матрица плагинов, диаграмма трафика (клиент → демон → nft-tproxy → sing-box → надстройки → интернет).

# \- `README.md` — обновить под v2: установка, quickstart, «как добавить плагин» (по шаблону mieru).

# \- `CHANGELOG.md` — запись v2.0.

# \- Этот `IMPLEMENTATION\_PLAN.md` — оставить как живой чек-лист (отмечать `\[x]` выполненные этапы).

# 

# \### Релиз

# \- PR `feat/v2-0` в main после этапа 8 (MVP beta).

# \- Отдельные PR на каждый плагин этапов 9–10.

# \- Тег `v2.0.0` после этапа 11.

# 

# \---

# 

# \## Чек-лист прогресса

# 

# \- \[x] 0. Очистка от xray/vless

# \- \[x] 1. Общие утилиты

# \- \[x] 2. State v2 + миграция

# \- \[x] 3. Plugin contract v2

# \- \[x] 4. Orchestrator + Registry + nft

# \- \[x] 5. Полировка AmneziaWG — ✅ `hydra/plugins/amneziawg/plugin.py`

# \- \[x] 6. Порт mieru (reference) — ✅ `hydra/plugins/mieru/plugin.py` (reference TRANSPORT impl)

# \- \[x] 7. Services на registry — ✅ все плагины зарегистрированы в `hydra/plugins/registry.py`

# \- \[x] 8. TUI generic → ✅ `hydra/ui/tui.py` + `hydra/ui/menus.py` (главное меню, протоколы, пользователи, Telegram, мониторинг, безопасность)

# \- \[x] 9.1 naive / \[x] 9.2 telemt / \[x] 9.3 vkturn / \[x] 9.4 wdtt / \[x] 9.5 olcrtc / \[x] 9.6 slipgate / \[x] 9.7 webdav

# \- \[x] 10.1 dnscrypt / \[x] 10.2 warp / \[x] 10.3 porthopping / \[ ] 10.4 fail2ban / \[ ] 10.5 geoip / \[ ] 10.6 honeypot / \[ ] 10.7 ipban

# \- \[ ] 11. Тесты, доки, релиз

