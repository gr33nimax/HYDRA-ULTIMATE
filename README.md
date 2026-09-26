<div align="center">

# 🐉 HYDRA

<img src="docs/assets/banner.png" width="760"
     alt="HYDRA — Multi-Protocol Proxy &amp; Routing Orchestrator, powered by Hydracore">

**Оркестратор многопротокольных прокси-серверов на базе Sing-Box**

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg?style=flat-square)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-green.svg?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg?style=flat-square)](https://ubuntu.com/)
[![CI](https://github.com/gr33nimax/HYDRA-ULTIMATE/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/gr33nimax/HYDRA-ULTIMATE/actions/workflows/ci.yml)

[Что вы получаете](#что-вы-получаете) ·
[Протоколы](#протоколы-и-модули) ·
[Установка](#установка) ·
[Обновление](#обновление) ·
[Документация](#документация)

</div>

---

Одна VPS, одна команда установки — и тринадцать транспортов, маршрутизация, DNS,
защитные контуры, подписки, учёт трафика и интерфейсы TUI/CLI/Telegram работают
как единый управляемый контур.

Пользователи, протоколы и сеть описаны в одном `state.json`, а конфигурации
Sing-Box, Caddy L4 и nftables — производная от него. Применение транзакционное:
с проверкой, снимком и автоматическим откатом.

```text
   вход                         обработка              выход
   ───────────────────────      ─────────────          ──────────────────
   TCP/443 ─▶ Caddy L4 · SNI ─▶ транспорты  ─┐
                                             ├─▶ Sing-Box ─▶ интернет, DNS,
   UDP     ─▶ QUIC, AWG, qWDTT, VK Calls  ───┘   маршруты     WARP

   поверх всего: AntiScan · Honeypot · Fail2ban · IPBan
                 подписки · учёт трафика · Telegram-бот
```

<table>
  <tbody>
    <tr><th scope="row">Транспорты</th><td>13</td></tr>
    <tr><th scope="row">Модули сети и защиты</th><td>6</td></tr>
    <tr><th scope="row">Интерфейсы</th><td>TUI, headless JSON-CLI, Telegram Admin Bot</td></tr>
    <tr><th scope="row">Платформа</th><td>Ubuntu 22.04+ / Debian 12+</td></tr>
    <tr><th scope="row">Python</th><td>3.10 – 3.13</td></tr>
  </tbody>
</table>

> [!IMPORTANT]
> `3.0.0` — текущая версия ветки `dev`. Это канал разработки и
> активного бета-тестирования.
> Для рабочей эксплуатации используйте чистый Ubuntu 22.04+ или Debian 12+ и
> обязательно настройте резервное копирование.

## Что вы получаете

- 🧩 **Один источник истины.** Пользователи, протоколы и сеть живут в
  `state.json`; конфигурации служб — производная от него, а не место для ручных
  правок.
- 🔄 **Изменения без страха.** Каждый шаг применения имеет снимок и откат; при
  сбое возвращаются state, конфигурации, firewall и плагины.
- 🔐 **TLS под контролем.** Сертификаты проверяются на домен, срок и соответствие
  ключу до применения.
- 🛰 **Порт 443 на несколько транспортов.** Caddy L4 разбирает SNI и отдаёт
  соединение владельцу домена; конфликт слушателей отклоняется до применения.
- 👥 **Пользователь — одна транзакция.** Добавление, блокировка, лимиты трафика и
  сроки действуют сразу во всех включённых транспортах.
- 📦 **Подписки с изоляцией транспортов.** Клиентские ссылки и профили выдаёт
  сервер подписок; защищённый формат HydraBox публикует каждый транспорт
  отдельным ресурсом.
- 🤖 **Управление откуда угодно.** TUI для настройки, `--json` CLI для cron и
  автоматизации, Telegram-бот для повседневного администрирования.
- 🛡 **Защитный контур из коробки.** AntiScan, Honeypot, Fail2ban и IPBan.
- 🧠 **Умеренные ресурсы по умолчанию.** Установка ограничивает рост journald и
  уменьшает запас heap Sing-Box без жёсткого memory cap.
- ⬆️ **Обновление как транзакция.** Новый release собирается рядом с рабочим,
  проходит preflight и переключается атомарно с откатом.

Почему это устроено именно так — [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Протоколы и модули

Каждый модуль — плагин: он декларативно объявляет возможности, зависимости,
конфликты и backup-ресурсы. Инвентарь — `hydra plugin list`.

| Транспорт | Тип |
| :--- | :--- |
| **AmneziaWG 2.0 / 3.0 / 3.1** | WireGuard: туннель обслуживает ядро |
| **AnyTLS** | обфусцированный TLS |
| **TrustTunnel** | TLS, режимы TCP и QUIC |
| **ShadowTLS** | ShadowTLS v3 + Trojan detour |
| **NaiveProxy** | HTTP/2 forward-proxy, UoT по настройке |
| **Hysteria2** | QUIC + Salamander |
| **VLESS + XHTTP** | XHTTP через Hydracore и Caddy L4 |
| **VLESS + CDN** | XHTTP через внешний CDN |
| **Mieru** | обфусцированный mTLS |
| **Snell 5 / 6** | TCP/UDP-прокси Hydracore |
| **MTProto Zig** | FakeTLS MTProxy |
| **Calls · VK** | Native Hydracore `call` в режиме VK-parasite |
| **qWDTT** | WireGuard поверх TURN |

Порты, владельцы, службы, пути и файлы состояния —
[REFERENCE.md](docs/REFERENCE.md). Какие транспорты понимают целевые клиенты
(Shadowrocket, NekoBox, Throne, HydraBox) — [COMPATIBILITY.md](docs/COMPATIBILITY.md).
Операции протоколов, параметры и примеры — [CLI.md](docs/CLI.md#плагины).

## Установка

Нужны Ubuntu 22.04+ или Debian 12+ с systemd, Python 3.10+ и права `root`.
Требования к ресурсам VPS и состав установки — [UPGRADE.md](docs/UPGRADE.md).

```bash
curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/bootstrap.sh | sudo env HYDRA_REF=dev bash
```

Установщик ставит зависимости, проверенное ядро Hydracore и изолированное
Python-окружение с командой `hydra`. Caddy L4 и конкретные протоколы включаются
позже — только те, что вам нужны.

Дальше:

```bash
sudo hydra                 # интерактивный TUI: включить протоколы и службы
sudo hydra user add alice  # пользователь во всех включённых транспортах сразу
hydra status               # желаемое и фактическое состояние
hydra check                # валидация и предпросмотр изменений
```

Протоколы включаются в TUI, потому что большинству нужен интерактивный ввод:
домен, режим обфускации, выбор портов. Дальнейшая эксплуатация полностью
доступна из CLI — [CLI.md](docs/CLI.md).

## Обновление

> [!WARNING]
> Не запускайте `bootstrap.sh` поверх рабочей установки и не обновляйтесь
> вручную через `git pull`.

```bash
curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/updater.sh | sudo env HYDRA_REF=dev bash
```

Updater фиксирует точный commit ветки, собирает новую версию отдельно от рабочей,
выполняет read-only preflight и переключает release атомарно; при любой ошибке
state, код и службы восстанавливаются. Состав снимка отката и ручное
восстановление — [UPGRADE.md](docs/UPGRADE.md).

## Документация

| Документ | О чём |
| :--- | :--- |
| [docs/](docs/) | Указатель всей документации |
| [UPGRADE.md](docs/UPGRADE.md) | Установка, обновление и откат |
| [CLI.md](docs/CLI.md) | Команды, JSON-контракт, коды ошибок, сценарии |
| [REFERENCE.md](docs/REFERENCE.md) | Модули, службы, пути, порты, файлы состояния |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Слои, инварианты, транзакции, state |
| [ANTIDPI.md](docs/ANTIDPI.md) | Обнаружение probes и политики банов |
| [COMPATIBILITY.md](docs/COMPATIBILITY.md) | Матрица «транспорт × клиент» |
| [TELEGRAM_BOT.md](docs/TELEGRAM_BOT.md) | Административный бот и уведомления |
| [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) | Добавление плагинов |
| [CHANGELOG.md](CHANGELOG.md) | История версий |

## Разработка

```bash
python verify.py     # compile + lint + полный pytest
```

Тесты удерживают не только поведение, но и архитектуру: направление
зависимостей, отсутствие циклов, лимиты размеров модулей и запрет обхода
`ApplicationService` и `HostBackend`. Карта каталогов, порядок применения и
правила расширения — [AGENT_PLAYBOOK.md](docs/AGENT_PLAYBOOK.md) и
[PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md).

## Поддержать проект

[Поддержать разработку HYDRA](https://web.tribute.tg/d/QHN).

## Связанный проект

[VLESS Ultimate](https://github.com/inferno1978/VLESS-Ultimate-Installer) —
альтернативный стек на базе Xray для VLESS/Reality и XHTTP.

## Лицензия

GNU General Public License v3.0 — см. [LICENSE](LICENSE).

Copyright © 2026 gr33nimax.
