<div align="center">

# 🐉 HYDRA

<img src="docs/assets/banner.png" width="760"
     alt="HYDRA — Multi-Protocol Proxy &amp; Routing Orchestrator, powered by sing-box extended">

**Оркестратор многопротокольных прокси-серверов на базе Sing-Box**

[![Version](https://img.shields.io/badge/version-2.5.5-blue.svg?style=flat-square)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-green.svg?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg?style=flat-square)](https://ubuntu.com/)
[![CI](https://github.com/gr33nimax/HYDRA-ULTIMATE/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gr33nimax/HYDRA-ULTIMATE/actions/workflows/ci.yml)

[Что вы получаете](#что-вы-получаете) ·
[Протоколы](#протоколы-и-модули) ·
[Установка](#установка) ·
[Обновление](#обновление) ·
[Документация](#документация)

</div>

---

Одна VPS, одна команда установки — и одиннадцать транспортов, маршрутизация, DNS,
защитные контуры, подписки, учёт трафика и интерфейсы TUI/CLI/Telegram работают
как единый управляемый контур.

Конфигурации служб вручную не редактируются: пользователи, протоколы и сеть
описаны в одном `state.json`, из которого генерируются конфигурации Sing-Box,
Caddy L4 и nftables. Применение — транзакционное, с проверкой и автоматическим
откатом.

```text
  вход                    обработка                        выход
  ────────────────        ─────────────────────────        ──────────────

  TCP/443 ──────────▶  Caddy L4 · разбор SNI
                         ├─▶ AnyTLS            ─┐
                         ├─▶ TrustTunnel       ─┤
                         ├─▶ ShadowTLS         ─┤
                         ├─▶ NaiveProxy        ─┤
                         ├─▶ VLESS + XHTTP     ─┤
                         └─▶ сайт-заглушка      │
                                                ├─▶ Sing-Box ─▶ интернет
  UDP/443 ──────────▶  один QUIC-транспорт     ─┤   маршруты     напрямую
  8443/udp ─────────▶  Hysteria2               ─┤   DNS          или через
  51820/udp ────────▶  AmneziaWG ─▶ TPROXY     ─┤   исходящие    WARP
  56000/udp ────────▶  qWDTT                   ─┘

  поверх всего:  AntiDPI · Honeypot · Fail2ban · IPBan
                 учёт трафика · подписки · Telegram-бот
```

<table>
  <tbody>
    <tr><th scope="row">Транспорты</th><td>11</td></tr>
    <tr><th scope="row">Модули сети и защиты</th><td>6</td></tr>
    <tr><th scope="row">Интерфейсы</th><td>TUI, headless JSON-CLI, Telegram Admin Bot</td></tr>
    <tr><th scope="row">Платформа</th><td>Ubuntu 20.04+ / Debian 11+</td></tr>
    <tr><th scope="row">Python</th><td>3.10 – 3.13</td></tr>
  </tbody>
</table>

> [!IMPORTANT]
> `2.5.5` — текущая версия ветки `main`.
> Для рабочей эксплуатации используйте чистый Ubuntu 20.04+ или Debian 11+ и
> обязательно настройте резервное копирование.

## Что вы получаете

- 🧩 **Один источник истины.** Пользователи, протоколы и сеть живут в
  `state.json`; конфигурации служб — производная от него, а не место для ручных
  правок.
- 🔄 **Изменения без страха.** Каждый шаг применения имеет снимок и откат: при
  сбое возвращаются state, конфигурации, firewall и плагины. Повторный `apply` —
  штатный сценарий, а не риск.
- 🔐 **TLS под контролем.** Сертификаты проверяются на домен, срок и соответствие
  ключу до применения; Caddy не получает маршрут без полной проверенной пары.
- 🛰 **Порт 443 на несколько транспортов.** Caddy L4 разбирает SNI и отдаёт
  соединение владельцу домена; конфликт слушателей отклоняется до применения.
- 👥 **Пользователь — одна транзакция.** Добавление, блокировка, лимиты трафика и
  сроки действуют сразу во всех включённых транспортах.
- 🤖 **Управление откуда угодно.** TUI для настройки, `--json` CLI для cron и
  автоматизации, Telegram-бот для повседневного администрирования.
- 🛡 **Защитный контур из коробки.** AntiDPI, Honeypot, Fail2ban и IPBan с
  корреляцией событий и защитой от ложных банов.
- ⬆️ **Обновление как транзакция.** Новый release собирается рядом с рабочим,
  проходит preflight, два уровня backup и атомарное переключение с откатом.

Почему это устроено именно так и какие отказы ручной сборки устраняет —
[ARCHITECTURE.md](docs/ARCHITECTURE.md#какие-отказы-устраняет-модель).

## Протоколы и модули

Каждый модуль — плагин: он декларативно объявляет возможности, зависимости,
конфликты и backup-ресурсы. Инвентарь — `hydra plugin list`.

| Транспорт | Порт по умолчанию | Тип |
| :--- | :--- | :--- |
| **AmneziaWG 2.0** | `51820/udp`, `51821/udp` | WireGuard с обфускацией |
| **AnyTLS** | `443/tcp` | обфусцированный TLS |
| **TrustTunnel** | `443/tcp`, `443/udp` | TLS, режимы TCP и QUIC |
| **ShadowTLS** | `443/tcp` | ShadowTLS v3 + Trojan detour |
| **NaiveProxy** | `443/tcp`, `443/udp` | HTTP/2 forward-proxy |
| **Hysteria2** | `8443/udp` | QUIC + Salamander |
| **VLESS + XHTTP** | `443/tcp` | XHTTP через Sing-Box Extended и Caddy L4 |
| **Mieru** | `2012–2022/tcp` | обфусцированный mTLS |
| **Snell v4** | `32000–32999/tcp` | TCP/UDP-прокси |
| **MTProto / Telemt** | `8443/tcp` | Telegram MTProxy |
| **qWDTT** | `56000/udp`, `56001/udp` | WireGuard поверх TURN |

**Сеть:** DNSCrypt (шифрованный резолвер) · WARP (выборочная маршрутизация через
Cloudflare).
**Защита:** AntiDPI · Fail2ban · Honeypot · IPBan.
**Ядро:** учёт трафика, лимиты и сроки пользователей ведёт служба
`hydra-traffic-daemon`.

У доменных транспортов есть сайт-заглушка: 11 тем на выбор — от блога и
документации до магазина и фотогалереи, — а бренд, палитра и тексты выводятся из
домена, поэтому две установки не отдают одинаковый сайт. Клиентские ссылки и
профили выдаются через сервер подписок и TUI. Полная карта модулей, портов,
служб и файлов — [REFERENCE.md](docs/REFERENCE.md).

## Установка

Нужны Ubuntu 20.04+ или Debian 11+ с systemd, Python 3.10+, от 512 МБ RAM и 2 ГБ
диска, внешний IPv4 и права `root`.

```bash
curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/main/bootstrap.sh | sudo bash
```

Установщик готовит зависимости, Sing-Box Extended, изолированное
Python-окружение и команду `hydra`. Caddy L4 и конкретные протоколы включаются
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
curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/main/updater.sh | sudo bash
```

Updater фиксирует точный commit ветки, собирает новую версию и `.venv` отдельно
от рабочей, выполняет read-only preflight, останавливает только службы HYDRA,
сохраняет проверенный backup и исходный state, мигрирует схему, переключает
release и проверяет запуск. При любой ошибке state, код, wrapper и ранее активные
службы восстанавливаются автоматически. Ход операции выводится нумерованными
этапами с понятными русскими ошибками; итоговая сводка показывает переход,
снимок отката и путь к подробному логу.

Требования, состав снимка отката и ручное восстановление —
[UPGRADE.md](docs/UPGRADE.md).

## Документация

| Документ | О чём |
| :--- | :--- |
| [docs/](docs/) | Указатель всей документации |
| [UPGRADE.md](docs/UPGRADE.md) | Установка, обновление и откат |
| [CLI.md](docs/CLI.md) | Команды, JSON-контракт, коды ошибок, сценарии |
| [REFERENCE.md](docs/REFERENCE.md) | Модули, службы, пути, порты, файлы состояния |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Слои, инварианты, транзакции, state |
| [ANTIDPI.md](docs/ANTIDPI.md) | Обнаружение probes и политики банов |
| [TELEGRAM_BOT.md](docs/TELEGRAM_BOT.md) | Административный бот и уведомления |
| [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) | Добавление плагинов |
| [CHANGELOG.md](CHANGELOG.md) | История версий |

## Структура проекта

```text
HYDRA-ULTIMATE/
├── main.py                 # точка входа в интерактивный TUI
├── bootstrap.sh            # установка и подготовка новой VPS
├── updater.sh              # однокомандный запуск обновления
├── upgrade.sh              # транзакционное ядро updater
├── verify.py               # локальная проверка: compile, lint, тесты
├── hydra/
│   ├── contracts/          # нейтральные типизированные контракты
│   ├── core/               # state, Sing-Box, nftables, Caddy L4, host
│   ├── plugins/            # транспортные, сетевые и защитные плагины
│   ├── services/           # use-cases, учёт, подписки, синхронизация
│   ├── ui/                 # TUI и модули представления
│   └── entrypoints/        # тонкие адаптеры фоновых служб
├── docs/                   # техническая документация
└── tests/                  # автоматические проверки
```

## Разработка

```bash
python verify.py     # compile + lint + полный pytest
```

Тесты удерживают не только поведение, но и архитектуру: направление
зависимостей, отсутствие циклов, лимиты размеров модулей и запрет обхода
`ApplicationService` и `HostBackend`. Правила расширения и обязательный набор
проверок — [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md).

## Поддержать проект

[Поддержать разработку HYDRA на Boosty](https://boosty.to/gr33nimax/donate).

## Связанный проект

[VLESS Ultimate](https://github.com/inferno1978/VLESS-Ultimate-Installer) —
альтернативный стек на базе Xray для VLESS/Reality и XHTTP.

## Лицензия

GNU General Public License v3.0 — см. [LICENSE](LICENSE).

Copyright © 2026 gr33nimax.
