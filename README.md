# 🐉 HYDRA v2.5.0 — Multi-Protocol Proxy & Routing Orchestrator

[![Version](https://img.shields.io/badge/version-2.5.0-blue.svg?style=flat-square)](https://github.com/gr33nimax/HYDRA-ULTIMATE)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg?style=flat-square)](https://ubuntu.com/)
[![Tests](https://img.shields.io/badge/tests-630%20passed-brightgreen.svg?style=flat-square)](tests/)

**HYDRA** — модульная платформа для развёртывания и администрирования
многопротокольных proxy-серверов на базе Sing-Box. Она объединяет транспорты,
маршрутизацию, DNS, безопасность, подписки, учёт трафика и TUI/JSON-интерфейсы
в единый управляемый контур.

> [!IMPORTANT]
> `2.5.0` — архитектурный и эксплуатационный релиз. Проект всё ещё находится
> в активном beta-тестировании; для production используйте чистый Ubuntu 20.04+
> или Debian 11+ и обязательно настройте резервное копирование.

## 📚 Документация

- [Архитектура и ключевые механизмы](docs/ARCHITECTURE.md)
- [Полное руководство Headless CLI](docs/CLI.md)
- [История изменений](CHANGELOG.md)

## 💿 Установка и запуск

### Требования

- Ubuntu 20.04+ или Debian 11+;
- Python 3.10+;
- от 512 МБ RAM и 2 ГБ диска;
- внешний IPv4 и права `root`.

### Быстрая установка

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/main/bootstrap.sh)
```

Bootstrap устанавливает зависимости, Sing-Box Extended, изолированное Python-
окружение и команду `hydra`. Caddy L4 и протоколы активируются только при
включении соответствующих модулей.

### Запуск из исходников

```bash
git clone https://github.com/gr33nimax/HYDRA-ULTIMATE /opt/hydra
cd /opt/hydra
sudo python3 main.py
```

Первичная настройка выполняется в TUI: включите нужные протоколы и системные
службы, создайте пользователей, затем проверьте состояние:

```bash
sudo hydra status
sudo hydra doctor
```

## 🧩 Поддерживаемые модули

### 🚀 Транспорты

| Модуль | Назначение |
| :--- | :--- |
| **AmneziaWG 2.0** | WireGuard-транспорт с расширенной обфускацией и TPROXY. |
| **Mieru** | Обфусцированный mTLS-транспорт с `mierus://` ссылками. |
| **NaiveProxy** | HTTP/2 proxy на базе Caddy forward-proxy. |
| **AnyTLS** | TLS-подобный обфусцированный туннель. |
| **TrustTunnel** | TLS-транспорт с TCP/QUIC режимами и Caddy decoy. |
| **Hysteria2** | QUIC-транспорт с Salamander и браузерной заглушкой. |
| **ShadowTLS** | ShadowTLS v3 с Trojan detour. |
| **Snell v4** | TCP/UDP-прокси из Sing-Box Extended. |
| **MTProto / Telemt** | Telegram MTProxy с управлением пользователями. |
| **qWDTT** | WireGuard-туннелирование поверх TURN. |

### 🌐 Сетевые и защитные службы

| Модуль | Назначение |
| :--- | :--- |
| **DNSCrypt** | Локальный шифрованный DNS-резолвер на `127.0.0.1:5300`. |
| **WARP** | Выборочная маршрутизация через Cloudflare WireGuard. |
| **Fail2ban** | Динамическая блокировка атакующих IP через nftables. |
| **Honeypot** | Обнаружение сканирования портов. |
| **IPBan** | Статические списки IP/CIDR/ASN/стран. |
| **Traffic daemon** | Учёт трафика и применение лимитов/сроков пользователей. |

Telegram-бот присутствует как экспериментальный модуль и не объявляется
production-ready в версии `2.5.0`.

## 🏗️ Архитектурный обзор

Сохранённое состояние, runtime-факты, plugin lifecycle, Sing-Box, nftables и
Caddy L4 разделены по слоям. Изменения применяются транзакционно, а TLS-
маршруты проверяются отдельно, потому что они являются самым чувствительным
артефактом системы.

Подробная схема трафика, жизненный цикл применения, HostBackend, plugin
contracts, state/runtime separation и эксплуатационные инварианты описаны в
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 🧪 Разработка и тестирование

```bash
python -m pytest -q
python -m ruff check main.py hydra tests .github/scripts/release_notes.py
python -m compileall -q hydra
```

Полный локальный набор содержит 630 тестов. CI дополнительно проверяет Python
3.10–3.13, dependency audit и Linux smoke-сценарии.

## 📂 Структура проекта

```text
HYDRA-ULTIMATE/
├── main.py                  # интерактивный TUI entrypoint
├── bootstrap.sh             # установка и подготовка VPS
├── hydra/core/              # state, orchestrator, Sing-Box, nftables, Caddy
├── hydra/plugins/           # transport, enhancement и security plugins
├── hydra/services/          # application services, traffic, sync, subscriptions
├── hydra/ui/                # TUI и presentation-модули
├── docs/                    # архитектура и headless CLI
└── tests/                   # автоматические проверки
```

## 📜 История и лицензия

- [CHANGELOG.md](CHANGELOG.md) — release notes и история версий.
- [LICENSE](LICENSE) — GNU GPLv3.

## 🔗 Связанный проект

- [VLESS Ultimate](https://github.com/inferno1978/VLESS-Ultimate-Installer) —
  альтернативный Xray-based стек для VLESS/Reality и XHTTP.

Copyright (c) 2026 gr33nimax.
