# 🐉 HYDRA v2.5.1-dev — Multi-Protocol Proxy & Routing Orchestrator

[![Version](https://img.shields.io/badge/version-2.5.1--dev-blue.svg?style=flat-square)](https://github.com/gr33nimax/HYDRA-ULTIMATE)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg?style=flat-square)](https://ubuntu.com/)
[![Tests](https://img.shields.io/badge/tests-630%20passed-brightgreen.svg?style=flat-square)](tests/)

**HYDRA** — модульная платформа для развёртывания и администрирования
многопротокольных прокси-серверов на базе Sing-Box. Она объединяет транспорты,
маршрутизацию, DNS, безопасность, подписки, учёт трафика и TUI/JSON-интерфейсы
в единый управляемый контур.

> [!IMPORTANT]
> `2.5.1-dev «FORTRESS»` — текущая ветка разработки. Проект всё ещё находится
> в активном бета-тестировании; для рабочей эксплуатации используйте чистый Ubuntu 20.04+
> или Debian 11+ и обязательно настройте резервное копирование.

## 📚 Документация

- [Архитектура и ключевые механизмы](docs/ARCHITECTURE.md)
- [Полное руководство Headless CLI](docs/CLI.md)
- [История изменений](CHANGELOG.md)

Остальная техническая документация находится в каталоге [`docs`](docs/).

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

Установщик подготавливает зависимости, Sing-Box Extended, изолированное Python-
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
| **NaiveProxy** | Прокси HTTP/2 на базе Caddy forward-proxy. |
| **AnyTLS** | TLS-подобный обфусцированный туннель. |
| **TrustTunnel** | TLS-транспорт с режимами TCP/QUIC и сайтом-заглушкой Caddy. |
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
| **Fail2ban** | Блокировка SSH и аутентификационных атак. |
| **AntiDPI** | Корреляция protocol probes и сканирования VPS с динамическим ipset. |
| **Honeypot** | Обнаружение сканирования портов. |
| **IPBan** | Статические списки IP/CIDR/ASN/стран. |
| **Traffic daemon** | Учёт трафика и применение лимитов/сроков пользователей. |

Telegram Admin Bot предоставляет кнопочное управление защитой, разбан и
категорийные уведомления. Токен бота следует защищать как root-equivalent секрет.

## 🏗️ Архитектурный обзор

Сохранённое состояние, фактическое состояние служб, жизненный цикл плагинов,
Sing-Box, nftables и
Caddy L4 разделены по слоям. Изменения применяются транзакционно, а TLS-
маршруты проверяются отдельно, потому что они являются самым чувствительным
артефактом системы.

Подробная схема трафика, жизненный цикл применения, HostBackend, контракты
плагинов, разделение state и фактического состояния, а также эксплуатационные
правила описаны в
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 🧪 Разработка и тестирование

```bash
python -m pytest -q
python -m ruff check main.py hydra tests .github/scripts/release_notes.py
python -m compileall -q hydra
```

Полный локальный набор содержит 630 тестов. CI дополнительно проверяет Python
3.10–3.13, зависимости и Linux-проверки на реальной системе.

## 📂 Структура проекта

```text
HYDRA-ULTIMATE/
├── main.py                  # точка входа в интерактивный TUI
├── bootstrap.sh             # установка и подготовка VPS
├── hydra/core/              # state, оркестратор, Sing-Box, nftables, Caddy
├── hydra/plugins/           # транспортные, сетевые и защитные плагины
├── hydra/services/          # прикладные службы, учёт, синхронизация, подписки
├── hydra/ui/                # TUI и модули представления
├── docs/                    # архитектура и headless CLI
└── tests/                   # автоматические проверки
```

## 📜 История и лицензия

- [CHANGELOG.md](CHANGELOG.md) — история версий и описания релизов.
- [LICENSE](LICENSE) — GNU GPLv3.

## 🔗 Связанный проект

- [VLESS Ultimate](https://github.com/inferno1978/VLESS-Ultimate-Installer) —
  альтернативный стек на базе Xray для VLESS/Reality и XHTTP.

Copyright (c) 2026 gr33nimax.
