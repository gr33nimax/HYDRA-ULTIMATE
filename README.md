# 🐉 HYDRA v1.0.0-alpha

[![Version](https://img.shields.io/badge/version-1.0.0--alpha-red.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)]()

> **HYDRA** — платформа для развёртывания прокси-серверов на базе **Sing-Box** как единого оркестратора трафика. Модульная архитектура: NaiveProxy, Mieru, AmneziaWG 2.0, DNSCrypt, WARP — всё работает через одно ядро с единой политикой роутинга, DNS и безопасности.

---

## 🏗️ Архитектура

```
Клиент → [Caddy] → Sing-Box (inbound) ──→ WARP (outbound)
                  → Sing-Box (inbound) ──→ Direct
                  → AWG (kernel)      ──→ роутинг через iptables
                  → Mieru             ──→ Direct

Все протоколы → Sing-Box DNS (DNSCrypt) → DoH/DNSCrypt upstream
Все протоколы → Sing-Box Route → GeoIP, domain rules
```

**Sing-Box** — центральный хаб: оркестрирует трафик, DNS, роутинг. Каждый протокол — плагин, отдающий фрагмент конфига.

---

## 🛠️ Стек протоколов

| Протокол | Статус | Реализация |
|---|---|---|
| **NaiveProxy** | Плагин | Caddy (TLS) → Sing-Box naive inbound |
| **Mieru** | Плагин | mTLS + random padding |
| **AmneziaWG 2.0** | Плагин | Kernel-модуль (wiresock/amneziawg-install) |
| **DNSCrypt** | Плагин | Системный DNS-прокси (127.0.0.1:5300) |
| **WARP** | Плагин | WireGuard → Sing-Box outbound |
| **MTProto** | Планируется | Sing-Box mtproto inbound |

---

## 🚀 Быстрый старт

```bash
# Установка (одна команда)
curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/bootstrap.sh | sudo bash

# После установки — TUI
sudo python3 /opt/hydra/main.py
# или
sudo hydra
```

---

## 📖 Возможности

### 1. Модульная архитектура
- **Плагины** — каждый протокол реализует единый интерфейс: install, configure, status, traffic
- **Конфиг Sing-Box** собирается динамически из фрагментов активных плагинов
- **Никаких exec()** — чистые импорты, типизированное состояние (dataclass'ы)

### 2. Управление пользователями
- Добавление, удаление, блокировка через TUI или Telegram-бота
- Лимиты трафика (GB) и срок действия (TTL)
- Персональные подписки: Sing-Box JSON, Base64, AmneziaWG-конфиг

### 3. Telegram-боты
- **Admin Bot**: управление пользователями, трафик, статус протоколов
- **Client Bot**: выдача конфигов, ссылок, QR-кодов конечным пользователям

### 4. Мониторинг
- Агрегация трафика со всех плагинов
- Sync Agent (systemd timer) — проверка лимитов каждые 5 минут
- Автоматическая блокировка при превышении лимита / истечении TTL

### 5. Безопасность
- GeoIP-блокировка входящих (iptables + ipset)
- Fail2ban, Honeypot
- Единая политика роутинга через Sing-Box

---

## 🧩 Структура проекта

```
hydra/
├── main.py                     # Точка входа
├── bootstrap.sh                # Установщик
├── hydra/
│   ├── core/                   # Ядро
│   │   ├── state.py            # Типизированное состояние + миграции
│   │   ├── singbox.py          # Управление Sing-Box
│   │   └── systemd.py          # Управление systemd-юнитами
│   ├── plugins/                # Плагины протоколов
│   │   ├── base.py             # Абстрактный интерфейс
│   │   ├── naiveproxy/         # NaiveProxy (Caddy + Sing-Box)
│   │   ├── mieru/              # Mieru (mTLS)
│   │   ├── amneziawg/          # AmneziaWG 2.0 (kernel)
│   │   ├── dnscrypt/           # DNSCrypt-proxy
│   │   └── warp/               # Cloudflare WARP
│   ├── services/               # Сервисы
│   │   ├── subscriptions/      # Генератор подписок
│   │   ├── telegram/           # Telegram-боты
│   │   ├── traffic.py          # Учёт трафика
│   │   └── sync_agent.py       # Фоновый агент
│   └── ui/                     # Интерфейс
│       ├── tui.py              # TUI-фреймворк
│       └── menus.py            # Меню
└── tests/                      # Тесты
```

---

## 📋 Требования

- **ОС**: Ubuntu 20.04/22.04/24.04, Debian 11/12/13
- **Python**: 3.10+
- **Права**: root

---

## 🔧 Разработка

```bash
# Клонирование
git clone https://github.com/gr33nimax/HYDRA-ULTIMATE.git
cd HYDRA-ULTIMATE
git checkout dev

# Запуск тестов
python -m pytest tests/ -v

# Запуск (требует root на Linux)
sudo python3 main.py
```

---

## 📄 Лицензия

MIT License — см. [LICENSE](LICENSE)
