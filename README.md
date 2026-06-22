# VLESS Ultimate Installer v4.12.10

[![Version](https://img.shields.io/badge/version-4.12.10-blue.svg)](https://github.com/inferno1978/VLESS-Ultimate-Installer)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](https://github.com/inferno1978/VLESS-Ultimate-Installer/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)](https://ubuntu.com)

Профессиональный установщик VLESS-сервера с поддержкой REALITY и xHTTP TLS. Полная автоматизация: от установки до мониторинга, с поддержкой обхода DPI, каскадных конфигураций и AmneziaWG.

```
██╗   ██╗██╗     ███████╗███████╗███████╗
██║   ██║██║     ██╔════╝██╔════╝██╔════╝
██║   ██║██║     █████╗  ███████╗███████╗
╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║
 ╚████╔╝ ███████╗███████╗███████║███████║
  ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝
  Ultimate Installer v4.12.10
```

## ⚡ Быстрый старт

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate-Installer/main/bootstrap.sh)
```

Или с `wget`:

```bash
wget -O bootstrap.sh https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate-Installer/main/bootstrap.sh
chmod +x bootstrap.sh
bash bootstrap.sh
```

## 🎯 Возможности

| Категория        | Функции                                                              |
| ---------------- | -------------------------------------------------------------------- |
| **Протоколы**    | VLESS + TCP + REALITY, VLESS + xHTTP + TLS                           |
| **Режимы**       | Одиночный (A), Каскад Россия→Зарубеж (B), Мульти-каскад (до 10 нод) |
| **Транспорт**    | AmneziaWG (AWG 2.0) с multi-node балансировкой                       |
| **Маскировка**   | XTLS Vision/Splice, сайты-заглушки (TechHub, Nextcloud, custom)      |
| **DNS**          | DNSCrypt-proxy, кастомные DNS-правила, DNS Leak Test                 |
| **Анти-цензура** | Split Tunneling, РФ-подсети (RIPE NCC), AS-direct routing            |
| **CloudFlare**   | WARP full / selective / runet-only                                   |
| **Безопасность** | AutoBan, DPI Detector, Honeypot, SSH Hardening                       |
| **Мониторинг**   | Smart Balancer, Watchdog, Health Reports, Failover A↔B               |
| **Пользователи** | Добавление/удаление, QR-коды, ссылки, TTL, лимиты трафика            |
| **Подписка**     | Единые пользователи VLESS + NaiveProxy + Mieru, URI и sing-box JSON  |
| **Диагностика**  | Health Check, MTU Tracepath, Speed Test, TLS Cert Check              |
| **Интеграции**   | Telegram-уведомления, Clash Meta / Sing-box конфиги                  |
| **Обслуживание** | Авторестарт, автообновление xray/geo, миграция конфигов              |
| **v4.11.1**        | Smoke-test, nginx Watchdog `[NW]`, ipset Persist `[IP]`, Кластер `[CL]` |
| **v4.11.4**        | Telemt MTProto на entry-ноде → xray-каскад → Telegram (VLESS / AWG 2.0) |
| **v4.11.5**        | TCP-фрагментация ClientHello: обход DPI, 6 модулей, поддержка Happ / Incy / Nekoray |
| **v4.12.3 NEW** 🔥 | Hysteria2 транспорт: меню 7, выбор H2 при установке Режима B, балансировщик нод |
| **v4.12.8**        | Интерактивный выбор TLS Fingerprint (11 вариантов) при установке и для каждой exit-ноды; единый модуль `fingerprint_manager.py`; FP сохраняется в state.json и применяется во всех режимах (A, B, AWG, WARP) |
| **v4.12.8** 🛡️ | Telemt MSS-фрагментация против TSPU JA4 DPI: новый модуль `telemt_mss_selector.py`, 10 пресетов (tspu★/2in8/extreme-low/…) с интерактивным выбором при установке Telemt |
| **v4.12.9 NEW** 📊 | Статистика трафика NaiveProxy и Mieru: новые модули `naiveproxy_stats.py` и `mieru_stats.py`; метрики из iptables, journalctl, ss; гистограммы активности, топ клиентов, NTP-мониторинг; живое обновление каждые 30 сек |
| **v4.12.10 NEW** 📡 | Подписка (Subscription): меню [14], единые пользователи VLESS + NaiveProxy + Mieru, HTTP-сервер + nginx, URI-подписка и sing-box JSON по ссылке `sub.domain.com/<tag>` |

## 📋 Требования

| Параметр | Минимум          | Рекомендуется            |
| -------- | ---------------- | ------------------------ |
| ОС       | Ubuntu 20.04 LTS | Ubuntu 22.04 / 24.04 LTS |
| Python   | 3.10+            | 3.12                     |
| RAM      | 512 МБ           | 1 ГБ+                    |
| Права    | root             | root                     |
| Сеть     | Публичный IP     | Публичный IP + домен     |

**Поддерживаемые ОС:** Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12 / 13

## 🔧 Ручная установка

```bash
git clone https://github.com/inferno1978/VLESS-Ultimate-Installer /opt/vless-ultimate
cd /opt/vless-ultimate
sudo python3 main.py
```

## 🗂️ Структура проекта

```
VLESS-Ultimate-Installer/
├── main.py                      # Точка входа
├── bootstrap.sh                 # Установка одной командой
├── verify.py                    # Проверка целостности
├── README.md
├── TROUBLESHOOTING.md           # Решение частых проблем
├── INSTALL.md                   # Детальная инструкция
├── CHANGELOG.md                 # История изменений
├── LICENSE
└── vless_installer/
    ├── __init__.py
    ├── _core.py                 # Основной код установщика (~37 000 строк)
    └── modules/
        ├── mtproto.py           # MTProto-прокси [v4.11.4: xray-каскад интеграция]
        ├── mtproto_stats.py     # Статистика MTProto
        ├── smoke_test.py        # [v4.11.4] Автодиагностика после apply
        ├── xray_safe_apply.py   # [v4.11.4] Атомарное применение конфига
        ├── nginx_watchdog.py    # [v4.11.4] Watchdog для nginx [NW]
        ├── ipset_persist.py     # [v4.11.4] Persistent ipset при reboot [IP]
        ├── ripe_file_age.py     # [v4.11.4] Проверка возраста RIPE-файла
        ├── cluster_ops.py       # [v4.11.4] Управление кластером Exit Nodes [CL]
        ├── fragment_config.py   # [v4.12.1] Генератор конфигов с фрагментацией
        ├── fragment_fuzzer.py   # [v4.12.1] Автоподбор параметров фрагментации
        ├── fragment_log_viewer.py # [v4.12.1] Визуализация фрагментации в логах
        ├── fragment_presets.py  # [v4.12.1] Полный набор пресетов (9 конфигов)
        ├── fragment_link.py     # [v4.12.1] Ссылки+QR для Happ/Incy/Nekoray/v2rayNG
        ├── fragment_guide.py    # [v4.12.1] Интерактивный гайд по тестированию
        ├── naiveproxy.py        # [v4.12.8] NaiveProxy (HTTPS/Chromium fingerprint)
        ├── mieru.py             # [v4.12.8] Mieru (mTLS + random padding)
        └── subscription.py      # [v4.12.10] Подписка: единые пользователи, URI + sing-box
```

## 🏗️ Архитектура

### Режимы развёртывания

**Режим A — одиночный сервер**

```
Клиент ──VLESS/REALITY──► VPS (любая страна) ──► Интернет
```

**Режим B — каскад Россия → Зарубеж**

```
Клиент ──VLESS/REALITY──► Entry VPS (RU) ──AWG──► Exit VPS (EU/US) ──► Интернет
```

**Режим B Multi — мульти-каскад с балансировкой**

```
                              ┌──► Exit VPS 1 (EU) ──►┐
Клиент ──► Entry VPS (RU) ─── ┼──► Exit VPS 2 (US) ──►├──► Интернет
                              └──► Exit VPS 3 (AS) ──►┘
```

### Компоненты

```
┌─────────────────────────────────────────────────────────────┐
│                        VLESS Ultimate                       │
│                                                             │
│  bootstrap.sh ──► main.py ──exec──► _core.py                │
│                                         │                   │
│                               modules/ (v4.12.10)           │
│                                         │                   │
│         Xray-core              Nginx (TLS)                  │
│         /etc/xray/             /etc/nginx/                  │
│         config.json            sites-enabled/               │
│              │                      │                       │
│         iptables/ipset         Certbot (ACME)               │
│         (ingress block)                                     │
│              │                                              │
│         AmneziaWG (AWG)                                     │
│         /etc/amnezia/awg0.conf                              │
└─────────────────────────────────────────────────────────────┘
```

| Компонент            | Роль                                            |
| -------------------- | ----------------------------------------------- |
| **Xray-core**        | VLESS REALITY / xHTTP TLS, routing, outbounds   |
| **Nginx**            | TLS termination, маскировочный сайт-заглушка    |
| **AmneziaWG**        | Зашифрованный туннель Entry→Exit (Режим B)      |
| **DNSCrypt-proxy**   | Зашифрованный DNS, защита от leak               |
| **ipset + iptables** | Ingress-блокировка РФ подсетей (опционально)    |
| **Certbot**          | TLS-сертификаты Let's Encrypt (xHTTP режим)     |

### Telemt MTProto — интеграция с xray-каскадом `[v4.12.1]`

Для entry-нод в России: Telemt принимает клиентов по MTProto,
трафик перехватывается через `iptables REDIRECT` и направляется
в `dokodemo-door` inbound xray, затем уходит через каскад на exit VPS.

```
Клиент (Telegram)
    │  tg://proxy?server=ENTRY_IP...
    ▼
Telemt (entry VPS / RU)  — type = "direct"
    │  iptables REDIRECT  →  127.0.0.1:10811
    ▼
Xray dokodemo-door  (tag: tproxy-telemt)
    │  routing: inboundTag → balancerTag / outboundTag
    ▼
┌─ VLESS+REALITY:  chain-exit[-1] → exit VPS
└─ AWG 2.0:        fwmark → awg0  → exit VPS
    ▼
Серверы Telegram ✓
```

### Хранение состояния

```
/etc/xray/
├── config.json              # Конфиг Xray
├── ru_subnets_ripe.txt      # РФ подсети (split tunneling)
├── geosite.dat / geoip.dat  # GeoData (runetfreedom)
└── config.json.pre-apply    # Авто-бэкап перед каждым apply

/var/lib/xray-installer/
├── state.json               # Состояние установщика (UUID, ключи, настройки)
├── subscription.json        # [v4.12.10] Пользователи подписки и настройки sub.domain
├── naiveproxy.json          # Пользователи NaiveProxy
├── mieru.json               # Пользователи Mieru
├── ingress_geoip.json       # Состояние ingress-блокировки
└── backups/                 # Резервные копии конфигов

/etc/ipset.conf              # [v4.12.1] Дамп ipset для восстановления при reboot
/var/log/
├── vless-install.log        # Лог установщика
├── nginx-watchdog.log       # [v4.12.1] Лог nginx watchdog
└── xray-ipset-restore.log   # [v4.12.1] Лог восстановления ipset
```

## 🖥️ Управление сервисами

```bash
systemctl status xray nginx
systemctl restart xray nginx
journalctl -u xray -f

# Подписка (после настройки меню [14])
systemctl status xray-subscription
systemctl restart xray-subscription
journalctl -u xray-subscription -f
```

## 📡 Подписка (Subscription) `[14]`

Модуль объединяет конфигурации **VLESS**, **NaiveProxy** и **Mieru** в одну subscription-ссылку.
Пользователь вводит префикс поддомена (например `sub`), после настройки DNS конфиги
доступны по адресу:

```
https://sub.example.com:8443/<tag>
```

где `<tag>` — уникальный идентификатор пользователя (латиница, цифры, `_`, `-`).

> Порт **8443** по умолчанию — порт 443 обычно занят Xray REALITY.

### Два формата раздачи

| URL | Формат | Клиенты |
|-----|--------|---------|
| `https://sub.domain.com:8443/ivan` | base64 URI-список (`vless://`, `naive+https://`, `mierus://`) | v2rayNG, Happ, Shadowrocket |
| `https://sub.domain.com:8443/ivan/singbox` | sing-box JSON с outbounds + selector | Karing, NekoBox, sing-box CLI |

Альтернативные пути: `?format=singbox`, `/ivan.json`.

### Архитектура

```
Клиент (v2rayNG / Karing / NekoBox)
    │  HTTPS GET https://sub.domain.com:8443/ivan
    ▼
Nginx :8443 (TLS, Let's Encrypt)
    │  proxy_pass
    ▼
xray-subscription.service :8765 (localhost)
    │  читает subscription.json + state.json
    ▼
URI:  base64(vless://...\nnaive+https://...\nmierus://...)
JSON: {"outbounds": [vless, naive, mieru, selector, ...]}
```

### Единая система пользователей

Модуль использует **оркестратор** поверх существующих хранилищ — не заменяет
менеджеры [2], [11], [12], а синхронизирует их при работе через меню [14]:

```
subscription.json (tag = единый ID)
    ├── VLESS      → /etc/xray/users.json + config.json  (UUID)
    ├── NaiveProxy → /var/lib/xray-installer/naiveproxy.json  (login/password)
    └── Mieru      → /var/lib/xray-installer/mieru.json       (login/password)
```

| Действие | Поведение |
|----------|-----------|
| **Добавить** (меню [14] → [2] → [1]) | Создаёт пользователя во всех выбранных протоколах |
| **Импорт** (меню [14] → [2] → [2]) | Связывает уже существующих из VLESS/Naive/Mieru |
| **Удалить** (меню [14]) | Удаляет из subscription.json и из всех привязанных модулей |
| **Блокировка** | Только HTTP 404 на подписку; прокси продолжает работать |

> После добавления VLESS-пользователя через подписку примените список к Xray:
> **Меню [2] → Управление пользователями → [5] Применить список к Xray**.

### Быстрая настройка

```bash
sudo python3 /opt/vless-ultimate/main.py
# → [14] Подписка
# → [1] Настроить поддомен (DNS A-запись sub → IP VPS)
# → [2] Пользователи → [1] Добавить
```

Пример записи в `subscription.json`:

```json
{
  "tag": "ivan",
  "name": "Иван",
  "protocols": ["vless", "naive", "mieru"],
  "vless_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "naive_username": "ivan",
  "naive_password": "...",
  "mieru_username": "ivan",
  "mieru_password": "...",
  "blocked": false
}
```

### Установка модуля на уже работающий сервер

Патч **совместим** с оригинальной установкой v4.12.10: он **добавляет** модуль
и пункт меню `[14]`, не переустанавливает Xray/Naive/Mieru и **не меняет**
существующие `config.json`, `state.json`, `users.json`.

> Модуль подписки пока в ветке форка — в официальный `inferno1978/main` ещё не влит.
> Стандартный `bootstrap.sh` с GitHub автора **не содержит** меню [14].

**Способ 1 — скачать файлы патча (рекомендуется):**

```bash
INSTALL_DIR="/opt/vless-ultimate"   # или ваш путь к установке
BRANCH="cursor/subscription-module-4b37"
BASE="https://raw.githubusercontent.com/gr33nimax/VLESS-Ultimate-Installer/${BRANCH}"

# Бэкап перед обновлением
cp -a "${INSTALL_DIR}/vless_installer/_core.py" \
      "${INSTALL_DIR}/vless_installer/_core.py.bak.$(date +%Y%m%d)"

# Новый модуль + обновлённый _core.py (импорт и меню [14])
curl -fsSL -o "${INSTALL_DIR}/vless_installer/modules/subscription.py" \
  "${BASE}/vless_installer/modules/subscription.py"
curl -fsSL -o "${INSTALL_DIR}/vless_installer/_core.py" \
  "${BASE}/vless_installer/_core.py"

# Проверка
python3 -m py_compile "${INSTALL_DIR}/vless_installer/modules/subscription.py"
sudo python3 "${INSTALL_DIR}/main.py"
# → в главном меню должен появиться пункт [14] Подписка
```

**Способ 2 — через git (если установка клонирована):**

```bash
cd /opt/vless-ultimate
git remote add gr33nimax https://github.com/gr33nimax/VLESS-Ultimate-Installer.git 2>/dev/null || true
git fetch gr33nimax cursor/subscription-module-4b37
git checkout gr33nimax/cursor/subscription-module-4b37 -- \
  vless_installer/modules/subscription.py \
  vless_installer/_core.py
sudo python3 main.py
```

**Откат:**

```bash
cp -a /opt/vless-ultimate/vless_installer/_core.py.bak.* \
      /opt/vless-ultimate/vless_installer/_core.py
rm -f /opt/vless-ultimate/vless_installer/modules/subscription.py
systemctl stop xray-subscription 2>/dev/null; systemctl disable xray-subscription 2>/dev/null
```

Ссылки патча:
- Репозиторий: [github.com/gr33nimax/VLESS-Ultimate-Installer](https://github.com/gr33nimax/VLESS-Ultimate-Installer)
- Ветка: `cursor/subscription-module-4b37`

## 🖥️ CLI-флаги

```bash
sudo python3 /opt/vless-ultimate/main.py                   # Меню
sudo python3 /opt/vless-ultimate/main.py --status          # Быстрый статус
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup
sudo python3 /opt/vless-ultimate/main.py --switch-mode-a
sudo python3 /opt/vless-ultimate/main.py --switch-mode-b
sudo python3 /opt/vless-ultimate/main.py --autoban
sudo python3 /opt/vless-ultimate/main.py --ttl-check
sudo python3 /opt/vless-ultimate/main.py --smart-balance
sudo python3 /opt/vless-ultimate/main.py --dpi-check
sudo python3 /opt/vless-ultimate/main.py --update-ru-subnets
sudo python3 /opt/vless-ultimate/main.py --update-as-direct
sudo python3 /opt/vless-ultimate/main.py --ingress-geoip-update
sudo python3 /opt/vless-ultimate/main.py --pinned-fallback-check
sudo python3 /opt/vless-ultimate/main.py --tg-event EVENT MSG
sudo python3 /opt/vless-ultimate/main.py --clear-asn-cache
```

## 🔗 Кластерное управление `[CL]`

Меню **Безопасность и Автоматизация → `[CL]`** позволяет управлять всеми
Exit Nodes из Entry Node одной командой по SSH.

| Пункт | Действие |
|-------|----------|
| `1` | Диагностика всех нод (статус + xray -test) |
| `2` | Перезапуск Xray на всех нодах |
| `3` | Обновление Xray-core на всех нодах |
| `4` | Ротация UUID на всех нодах |
| `5` | Произвольная команда на всех нодах |
| `6` | Проверить SSH-доступ к нодам |
| `P` | Задать / сменить пароль SSH-сессии |

**Аутентификация:** сначала пробуется SSH-ключ (`~/.ssh/id_ed25519` и др.),
при неудаче — запрашивается пароль root (один раз за сессию через `sshpass`).

> **Зависимость:** для парольной аутентификации требуется `sshpass`
> (`apt install sshpass`). При первом использовании устанавливается автоматически.

## 🔍 Диагностика

```bash
# Полная диагностика через меню
sudo python3 /opt/vless-ultimate/main.py
# → Диагностика и Мониторинг → Полная диагностика

sudo python3 /opt/vless-ultimate/main.py --status
/usr/local/bin/xray run -test -config /etc/xray/config.json
tail -100 /var/log/vless-install.log
```

## 🔄 Обслуживание

```bash
python3 /opt/vless-ultimate/verify.py
cd /opt/vless-ultimate && git pull    # обновляет с origin (обычно inferno1978/main)
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup
```

> `git pull` в `/opt/vless-ultimate` тянет **upstream** (авторский репозиторий).
> Если вы ставили патч подписки с форка — повторно примените файлы из ветки
> `cursor/subscription-module-4b37` после обновления, иначе меню [14] пропадёт.

## ❓ Решение проблем

Смотри [TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [INSTALL.md](INSTALL.md) · [CHANGELOG.md](CHANGELOG.md)

## 📌 О проекте и формате общения

> **Этот проект — личная инициатива, разрабатывается и поддерживается в свободное
> от основной занятости время. Это не коммерческий продукт и не услуга с SLA.**
>
> **Что это значит на практике:**
>
> - Автор не обязан отвечать в каком-либо конкретном темпе, реализовывать
>   любую функцию по запросу или подстраивать архитектуру под чужие сценарии.
> - Сообщения в требовательном или претензионном тоне будут проигнорированы.
>   Токсичное поведение — повод для бана без предупреждения.
>
> **Как помочь проекту или получить помощь:**
>
> - Нашли реальный баг? Опишите шаги воспроизведения — это самое полезное,
>   что можно сделать.
> - Есть идея фичи? Аргументированное предложение с пользой для проекта
>   в целом — welcome.
> - Хотите другую логику под свои задачи? Форкайте репозиторий и меняйте
>   как нужно — для этого он open-source.
>
> **Спасибо всем, кто использует проект с уважением к тому, что он создан
> бесплатно и на энтузиазме.**

## 📄 Лицензия

MIT — см. [LICENSE](LICENSE)

## ✍️ Автор

inferno1978 · [GitHub](https://github.com/inferno1978)
