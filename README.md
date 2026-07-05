# HYDRA v2.3.1

[![Version](https://img.shields.io/badge/version-2.3.1-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)]()

> HYDRA – платформа для развёртывания прокси-серверов на базе **Sing-Box** как единого оркестратора трафика. Модульная архитектура: 17 плагинов (9 транспортов, 3 надстройки, 4 безопасности) с единой политикой роутинга, DNS и безопасности.

> [!IMPORTANT]
> На данный момент полностью готовы, отлажены и стабильно работают плагины **AmneziaWG 2.0** (интегрирован напрямую в ядро Sing-Box через TPROXY), **Mieru**, **AnyTLS**, **TrustTunnel**, **NaiveProxy** (работает через HTTP/2), **MTProto (Telemt)** (Rust MTProxy с защитой от DPI и продвинутой TUI-статистикой) и **qWDTT** (WireGuard over TURN с изолированным парольным управлением; *внимание: интеграция с Telegram-ботом находится в разработке и еще не готова*). Полностью готов и отлажен **подписочный функционал** для генерации клиентских подписок.
> В разделе безопасности полностью готовы и снабжены интерактивными пультами управления плагины **Fail2ban** (защита от перебора sing-box/sshd), **Honeypot** (ловушка сканеров с авто-баном) и **IPBan** (ручная блокировка IP/CIDR/диапазонов/ASN).
> В разделе сетевых служб полностью готовы модули **WARP** с выборочной маршрутизацией и **DNSCrypt** для системного шифрования DNS (с автоматическим замером latency и выбором серверов).
> Все остальные плагины (транспорты, надстройки) находятся на этапе активной разработки (WIP).

---

## Архитектура

```
Клиент → [Транспортный демон] → nftables TPROXY → Sing-Box (inbound)
                                                     │
                          ┌──────────────────────────┤
                          ↓                          ↓
                    WARP (outbound)             Direct (outbound)
                          │                          │
                    Cloudflare                  Интернет
                          │
                    ┌─────┴──────┬─────────────────────────┐
                    ↓            ↓                         ↓
              DNSCrypt:5300  Fail2ban                  IPBan/Honeypot
              (DNS шифрование) (бан по логам)            (ручной/авто бан)
```

Каждый протокол — плагин, отдающий фрагмент конфига для Sing-Box. Конфиг собирается динамически: orchestrator → collect_fragments → generate_config → nft.apply_tproxy → write_config → reload.

---

## Стек протоколов

### Транспорты (TRANSPORT)
| Протокол | Плагин | Особенности | Статус |
|---|---|---|---|
| AmneziaWG 2.0 | `amneziawg` | Kernel-модуль, интегрирован в ядро Sing-Box через TPROXY | 🟢 Готов (Ready) |
| Mieru | `mieru` | mTLS + random padding | 🟢 Готов (Ready) |
| NaiveProxy | `naive` | Caddy (TLS) + fake-site (работает через HTTP/2) | 🟢 Готов (Ready) |
| MTProto | `telemt` | Telegram MTProto, multi-user | 🟢 Готов (Ready) |
| qWDTT | `wdtt` | WG over TURN с изолированным парольным управлением (интеграция Telegram-ботов в разработке) | 🟢 Готов (Ready) |
| AnyTLS | `anytls` | TLS-shaped tunnel с padding scheme | 🟢 Готов (Ready) |
| TrustTunnel | `trusttunnel` | Защищённый туннель для обхода блокировок | 🟢 Готов (Ready) |
| ShadowTLS | `shadowtls` | TLS-обертка с имитацией рукопожатия доверенных сайтов | 🟡 В планах (Roadmap) |

### Сетевые службы (ENHANCEMENT)
| Плагин | Что делает | Статус |
|---|---|---|
| DNSCrypt | Системный DNS-прокси :5300 (DoH/DNSCrypt) | 🟢 Готов (Ready) |
| WARP | Cloudflare WARP — выборочный роутинг через WireGuard | 🟢 Готов (Ready) |

### Безопасность (SECURITY)
| Плагин | Что делает | Статус |
|---|---|---|
| Fail2ban | Защита от перебора (sing-box/sshd) | 🟢 Готов (Ready) |
| Honeypot | Ловушка для сканеров с авто-баном | 🟢 Готов (Ready) |
| IPBan | Ручная блокировка IP/CIDR/диапазона/ASN | 🟢 Готов (Ready) |

---

## Описание Ключевых Функций

### Cloudflare WARP (Выборочный роутинг)

Модуль интеграции с Cloudflare WARP (`warp`) предназначен для выборочного перенаправления трафика. Он никогда не перехватывает весь трафик по умолчанию, позволяя пустить через сеть Cloudflare только выбранные ресурсы.

**Возможности модуля:**
* **Локальные правила**: Добавление и удаление собственных доменов, IP-адресов и CIDR-подсетей через интерактивное меню TUI.
* **Встроенные списки правил (itdoginfo)**:
  * **РФ-сервисы** (`outside-raw.lst`): Российские ресурсы (используются для скрытия IP VPS за серверами WARP, чтобы РФ зонды не обнаруживали его).
  * **GEO-block** (`geoblock.lst`): Популярные зарубежные ресурсы, заблокированные на территории РФ.
  * **GoogleAI** (`google_ai.lst`): Сервисы ИИ от Google (Gemini, Google AI Studio и др.).
* **Автоматическое обновление**: Фоновый агент `sync_agent` раз в 24 часа автоматически скачивает включенные списки, кэширует их и обновляет конфигурацию маршрутизации Sing-Box.
* **Современный стек**: Полная интеграция с Sing-Box 1.13.0+ через нативную секцию `endpoints` (без лишних `outbounds` и прослоек).

### HAProxy Роутер (TLS SNI Мультиплексор)

При активации двух или более TLS-транспортов (например, AnyTLS, NaiveProxy, TrustTunnel), слушающих порт 443, HYDRA автоматически разворачивает и настраивает **HAProxy** как единую точку входа.

**Схема работы:**
```
Входящий TLS-трафик (Порт 443)
              │
              ▼
       ┌─────────────┐
       │   HAProxy   │ (Чтение SNI из TLS Client Hello без расшифрования)
       └──────┬──────┘
              │
     ┌────────┼────────┬─────────────┐
     ▼        ▼        ▼             ▼
  [SNI-1]  [SNI-2]  [SNI-3]     [Неизвестный/Default]
     │        │        │             │
     ▼        ▼        ▼             ▼
 NaiveProxy AnyTLS TrustTunnel  Сайт-заглушка (Маскировка)
  (:10443)  (:10444) (:10445)   (Защита от активного сканирования)
```

**Как это работает:**
* **TCP SNI Мультиплексирование**: HAProxy слушает порт 443 и при входящем соединении считывает TLS Client Hello.
* **Маршрутизация по домену**: На основе SNI (Server Name Indication) запрос без расшифрования (что гарантирует абсолютную безопасность и скрытность) перенаправляется на нужный внутренний порт соответствующего плагина:
  * NaiveProxy → порт `10443`
  * AnyTLS → порт `10444`
  * TrustTunnel → порт `10445`
* **Маскировка (Decoy)**: Запросы с неизвестными доменами сбрасываются или перенаправляются на сайт-заглушку, защищая прокси от обнаружения активным сканированием.

---

## Тестирование и Диагностика VPS

В менеджер встроен полноценный интерактивный пульт отладки и мониторинга работы VPS (`Опция 8` в главном меню). Он позволяет выявлять проблемы со скоростью, маршрутизацией, гео-блокировками и производительностью системы. Все тесты выполняются неинтерактивно с отображением результатов в TUI-рамках.

| Инструмент | Что делает | Какую информацию дает |
|---|---|---|
| 🌍 Геолокация и провайдер (GeoIP) | Опрос внешних баз данных GeoIP | Определение GeoIP для проверки смены региона. |
| 🛡️ Доступность ресурсов (Censorcheck) | Тест доступности популярных зарубежных сайтов | Проверка блокировок сервисов (OpenAI, Netflix, YouTube) напрямую с сервера. |
| 🛡️ Обход DPI-фильтров (Censorcheck DPI) | Анализ прохождения трафика через ТСПУ РФ | Проверка фильтрации и замедления трафика российскими провайдерами. |
| ⚡ Тест скорости до РФ (iPerf3) | Многопоточный замер через iPerf3 до узлов в РФ | Измерение пропускной способности (Download/Upload) и задержки (Ping) до рунета. |
| 🌐 Тест скорости: Мир (Global) | HTTP-загрузка файлов с 14 мировых дата-центров | Замер скорости скачивания и Ping до серверов США, Европы, Азии и Австралии. |
| 💻 Производительность CPU (Sysbench) | Стресс-тест процессора в один поток | Оценка вычислительной мощности CPU (событий в секунду, лимиты, задержки). |

---

## Установка

### Требования

| Параметр | Значение |
|---|---|
| ОС | Ubuntu 20.04+, Debian 11+ |
| Python | 3.10+ |
| RAM | от 512 МБ |
| Диск | от 2 ГБ |
| Права | root |
| Сеть | публичный IP, домен (для NaiveProxy) |

### Автоматическая (рекомендуется)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/bootstrap.sh)
```

Скрипт сам установит Python, Sing-Box, клонирует HYDRA в `/opt/hydra` и запустит TUI.

### Ручная

```bash
git clone --branch dev https://github.com/gr33nimax/HYDRA-ULTIMATE /opt/hydra
cd /opt/hydra
sudo python3 main.py
```

### После установки

В TUI:

1. **Протоколы** → включить транспорты (AmneziaWG, Mieru, Naive и т.д.)
2. **Сетевые службы** → DNSCrypt, WARP
3. **Безопасность** → Fail2ban, Honeypot, IPBan
4. **Пользователи** → Добавить → готовы ссылки и QR

Проверить статус:

```bash
sudo hydra status
journalctl -u sing-box -n 20 --no-pager
```

---

## Структура проекта

```
hydra/
├── main.py                     # Точка входа
├── bootstrap.sh                # Установщик
├── hydra/
│   ├── core/
│   │   ├── state.py            # Типизированное состояние + миграции
│   │   ├── singbox.py          # Генератор конфигов Sing-Box
│   │   ├── orchestrator.py     # Единый pipeline apply_config
│   │   ├── nft.py              # nftables TPROXY
│   │   └── systemd.py          # systemd-хелперы
│   ├── plugins/
│   │   ├── base.py             # Абстрактный контракт v2
│   │   ├── registry.py         # Реестр + discovery + collect_fragments
│   │   ├── amneziawg/          # AmneziaWG 2.0
│   │   ├── mieru/              # Mieru (reference impl)
│   │   ├── naive/              # NaiveProxy
│   │   ├── telemt/             # MTProto
│   │   ├── wdtt/               # qWDTT
│   │   ├── dnscrypt/           # DNSCrypt-proxy
│   │   ├── warp/               # Cloudflare WARP
│   │   ├── fail2ban/           # Fail2ban
│   │   ├── honeypot/           # Honeypot
│   │   └── ipban/              # IPBan
│   ├── services/
│   │   ├── subscriptions/      # Генератор подписок
│   │   ├── telegram/           # Telegram-боты (в разработке)
│   │   ├── traffic.py          # Агрегация трафика
│   │   └── sync_agent.py       # Лимиты/TTL
│   ├── utils/
│   │   ├── firewall.py         # UFW/iptables helper
│   │   ├── downloader.py       # GitHub releases
│   │   ├── crypto.py           # Ключи/пароли
│   │   └── net.py              # IP/arch
│   └── ui/
│   │   ├── tui.py              # TUI-фреймворк
│   │   └── menus.py            # Меню
└── tests/                      # 230+ тестов
```

---

## История изменений (Changelog)

| Дата | Версия | Тип | Ключевые изменения |
| :--- | :--- | :--- | :--- |
| **05.07.2026** | **v2.3.1** | `fix` | Исправление багов деплоя, перезапуска подписочного сервера при блокировках, схем ссылок `naive+https://`. |
| **04.07.2026** | **v2.3.0-beta** | `feat` | Запуск HTTPS-сервера подписок (порт 9443), интеграция MTProxy (Telemt) и qWDTT, пульт VPS-диагностики. |
| **03.07.2026** | **v0.5 BETA** / *v2.2.0* | `feat` | Внедрение Traffic Accounting Daemon, модулей Fail2ban, IPBan, Honeypot, интеграция TrustTunnel, лимиты WARP. |
| **02.07.2026** | **v2.1.1** | `fix` | Исправления авторизации NaiveProxy (plaintext basic_auth) и биндинга портов Caddy. |
| **01.07.2026** | **v0.0.3 BETA** / *v2.1.0* | `feat` | Миграция на `sing-box-extended`, нативный Mieru inbound, плагин NaiveProxy, исправление nftables TPROXY петель. |
| **30.06.2026** | **v2.0.1-beta** | `feat` | Автоматический выбор неконфликтующих подсетей для AmneziaWG, фикс MTU 1376, двойные рамки TUI. |
| **29.06.2026** | **v2.0.0** | `release` | Релиз HYDRA v2.0: новая модульная архитектура плагинов, удаление legacy-ядер, внедрение оркестратора. |

<details>
<summary><b>Развернуть детальную историю изменений</b></summary>

### v2.3.1 (05.07.2026)
* **fix(orchestrator):** Немедленный перезапуск сервера подписок при блокировке/удалении пользователя для отзыва токенов.
* **fix(naive):** Изменен формат ссылок подключения клиентов на `naive+https://`.
* **fix(fail2ban):** Авто-миграция старых конфигураций jail sshd при перезаписи.

### v2.3.0-beta (04.07.2026)
* **feat(subscriptions):** Поднят HTTPS-сервер на порту 9443, раздающий конфиги в формате NekoBox (`sn://`) с проверкой лимитов трафика/TTL.
* **feat(telemt):** Интегрирован плагин Telegram MTProxy с Sing-Box (сбор статистики по пользователям).
* **feat(wdtt):** Добавлен плагин qWDTT (WireGuard over TURN) с изолированным парольным управлением.
* **feat(diagnostics):** Пульт VPS-диагностики в TUI (тесты GeoIP, скорость iPerf3 до РФ, глобальный замер HTTP-загрузки, тесты DPI через Censorcheck).

### v0.5 BETA / v2.2.0-beta (03.07.2026)
* **feat(traffic):** Разработан фоновый Traffic Daemon (учет трафика AnyTLS/Mieru/TrustTunnel по journalctl и Caddy).
* **feat(security):** Добавлены интерактивные TUI пульты для Fail2ban, IPBan, Honeypot.
* **feat(warp):** Умный WARP с 24h-обновлением списков РФ/GoogleAI/GEO-block.
* **feat(trusttunnel):** Интегрирован защищенный транспорт TrustTunnel с генерацией ссылок `tt://`.

### v2.1.1 (02.07.2026)
* **fix(naive):** Исправлены сбои basic_auth в Caddy (использование plaintext basic_auth).
* **fix(naive):** Назначен биндинг Caddy на `127.0.0.1:10443`.

### v0.0.3 BETA / v2.1.0-beta (01.07.2026)
* **feat(singbox):** Переход на `sing-box-extended` и интеграция плагина Mieru как нативного inbound.
* **feat(naive):** Интеграция плагина NaiveProxy с Caddy (авто-выпуск SSL через Certbot).
* **fix(nftables):** Исправление петель маршрутизации TPROXY добавлением проверки метки сокета `meta mark 0xff` в nftables.

### v2.0.1-beta (30.06.2026)
* **feat(awg):** Автоматический бесконфликтный выбор подсетей для AmneziaWG и ограничение MTU до 1376.
* **style(tui):** Переход на двойные рамки окон TUI и исправление расчета ширины Emoji (>0xFFFF).

### v2.0.0 (29.06.2026)
* **release:** Релиз новой архитектуры HYDRA v2.0. Модульная структура плагинов, удаление устаревших ядер Xray/VLESS. Старт единого оркестратора Sing-Box.
</details>

---

## Разработка

```bash
git clone https://github.com/gr33nimax/HYDRA-ULTIMATE.git
cd HYDRA-ULTIMATE
python -m pytest tests/ -v   # 230+ тестов за 7 секунд
sudo python3 main.py         # TUI (только Linux)
```

---

## Лицензия

MIT License — см. [LICENSE](LICENSE)
