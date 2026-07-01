# HYDRA v0.0.3 BETA

[![Version](https://img.shields.io/badge/version-0.0.3--beta-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)]()

> HYDRA – платформа для развёртывания прокси-серверов на базе **Sing-Box** как единого оркестратора трафика. Модульная архитектура: 17 плагинов (9 транспортов, 3 надстройки, 4 безопасности) с единой политикой роутинга, DNS и безопасности.

> [!IMPORTANT]
> **Текущий статус проекта:**
> На данный момент полностью готовы, отлажены и стабильно работают плагины **AmneziaWG 2.0** (интегрирован напрямую в ядро Sing-Box через TPROXY), **Mieru** и **NaiveProxy**.
> Все остальные плагины (транспорты, надстройки и модули безопасности) находятся на этапе активной разработки и интеграции (WIP).

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
                    ┌─────┴──────┬──────────┬──────────────┐
                    ↓            ↓          ↓              ↓
              DNSCrypt:5300  GeoIP     Fail2ban        IPBan/Honeypot
              (DNS шифрование) (RU блок) (бан по логам)  (ручной бан)
```

Каждый протокол — плагин, отдающий фрагмент конфига для Sing-Box. Конфиг собирается динамически: orchestrator → collect_fragments → generate_config → nft.apply_tproxy → write_config → reload.

---

## Стек протоколов

### Транспорты (TRANSPORT)
| Протокол | Плагин | Особенности | Статус |
|---|---|---|---|
| AmneziaWG 2.0 | `amneziawg` | Kernel-модуль, интегрирован в ядро Sing-Box через TPROXY | 🟢 Готов (Ready) |
| Mieru | `mieru` | mTLS + random padding | 🟢 Готов (Ready) |
| NaiveProxy | `naive` | Caddy (TLS) + fake-site | 🟢 Готов (Ready) |
| MTProto | `telemt` | Telegram MTProto, multi-user | 🟡 В разработке (WIP) |
| FreeTurn | `vkturn` | UDP:56000, sing-box vmess outbound | 🟡 В разработке (WIP) |
| qWDTT | `wdtt` | WG over TURN, per-user | 🟡 В разработке (WIP) |
| OlaRTC | `olcrtc` | TCP over WebRTC, SOCKS :8808 | 🟡 В разработке (WIP) |
| SlipGate | `slipgate` | DNS-туннели (DNSTT/Noize/Slipstream/VayDNS) | 🟡 В разработке (WIP) |
| WebDAV | `webdav` | SOCKS5 over WebDAV | 🟡 В разработке (WIP) |
| VLESS | `vless` | VLESS-XTLS-Reality (sing-box native) | 🟡 В планах (Roadmap) |
| AnyTLS | `anytls` | TLS-обфускатор для обхода DPI | 🟡 В планах (Roadmap) |
| TrustTunnel | `trusttunnel` | Защищённый туннель для обхода блокировок | 🟡 В планах (Roadmap) |

### Надстройки (ENHANCEMENT)
| Плагин | Что делает | Статус |
|---|---|---|
| DNSCrypt | Системный DNS-прокси :5300 (DoH/DNSCrypt) | 🟡 В разработке (WIP) |
| WARP | Cloudflare WARP — AI-домены через WireGuard | 🟡 В разработке (WIP) |
| PortHopping | nftables PREROUTING REDIRECT диапазона → порт | 🟡 В разработке (WIP) |

### Безопасность (SECURITY)
| Плагин | Что делает | Статус |
|---|---|---|
| Fail2ban | Защита от перебора (sing-box/sshd/nginx) | 🟡 В разработке (WIP) |
| GeoIP | Блокировка входящих из РФ через ipset | 🟡 В разработке (WIP) |
| Honeypot | Ловушка для сканеров с авто-баном | 🟡 В разработке (WIP) |
| IPBan | Ручная блокировка IP/CIDR/ASN | 🟡 В разработке (WIP) |

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
| Сеть | публичный IP, домен (для Naive/SlipGate) |

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
2. **Надстройки** → DNSCrypt, WARP, PortHopping
3. **Безопасность** → Fail2ban, GeoIP, Honeypot, IPBan
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
│   │   ├── vkturn/             # FreeTurn
│   │   ├── wdtt/               # qWDTT
│   │   ├── olcrtc/             # OlaRTC
│   │   ├── slipgate/           # DNS-туннели
│   │   ├── webdav/             # WebDAV tunnel
│   │   ├── dnscrypt/           # DNSCrypt-proxy
│   │   ├── warp/               # Cloudflare WARP
│   │   ├── porthopping/        # Port hopping
│   │   ├── fail2ban/           # Fail2ban
│   │   ├── geoip/              # GeoIP
│   │   ├── honeypot/           # Honeypot
│   │   └── ipban/              # IPBan
│   ├── services/
│   │   ├── subscriptions/      # Генератор подписок
│   │   ├── telegram/           # Telegram-боты
│   │   ├── traffic.py          # Агрегация трафика
│   │   └── sync_agent.py       # Лимиты/TTL
│   ├── utils/
│   │   ├── firewall.py         # UFW/iptables helper
│   │   ├── downloader.py       # GitHub releases
│   │   ├── crypto.py           # Ключи/пароли
│   │   └── net.py              # IP/arch
│   └── ui/
│       ├── tui.py              # TUI-фреймворк
│       └── menus.py            # Меню
└── tests/                      # 230+ тестов
```

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
