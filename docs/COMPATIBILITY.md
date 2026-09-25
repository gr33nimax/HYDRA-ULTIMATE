# Матрица совместимости клиентов

Какие транспорты HYDRA (3.0.0) понимают целевые клиентские приложения.
Строки — транспорты, которые отдаёт сервер; столбцы — клиенты.

**Данные проверены:** сентябрь 2026 (веб-ресёрч по релиз-нотам и исходникам клиентов).
Клиенты обновляются часто — при расхождении верь приложению, а не таблице, и присылай правку.

## Легенда

| Знак | Значение |
| ------ | ---------- |
| ✅ | Поддерживается из коробки |
| ⚠️ | Частично / с оговоркой (см. примечание) |
| ❌ | Не поддерживается |
| — | Неприменимо (протокол потребляется не этим клиентом) |

## Матрица

| Транспорт HYDRA | Shadowrocket (iOS) | NekoBox (Android) | Throne (desktop) | HydraBox (Android) |
| --- | :---: | :---: | :---: | :---: |
| **VLESS Reality** (Vision/XTLS) | ✅ | ✅ | ✅ | ✅ |
| **VLESS-CDN** (XHTTP packet-up) | ✅ | ❌ | ⚠️ | ✅ |
| **Hysteria2** | ✅ | ✅ | ✅ | ✅ |
| **AnyTLS** | ✅ | ✅ | ✅ | ✅ |
| **ShadowTLS v3** | ✅ | ✅ | ✅ | ⚠️ |
| **NaiveProxy** | ✅ | ✅ | ✅ | ✅ |
| **Snell** | ⚠️ | ❌ | ✅ | ✅ |
| **Mieru** | ✅ | ⚠️ | ✅ | ⚠️ |
| **AmneziaWG** | ⚠️ | ❌ | ✅ | ✅ |
| **WARP** (Cloudflare) | ⚠️ | ⚠️ | ✅ | ⚠️ |
| **TrustTunnel** | ❌ | ❌ | ❌ | ✅ |
| **MTProto** (Zig) | — | — | — | — |

## Примечания

**VLESS-CDN (XHTTP).** HYDRA использует XHTTP в режиме `packet-up`, а не WS/gRPC.

- Shadowrocket — XHTTP с 2.2.67.
- NekoBox — XHTTP нет (upstream sing-box его не принял; форк `1.12.19-neko-1` не подтверждён). Схема через NekoBox не поднимется.
- Throne — XHTTP через Xray/sing-box, но с известными частичными отказами ([Throne #1761](https://github.com/throneproj/Throne/issues/1761)).
- HydraBox — XHTTP/Reality на уровне ядра HydraCore.

**ShadowTLS v3.** Shadowrocket (плагин с 2.2.19, парсинг v3 починен в 2.2.28), NekoBox (отдельный тип), Throne (`edit_shadowtls`) — полноценно. HydraBox: ядро умеет `shadowtls` outbound, но своего типа/парсера share-ссылки в клиенте нет — только через sing-box-JSON подписку.

**Snell.** Shadowrocket — v1–v3 (по v4 надёжных данных нет; HYDRA-сервер отдаёт v4). NekoBox — не поддерживает. Throne/HydraBox — да, включая v4.

**Mieru.** Shadowrocket — с 2.2.81. NekoBox — только через `mieru-plugin` (не в ядре). Throne — редактор `edit_mieru`. HydraBox — ядро умеет, но парсер ссылок клиента схему `mieru://` не строит; только через sing-box-JSON подписку без UI.

**AmneziaWG.** Shadowrocket — фиксы AWG-полей есть (AWG 1.5/2.0), про 3.x/3.1 данных нет — считать «вероятно, но не проверено». NekoBox — только обычный WireGuard. Throne (`edit_wireguard_amnezia`) и HydraBox (`awg`/`amnezia` share-link с полями jc/jmin/jmax/s1–s4/h1–h4/i1–i5) — полноценно.

**WARP.** Ни у кого не отдельный протокол, а WireGuard-профиль Cloudflare:

- Shadowrocket — вручную как WireGuard, MASQUE нет.
- NekoBox — генератор WARP **удалён в 1.4.0**; остаётся ручной WireGuard с `Reserved`.
- Throne — WireGuard + MASQUE (`edit_masque`) из коробки.
- HydraBox — WARP-фича в ядре, отдельного типа в клиенте нет.

**TrustTunnel.** Транспорт стека Hydra; из целевых клиентов его несёт только HydraCore (движок HydraBox). Сторонние клиенты его не знают.

**MTProto (Zig).** Серверный Telegram-прокси. Потребляется **официальным приложением Telegram** напрямую (ссылка `tg://proxy?...` / `https://t.me/proxy?...`), а не универсальными прокси-клиентами из этой таблицы — потому «—» во всех столбцах.

## HydraBox — родной клиент стека

- **Что это:** Android-клиент (Flutter/KMP, alpha) для self-hosted стека Hydra. Тянет подписку/share-ссылки → генерирует конфиг sing-box → системный VPN через HydraCore.
- **Клиент:** <https://github.com/gr33nimax/hydrabox>
- **Релизы:** **<https://github.com/gr33nimax/hydrabox/releases>** (актуальный на сентябрь 2026 — `v2.1.0-stable.7`; README репозитория может отставать от релизов)
- **Движок:** [HydraCore](https://github.com/gr33nimax/hydracore) — форк [sing-box-extended](https://github.com/shtorm-7/sing-box-extended). Отсюда у HydraBox из коробки Mieru, ShadowTLS, Snell, AmneziaWG 3.1, XHTTP, WARP/MASQUE, TrustTunnel (часть — только на уровне ядра, без UI-парсера ссылки).
- **Парсер ссылок клиента** понимает: `vless`, `vmess`, `trojan`, `shadowsocks(r)`, `wireguard`, `amnezia(wg)`, `hysteria/2`, `tuic`, `anytls`, `snell`, `naive+https`, `naive+quic`, `socks/http`. Не парсит: `mieru`, `shadowtls`, `mtproto` — эти протоколы доступны только через полный sing-box-JSON в подписке.

## Рекомендации

- **Проверить любой протокол быстро** — Throne (максимум транспортов из коробки) или Shadowrocket.
- **NekoBox** — избегать для XHTTP/Snell/AmneziaWG; его апстрим-ветка заморожена (1.4.x, «не принимает запросы фич»).
- **HydraBox** — брать, если нужен именно стек Hydra; протоколы уровня ядра без UI подключаются только через полную sing-box-JSON подписку.

## Оговорки по данным

Живого прогона на устройствах не было — таблица собрана из релиз-нот и исходников клиентов. Наименее подтверждено: Shadowrocket по Mieru / Snell v4 / AmneziaWG 3.x, NekoBox по XHTTP, HydraBox по Mieru/ShadowTLS/WARP (вывод из состава ядра и парсера). Проверка на реальном устройстве отменяет любую ячейку.
