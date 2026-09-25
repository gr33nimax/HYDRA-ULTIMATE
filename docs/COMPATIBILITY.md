# Матрица совместимости клиентов

Транспорты HYDRA 3.0.0 × целевые клиенты. Данные: сентябрь 2026 (релиз-ноты и исходники клиентов).
`✅` из коробки · `⚠️` частично (сноска) · `❌` нет · `—` неприменимо.

| Транспорт | Shadowrocket | NekoBox | Throne | HydraBox |
| --- | :---: | :---: | :---: | :---: |
| VLESS Reality | ✅ | ✅ | ✅ | ✅ |
| VLESS-CDN (XHTTP) | ✅ | ❌ ¹ | ⚠️ ² | ✅ |
| Hysteria2 | ✅ | ✅ | ✅ | ✅ |
| AnyTLS | ✅ | ✅ | ✅ | ✅ |
| ShadowTLS v3 | ✅ | ✅ | ✅ | ⚠️ ³ |
| NaiveProxy | ✅ | ✅ | ✅ | ✅ |
| Snell | ⚠️ ⁴ | ❌ | ✅ | ✅ |
| Mieru | ✅ | ⚠️ ⁵ | ✅ | ⚠️ ³ |
| AmneziaWG | ⚠️ ⁶ | ❌ ⁷ | ✅ | ✅ |
| WARP | ⚠️ ⁸ | ⚠️ ⁸ | ✅ | ⚠️ ³ |
| TrustTunnel | ❌ | ❌ | ❌ | ✅ |
| MTProto (Zig) | — | — | — | — |

¹ NekoBox не умеет XHTTP — схема через него не поднимается.
² Throne: XHTTP через Xray с частичными отказами ([#1761](https://github.com/throneproj/Throne/issues/1761)).
³ Уровень ядра HydraCore, без UI-парсера ссылки — только через полную sing-box-JSON подписку.
⁴ Shadowrocket: v1–v3; по v4 (его отдаёт сервер) данных нет.
⁵ NekoBox: только через `mieru-plugin`.
⁶ Shadowrocket: AWG 1.5/2.0 подтверждён, 3.x — нет.
⁷ NekoBox: только обычный WireGuard.
⁸ WARP везде — WireGuard-профиль, не отдельный протокол; MASQUE только у Throne (генератор в NekoBox удалён в 1.4.0).
`—` MTProto — серверный Telegram-прокси, идёт в официальный Telegram, не в эти клиенты.

**HydraBox** — родной Android-клиент стека (движок HydraCore, форк sing-box-extended).
Релизы: **<https://github.com/gr33nimax/hydrabox/releases>**

> Собрано из релиз-нот и исходников, без прогона на устройствах. Проверка на девайсе отменяет любую ячейку.
