# Совместимость с клиентами

Какие транспорты HYDRA понимают целевые клиенты. `✅` — работает, `❌` — нет,
`—` — неприменимо (транспорт не для этого клиента).

| Транспорт | Shadowrocket | NekoBox | Throne | HydraBox |
| :--- | :---: | :---: | :---: | :---: |
| VLESS + XHTTP | ✅ | ✅ | ✅ | ✅ |
| VLESS + CDN | ✅ | ✅ | ✅ | ✅ |
| Hysteria2 | ✅ | ✅ | ✅ | ✅ |
| AnyTLS | ✅ | ✅ | ✅ | ✅ |
| ShadowTLS v3 | ✅ | ✅ | ✅ | ✅ |
| NaiveProxy | ✅ | ✅ | ✅ | ✅ |
| AmneziaWG 2.0/3.x | ⚠️ ¹ | ✅ | ✅ | ✅ |
| Mieru | ✅ | ❌ ² | ✅ | ✅ |
| Snell 5/6 | ⚠️ ³ | ❌ ² | ✅ | ✅ |
| TrustTunnel | ❌ | ❌ | ✅ | ✅ |
| MTProto Zig | — | — | — | — |
| Calls · VK | — | — | — | ✅ |
| qWDTT | — | — | — | — |

¹ Shadowrocket импортирует AmneziaWG 2.0; поколение 3.x он не читает.
² Официальные Shadowrocket/NekoBox эти транспорты не умеют — нужен клиент с их
поддержкой (см. список ниже).
³ Shadowrocket читает Snell v1–v3; данных по v4 нет.

MTProto Zig — прокси для Telegram, он настраивается внутри самого Telegram, а не
в этих клиентах. qWDTT работает только со своим клиентом. Calls · VK доступен
через подписку HydraBox.

## Клиенты

| Клиент | Платформы | Где взять |
| :--- | :--- | :--- |
| **HydraBox** | Android | <https://github.com/gr33nimax/hydrabox/releases> |
| **Shadowrocket** | iOS, macOS | [App Store](https://apps.apple.com/app/id932747118) |
| **NekoBox** | Android | <https://github.com/MatsuriDayo/NekoBoxForAndroid/releases> |
| **Throne** | Windows, Linux, macOS | <https://github.com/throneproj/Throne/releases> |
| **Throne для Android** | Android | <https://github.com/throneproj/ThroneForAndroid/releases> |

HydraBox — родной клиент стека: понимает все транспорты, кроме qWDTT. Для
защищённой подписки нужен HydraBox не ниже `0.4.0-beta.1`.

Пользуйтесь актуальными сборками клиентов: набор поддерживаемых транспортов
расширяется с обновлениями их ядер (sing-box, Xray).

## Другие клиенты на sing-box

`?format=singbox` отдаёт конфигурацию как sing-box JSON, поэтому её принимает
любой клиент на этом ядре — например Karing (<https://karing.app/>),
ClashMi (<https://clashmi.app/>), husi (<https://github.com/xchacha20-poly1305/husi>).
Для Mieru нужен клиент из официального списка проекта
(<https://github.com/enfein/mieru>): HYDRA отдаёт ссылку `mierus://`.
