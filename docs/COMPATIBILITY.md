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

## FlClash и Happ

Основная HTTPS-ссылка подписки распознаёт эти клиенты по `User-Agent`.
Если приложение меняет его, используй явный формат:

- **FlClash / Mihomo:** `https://<домен>/sub/<токен>?format=clash`.
  Полный конфиг содержит выбор серверов и маршрутизацию. Включаются VLESS
  (TCP/WS/gRPC/XHTTP), Hysteria2, AnyTLS и standalone Trojan. Для XHTTP необходимо
  ядро Mihomo с поддержкой этого транспорта; старое ядро не исправляется форматом
  подписки. VLESS CDN с GET-uplink и неизвестные XHTTP-расширения пропускаются,
  а не превращаются в другой транспорт.
- **Happ:** `https://<домен>/sub/<токен>?format=happ`.
  Base64-список VLESS, VMess, Trojan, Shadowsocks, SOCKS и Hysteria2.
  NekoBox-контейнеры `sn://`, AnyTLS, Naive, AWG, Snell и TrustTunnel исключены.
  XHTTP/Reality/`extra` сохраняются в VLESS-ссылке; поддержка расширений зависит
  от установленной версии Happ/Xray, импорт не доказывает работоспособность транспорта.

Ссылки обоих форматов показывает меню подписок HYDRA. Токен секретный.
Когда подходящих серверов нет, выдача завершается ошибкой, не подменяя туннель
прямым подключением. Реальный импорт в приложениях не покрывается Python unit-тестами.

## Другие клиенты на sing-box

`?format=singbox` отдаёт конфигурацию как sing-box JSON, поэтому её принимает
любой клиент на этом ядре — например Karing (<https://karing.app/>),
ClashMi (<https://clashmi.app/>), husi (<https://github.com/xchacha20-poly1305/husi>).
Для Mieru нужен клиент из официального списка проекта
(<https://github.com/enfein/mieru>): HYDRA отдаёт ссылку `mierus://`.
