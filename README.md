# VLESS Ultimate Installer: Fork Edition (by gr33nimax)

[![Version](https://img.shields.io/badge/version-4.12.10-blue.svg)](https://github.com/gr33nimax/VLESS-Ultimate-Installer)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](https://github.com/gr33nimax/VLESS-Ultimate-Installer/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)](https://ubuntu.com)

Профессиональный установщик VLESS-сервера с поддержкой REALITY и xHTTP TLS, расширенный **системой подписок пользователей** и **универсальным WARP-обходом** на уровне операционной системы.

```
██╗   ██╗██╗     ███████╗███████╗███████╗
██║   ██║██║     ██╔════╝██╔════╝██╔════╝
██║   ██║██║     █████╗  ███████╗███████╗
╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║
 ╚████╔╝ ███████╗███████╗███████║███████║
  ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝
  Ultimate Fork (Subscriptions + OS-level WARP)
```

---

## 🚀 Новые возможности форка

### 1. 📋 Полноценная подписочная система
- **3 формата конфигураций**:
  - **Base64** — универсальный (v2rayNG, Hiddify, Shadowrocket).
  - **Clash Meta YAML** — для Mihomo / Clash Verge / Nyanpasu.
  - **Sing-box JSON** — для нативного клиента sing-box и NekoBox.
- **Поддержка NaiveProxy и Mieru**: NaiveProxy экспортируется как тип `naive`, а Mieru как тип `socks` внутри Sing-box JSON, что позволяет клиентам вроде NekoBox безболезненно импортировать их из единой подписки.
- **Встроенный HTTP-сервер**: Легковесный многопоточный сервер на Python stdlib (запущен локально на порту `9443` под systemd `vless-sub.service`), проксируемый через Nginx по безопасному пути `/sub/<токен>`.
- **Subscription-Userinfo**: Поддержка заголовков трафика и лимитов (оставшийся трафик, дата истечения срока).
- **Интерактивное меню**: Получение ссылок и QR-кодов, включение/отключение сервера подписок, перегенерация токенов пользователей.

### 2. 🌐 Универсальный обход блокировок через WARP
- **Маршрутизация на уровне ОС**: Вместо настройки правил внутри Xray, этот модуль использует таблицы маршрутизации Linux (`ip route`) для направления трафика к определенным доменам и подсетям через WARP-интерфейс (например, `warp0` или `wg-warp`).
- **Универсальность**: Правила обхода действуют **для всех процессов** на сервере: Xray (все конфигурации), NaiveProxy, Mieru, Hysteria2 и др.
- **Динамический резолв**: Скрипт периодически резолвит указанные вами домены в IP-адреса и обновляет маршруты в фоновом режиме по расписанию cron (каждые 5 минут).
- **CLI-флаг**: Синхронизацию путей можно запускать вручную или через автоматический крон-скрипт с помощью команды `--warp-sync-routes`.

### 3. 🤖 Интеграция с Telegram-ботом
- Админ-команда `/sub <user>` — вывод подписочных ссылок пользователя.
- Админ-команда `/sub_qr <user>` — генерация и отправка QR-кода подписки прямо в чат Telegram.

---

## ⚡ Быстрый запуск

Установка одной командой:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gr33nimax/VLESS-Ultimate-Installer/main/bootstrap.sh)
```

Или с использованием `wget`:
```bash
wget -O bootstrap.sh https://raw.githubusercontent.com/gr33nimax/VLESS-Ultimate-Installer/main/bootstrap.sh
chmod +x bootstrap.sh
bash bootstrap.sh
```

---

## 🔧 Ручная установка

```bash
# 1. Клонировать репозиторий
git clone https://github.com/gr33nimax/VLESS-Ultimate-Installer /opt/vless-ultimate
cd /opt/vless-ultimate

# 2. Проверить целостность файлов и синтаксис
python3 verify.py

# 3. Запустить установщик
sudo python3 main.py
```

---

## 🔄 Обновление существующей установки (Накат патча)
Если у вас уже установлен оригинальный VLESS-Ultimate-Installer, вы можете обновить его до этого форка без потери данных:

1. Скопируйте новые файлы форка поверх существующих в вашей установке:
   - Модули в `vless_installer/modules/` (`sub_generator.py`, `sub_server.py`, `sub_nginx.py`, `warp_universal.py`).
   - Перезаписать файлы `main.py`, `vless_installer/_core.py`, `vless_installer/modules/warp.py` и `vless_installer/modules/tg_bot.py`.
2. Запустите установщик (`sudo python3 main.py`).
3. Для включения **Подписок**: перейдите в `👥 Управление пользователями (2)` → `📋 Подписки (7)` → `Включить систему подписок (1)`.
4. Для включения **Универсального WARP**: перейдите в `🌐 Настройки сети (3)` → `W` (Управление WARP) → `Универсальный обход (8)` → `Включить обход (1)`.

---

## 🖥️ CLI-флаги форка

В дополнение к стандартным командам, форк добавляет новые системные вызовы:
```bash
sudo python3 /opt/vless-ultimate/main.py --warp-sync-routes     # Запуск фонового резолва и синхронизации маршрутов WARP
```

Полный список флагов:
```bash
sudo python3 /opt/vless-ultimate/main.py --status               # Быстрый статус без вызова меню
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup     # Создание резервной копии конфигурации
sudo python3 /opt/vless-ultimate/main.py --switch-mode-a        # Быстрое переключение в режим A
sudo python3 /opt/vless-ultimate/main.py --switch-mode-b        # Быстрое переключение в режим B (Каскад)
sudo python3 /opt/vless-ultimate/main.py --autoban              # Запуск проверки автобана
sudo python3 /opt/vless-ultimate/main.py --ttl-check            # Проверка лимитов TTL пользователей
sudo python3 /opt/vless-ultimate/main.py --smart-balance        # Балансировка нод Hysteria2/AWG
sudo python3 /opt/vless-ultimate/main.py --dpi-check            # Проверка на наличие DPI блокировок
```

---

## 🗂️ Структура проекта форка

```
VLESS-Ultimate-Installer/
├── main.py                      # Точка входа
├── bootstrap.sh                 # Скрипт быстрой установки
├── verify.py                    # Проверка целостности и синтаксиса
├── README.md                    # Этот файл
├── vless_installer/
│   ├── _core.py                 # Логика меню и интеграции
│   └── modules/
│       ├── sub_generator.py     # [NEW] Генератор Base64, Clash, Sing-box подписок
│       ├── sub_server.py        # [NEW] Локальный HTTP-сервер подписок
│       ├── sub_nginx.py         # [NEW] Интеграция сервера подписок с Nginx
│       ├── warp_universal.py    # [NEW] Системная маршрутизация доменов/сетей через WARP
│       ├── warp.py              # Обновленный модуль управления WARP
│       └── tg_bot.py            # Обновленный Telegram-бот с командами подписок
```

---

## 🛡️ Безопасность и Лицензия

Проект распространяется по лицензии **MIT**. См. [LICENSE](https://github.com/gr33nimax/VLESS-Ultimate-Installer/blob/main/LICENSE) для подробностей.
При обнаружении уязвимостей, пожалуйста, создавайте приватное [Security Advisory](https://github.com/gr33nimax/VLESS-Ultimate-Installer/security/advisories/new).
