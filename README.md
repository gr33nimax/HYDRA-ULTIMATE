# HYDRA Multi-Proxy Manager

**v0.7.0-rc1** · Python 3.10+ · Ubuntu / Debian · MIT

Панель на сервере для развёртывания и администрирования прокси-стека: **NaiveProxy**, **Mieru**, **AmneziaWG**, подписки, лимиты, Telegram-боты, DNSCrypt и WARP. Всё управляется из терминала — без отдельной веб-панели.

> Сборка **HYDRA-only**: без Xray/VLESS-каскада. Один сервер, несколько протоколов, общие пользователи и подписки.

---

## Что умеет

| Блок | Кратко |
|------|--------|
| **Пользователи** | Один логин → учётки в Naive, Mieru и AWG сразу. Блок, TTL, лимит трафика. |
| **Подписки** | HTTP-сервер `vless-sub`, ссылки Base64 / Clash / sing-box. |
| **Sync-agent** | Каждые 5 мин проверяет лимиты и срок подписки (`hydra-sync-agent.timer`). |
| **Сеть** | DNSCrypt, WARP-маршруты, MTU-мастер, диагностика. |
| **Telegram** | Админ-бот и пользовательский бот (ссылки, QR, статистика). |
| **Безопасность** | Fail2ban, honeypot, GeoIP ingress, IP-ban. |

Подробности по сбоям — [TROUBLESHOOTING.md](TROUBLESHOOTING.md).  
Полная инструкция — [INSTALL.md](INSTALL.md).

---

## Требования

- VPS с **публичным IP**, Ubuntu 20.04+ / Debian 11+
- **root** (или `sudo`)
- **Python 3.10+** (лучше 3.12)
- **RAM от 2 ГБ** — на 1 ГБ часть функций может не влезть
- Домен с A-записью на сервер — для TLS и подписок

---

## Установка

### Стабильная ветка `main`

Одна команда — скачает bootstrap, клонирует репозиторий в `/opt/vless-ultimate` и откроет мастер:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/main/bootstrap.sh)"
```

### Ветка `prerelease` (тестовая, сейчас v0.7.0-rc1)

**Способ 1 — bootstrap с переменной ветки** (удобно на чистом сервере):

```bash
sudo HYDRA_BRANCH=prerelease bash -c "$(curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/prerelease/bootstrap.sh)"
```

**Способ 2 — вручную через git** (удобно, если уже знаете путь):

```bash
sudo git clone -b prerelease --depth 1 https://github.com/gr33nimax/HYDRA-ULTIMATE /opt/vless-ultimate
cd /opt/vless-ultimate
sudo python3 verify.py
sudo python3 main.py
```

**Обновить существующую установку до prerelease:**

```bash
cd /opt/vless-ultimate   # или ваш каталог с main.py
sudo git fetch origin
sudo git checkout prerelease
sudo git pull origin prerelease
sudo python3 verify.py
sudo python3 main.py
```

Если репозиторий лежит не в `/opt/vless-ultimate`, bootstrap сам ищет каталог с `main.py` (см. `runtime_paths` / `HYDRA_INSTALL_ROOT`).

---

## После установки

```bash
# Панель управления
sudo python3 /opt/vless-ultimate/main.py

# Проверка целостности
sudo python3 /opt/vless-ultimate/verify.py

# Статус основных служб
systemctl status caddy-naive mita vless-sub dnscrypt-proxy

# Лог установщика
tail -50 /var/log/vless-install.log
```

Дальше в меню: **мастер установки HYDRA** → домен, Naive/Mieru/AWG, подписки, боты.

---

## Структура репозитория

```
main.py                 → точка входа
vless_installer/cli.py  → CLI и флаги
vless_installer/_core.py → меню и оркестрация
vless_installer/modules/ → протоколы, боты, подписки
verify.py               → самопроверка перед продакшеном
bootstrap.sh            → быстрая установка с GitHub
```

---

## Благодарности

Основа — [VLESS Ultimate Installer](https://github.com/inferno1978) (inferno1978).  
Стек: NaiveProxy, Mieru, AmneziaWG, DNSCrypt, Cloudflare WARP.

## Лицензия

[MIT](LICENSE) — использование на свой риск.
