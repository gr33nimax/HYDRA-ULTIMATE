# Установка HYDRA v2.0

## Быстрый старт (одна команда)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/bootstrap.sh)
```

Bootstrap сам:
1. Проверяет root, ОС (Ubuntu/Debian), Python 3.10+
2. Устанавливает зависимости (curl, git, iptables, ipset)
3. Устанавливает Sing-Box из официального репозитория
4. Клонирует HYDRA в `/opt/hydra`
5. Запускает TUI `main.py`

## Ручная установка

```bash
git clone --branch dev https://github.com/gr33nimax/HYDRA-ULTIMATE /opt/hydra
cd /opt/hydra
sudo python3 main.py
```

## Требования

| Параметр | Значение |
|---|---|
| ОС | Ubuntu 20.04+, Debian 11+ |
| Python | 3.10+ (рекомендуется 3.12) |
| RAM | минимум 512 МБ |
| Диск | минимум 2 ГБ |
| Права | root |
| Сеть | публичный IP + домен для Naive/SlipGate |

## После установки

```bash
sudo hydra          # или sudo python3 /opt/hydra/main.py
```

В TUI:
- **Протоколы** → включить нужные транспорты
- **Надстройки** → DNSCrypt, WARP, PortHopping
- **Безопасность** → Fail2ban, GeoIP, Honeypot, IPBan
- **Пользователи** → добавить → получить ссылки/QR

## Логи

```bash
tail -f /var/log/hydra/install.log
journalctl -u sing-box -n 50 --no-pager
```
