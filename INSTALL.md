# Инструкция по установке — HYDRA v0.7.0-rc1

## Стабильная ветка (`main`)

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/main/bootstrap.sh)"
```

## Ветка prerelease (тест)

```bash
# Чистый сервер
sudo HYDRA_BRANCH=prerelease bash -c "$(curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/prerelease/bootstrap.sh)"

# Или вручную
sudo git clone -b prerelease --depth 1 https://github.com/gr33nimax/HYDRA-ULTIMATE /opt/vless-ultimate
cd /opt/vless-ultimate && sudo python3 verify.py && sudo python3 main.py
```

Обновление уже установленной копии до prerelease:

```bash
cd /opt/vless-ultimate
sudo git fetch origin && sudo git checkout prerelease && sudo git pull origin prerelease
sudo python3 verify.py && sudo python3 main.py
```

Переменная **`HYDRA_BRANCH`** задаёт ветку для `bootstrap.sh` (по умолчанию `main`).

Bootstrap скрипт автоматически:
1. Проверяет права root
2. Устанавливает `python3`, `curl`, `git` если отсутствуют
3. Клонирует репозиторий в `/opt/vless-ultimate`
4. Запускает установщик

---

## Ручная установка

```bash
# 1. Клонировать репозиторий (ветка main)
git clone https://github.com/gr33nimax/HYDRA-ULTIMATE /opt/vless-ultimate
cd /opt/vless-ultimate

# Для prerelease: git clone -b prerelease ...

# 2. Проверить целостность
python3 verify.py

# 3. Запустить
sudo python3 main.py
```

---

## Требования

| Параметр | Значение |
|----------|----------|
| ОС | Ubuntu 20.04 / 22.04 / 24.04 LTS, Debian 11 / 12 / 13 |
| Python | 3.10+ (рекомендуется 3.12) |
| RAM | минимум 512 МБ |
| Диск | минимум 2 ГБ |
| Права | root |
| Сеть | публичный IP, домен с A-записью |

### Предустановка Python 3.12 (если нужно)

```bash
# Ubuntu 20.04 / 22.04
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.12

# Ubuntu 24.04 / Debian 12+
sudo apt-get install -y python3
```

---

## После установки

```bash
# Панель
sudo python3 /opt/vless-ultimate/main.py

# Статус HYDRA-служб
systemctl status caddy-naive mita vless-sub dnscrypt-proxy

# Лог
tail -50 /var/log/vless-install.log
```

---

## Обновление

```bash
cd /opt/vless-ultimate
git pull origin main    # или: prerelease
sudo python3 verify.py
sudo python3 main.py
```

---

## Удаление

Через меню: **Установка HYDRA → Удаление HYDRA** (с опциональным бэкапом `state.json`).

Или вручную остановить службы `caddy-naive`, `mita`, `vless-sub`, `dnscrypt-proxy` и удалить каталог установки.

---

## Проблемы при установке?

Смотри [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
