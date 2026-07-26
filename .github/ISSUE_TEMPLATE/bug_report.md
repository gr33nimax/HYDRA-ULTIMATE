---
name: Bug report
about: Сообщить об ошибке
title: '[BUG] '
labels: bug
---

**Описание ошибки**

Что случилось?

**Шаги для воспроизведения**

1. Что делали
2. Что нажали
3. Что произошло

**Ожидаемое поведение**

Что должно было произойти?

**Диагностика**

Приложите вывод команд (секреты в них не выводятся):

```
hydra check
hydra status
```

**Вывод ошибки**

```
Вставьте сюда текст ошибки или JSON с error_details
```

**Журналы**

```
Последние 30 строк из /var/log/hydra/install.log
или /var/log/hydra/upgrade.log — если проблема при установке/обновлении

sudo journalctl -u sing-box -u caddy-l4 --no-pager -n 50
— если проблема в работе транспортов
```

**Окружение**

- ОС: (Ubuntu 22.04 / Debian 12 / ...)
- Python: (`python3 --version`)
- Версия HYDRA: (`hydra status` → поле `version`, или ветка и commit)
- Способ установки: (bootstrap.sh / updater.sh / upgrade.sh напрямую / запуск из исходников)
- Затронутый модуль: (AmneziaWG / AnyTLS / Hysteria2 / AntiDPI / ...)
