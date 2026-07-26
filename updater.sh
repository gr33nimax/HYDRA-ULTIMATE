#!/usr/bin/env bash
# One-command launcher for the transactional HYDRA updater.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/main/updater.sh | sudo bash

set -Eeuo pipefail
umask 077

RAW_BASE="https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE"
HYDRA_REF="${HYDRA_REF:-main}"
UPGRADE_SCRIPT=""

title() {
    printf 'HYDRA · %s\n' "$*"
    printf '%s\n' '────────────────────────────────────────'
}

step() {
    local current=$1
    local total=$2
    shift 2
    printf '\n[%s/%s] %s\n' "$current" "$total" "$*"
}

ok() {
    printf '  OK  %s\n' "$*"
}

fail() {
    printf '  ОШИБКА  %s\n' "$*" >&2
    return 1
}

cleanup() {
    if [[ -n "$UPGRADE_SCRIPT" && -f "$UPGRADE_SCRIPT" ]]; then
        rm -f -- "$UPGRADE_SCRIPT"
    fi
}
trap cleanup EXIT HUP INT TERM

title "ОБНОВЛЕНИЕ HYDRA"
step 1 3 "Проверка запуска"

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    fail "Запустите команду обновления с sudo."
    exit 1
}

for command in bash curl git mktemp; do
    command -v "$command" >/dev/null 2>&1 || {
        fail "Не найдена обязательная команда: $command"
        exit 1
    }
done

git check-ref-format --branch "$HYDRA_REF" >/dev/null 2>&1 || {
    fail "Некорректное имя ветки HYDRA_REF: $HYDRA_REF"
    exit 1
}
ok "Ветка: $HYDRA_REF"

step 2 3 "Загрузка updater"
UPGRADE_SCRIPT=$(mktemp /tmp/hydra-updater.XXXXXX)
curl -fsSL --connect-timeout 30 --retry 3 --retry-delay 2 \
    "${RAW_BASE}/${HYDRA_REF}/upgrade.sh" \
    -o "$UPGRADE_SCRIPT"

[[ -s "$UPGRADE_SCRIPT" ]] || {
    fail "Скачанный updater пуст."
    exit 1
}
grep -q '^# Transactional updater for an existing HYDRA installation\.$' \
    "$UPGRADE_SCRIPT" || {
    fail "Скачан некорректный updater; обновление не запущено."
    exit 1
}
ok "Updater полностью загружен"

step 3 3 "Транзакционное обновление"
env HYDRA_REF="$HYDRA_REF" HYDRA_UPDATER_LAUNCHED=1 \
    bash "$UPGRADE_SCRIPT"
