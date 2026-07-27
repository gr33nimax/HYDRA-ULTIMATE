#!/usr/bin/env bash
# One-command launcher for the transactional HYDRA updater.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/updater.sh | sudo bash

set -Eeuo pipefail
umask 077

RAW_BASE="https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE"
HYDRA_REF="${HYDRA_REF:-dev}"
UPGRADE_SCRIPT=""

configure_utf8_locale() {
    local candidate
    command -v locale >/dev/null 2>&1 || return 0
    command -v awk >/dev/null 2>&1 || return 0
    candidate=$(
        locale -a 2>/dev/null \
            | awk 'tolower($0) ~ /^(c|en_us)\.utf-?8$/ {print; exit}'
    )
    if [[ -n "$candidate" ]]; then
        export LANG="$candidate"
        export LC_ALL="$candidate"
    fi
}

configure_utf8_locale

UI_RESET=""
UI_CYAN=""
UI_GREEN=""
UI_RED=""
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    UI_RESET=$'\033[0m'
    UI_CYAN=$'\033[1;36m'
    UI_GREEN=$'\033[1;32m'
    UI_RED=$'\033[1;31m'
fi

title() {
    printf '\n%s%s%s\n' "$UI_CYAN" \
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' "$UI_RESET"
    printf '  %sHYDRA · ОБНОВЛЕНИЕ%s\n' "$UI_CYAN" "$UI_RESET"
    printf '%s%s%s\n' "$UI_CYAN" \
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' "$UI_RESET"
}

step() {
    local current=$1
    local total=$2
    shift 2
    printf '\n%s[%s/%s]%s %s\n' \
        "$UI_CYAN" "$current" "$total" "$UI_RESET" "$*"
}

ok() {
    printf '  %s✓%s %s\n' "$UI_GREEN" "$UI_RESET" "$*"
}

fail() {
    printf '  %s✗ Ошибка:%s %s\n' "$UI_RED" "$UI_RESET" "$*" >&2
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

for command in awk bash curl git mktemp; do
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

step 2 3 "Загрузка сценария обновления"
UPGRADE_SCRIPT=$(mktemp /tmp/hydra-updater.XXXXXX)
curl -fsSL --connect-timeout 30 --retry 3 --retry-delay 2 \
    "${RAW_BASE}/${HYDRA_REF}/upgrade.sh" \
    -o "$UPGRADE_SCRIPT"

[[ -s "$UPGRADE_SCRIPT" ]] || {
    fail "Скачанный сценарий обновления пуст."
    exit 1
}
grep -q '^# Transactional updater for an existing HYDRA installation\.$' \
    "$UPGRADE_SCRIPT" || {
    fail "Скачан некорректный сценарий; обновление не запущено."
    exit 1
}
ok "Сценарий обновления полностью загружен"

step 3 3 "Транзакционное обновление"
env HYDRA_REF="$HYDRA_REF" HYDRA_UPDATER_LAUNCHED=1 \
    bash "$UPGRADE_SCRIPT"
