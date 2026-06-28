#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# HYDRA v1.0.0-alpha — Bootstrap Installer
# ═══════════════════════════════════════════════════════════════════════════════
# Установка:
#   curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/bootstrap.sh | sudo bash
#
# Что делает:
#   1. Проверяет root, ОС (Ubuntu/Debian), Python 3.10+
#   2. Устанавливает системные зависимости (curl, git, iptables, etc.)
#   3. Устанавливает Sing-Box (из официального репозитория)
#   4. Клонирует/обновляет репозиторий HYDRA
#   5. Запускает main.py
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Сброс прокси
unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy 2>/dev/null || true

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "  ${CYAN}→${NC} $*"; }
ok()    { echo -e "  ${GREEN}✓${NC} $*"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $*"; }
err()   { echo -e "  ${RED}✗${NC} $*"; }

echo -e "${GREEN}${BOLD}"
cat << 'BANNER'
  ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗
  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
  ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
  ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
  ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
           SING-BOX MULTI-PROXY MANAGER v1.0
BANNER
echo -e "${NC}"

# ── [1/5] Root check ────────────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Проверка прав${NC}"
if [[ $EUID -ne 0 ]]; then
    err "Требуются права root"
    echo -e "     sudo bash bootstrap.sh"
    exit 1
fi
ok "root: OK"

# ── [2/5] Система ───────────────────────────────────────────────────────────
echo -e "\n${BOLD}[2/5] Система${NC}"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    err "Не удалось определить ОС"
    exit 1
fi

case "$OS" in
    ubuntu|debian)
        ok "ОС: $OS $VER"
        PKG_INSTALL="apt-get install -y -qq"
        ;;
    *)
        err "Поддерживаются только Ubuntu/Debian. Обнаружено: $OS"
        exit 1
        ;;
esac

# ── [3/5] Зависимости ───────────────────────────────────────────────────────
echo -e "\n${BOLD}[3/5] Зависимости${NC}"

apt-get update -qq

MISSING=()
command -v python3 &>/dev/null || MISSING+=("python3")
command -v curl    &>/dev/null || MISSING+=("curl")
command -v git     &>/dev/null || MISSING+=("git")

for pkg in "${MISSING[@]}"; do
    info "Устанавливаю: $pkg"
    $PKG_INSTALL "$pkg" || { err "Не удалось установить $pkg"; exit 1; }
done

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_OK=$(python3 -c "import sys; print(int(sys.version_info >= (3, 10)))")
if [[ "$PY_OK" != "1" ]]; then
    err "Требуется Python >= 3.10, найден $PY_VER"
    exit 1
fi
ok "Python $PY_VER: OK"

# Дополнительные пакеты
$PKG_INSTALL iptables iproute2 gnupg ca-certificates 2>/dev/null || true

# ── Sing-Box ────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}Sing-Box${NC}"
if ! command -v sing-box &> /dev/null; then
    info "Установка Sing-Box..."
    curl -fsSL https://sing-box.app/gpg.key -o /usr/share/keyrings/sagernet.asc 2>/dev/null
    chmod 644 /usr/share/keyrings/sagernet.asc
    echo "deb [signed-by=/usr/share/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" \
        > /etc/apt/sources.list.d/sagernet.list
    apt-get update -qq
    $PKG_INSTALL sing-box 2>/dev/null || {
        warn "Не удалось установить sing-box через apt. Попробуйте вручную."
    }
    command -v sing-box &>/dev/null && ok "Sing-Box: $(sing-box version 2>/dev/null | head -1)" || warn "Sing-Box не установлен"
else
    ok "Sing-Box: $(sing-box version 2>/dev/null | head -1)"
fi

# ── [4/5] Клонирование / обновление ─────────────────────────────────────────
echo -e "\n${BOLD}[4/5] Загрузка HYDRA${NC}"
INSTALL_DIR="/opt/hydra"
REPO_URL="https://github.com/gr33nimax/HYDRA-ULTIMATE"
BRANCH="dev"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Обновление репозитория..."
    cd "$INSTALL_DIR"
    git fetch origin "$BRANCH" 2>/dev/null || true
    git checkout "$BRANCH" 2>/dev/null || true
    git reset --hard "origin/$BRANCH" 2>/dev/null || warn "git reset не удался"
    ok "Репозиторий обновлён"
elif [[ -d "$INSTALL_DIR" ]]; then
    info "Установка без git — принудительное обновление..."
    ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
    curl -fsSL --connect-timeout 30 --retry 3 -o /tmp/hydra.tar.gz "$ARCHIVE" && {
        tar -xzf /tmp/hydra.tar.gz -C /tmp/
        cp -rf /tmp/HYDRA-ULTIMATE-${BRANCH}/. "$INSTALL_DIR/"
        rm -rf /tmp/HYDRA-ULTIMATE-${BRANCH} /tmp/hydra.tar.gz
        ok "Файлы обновлены"
    } || err "Не удалось загрузить архив"
else
    info "Клонирование репозитория..."
    mkdir -p "$INSTALL_DIR"
    git clone --quiet --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null || {
        warn "git clone не удался — загружаю архив..."
        ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
        curl -fsSL --connect-timeout 30 --retry 3 -o /tmp/hydra.tar.gz "$ARCHIVE" && {
            tar -xzf /tmp/hydra.tar.gz -C /tmp/
            cp -rf /tmp/HYDRA-ULTIMATE-${BRANCH}/. "$INSTALL_DIR/"
            rm -rf /tmp/HYDRA-ULTIMATE-${BRANCH} /tmp/hydra.tar.gz
        } || { err "Не удалось загрузить репозиторий"; exit 1; }
    }
    ok "Загружено в $INSTALL_DIR"
fi

[[ -f "${INSTALL_DIR}/main.py" ]] || { err "main.py не найден в $INSTALL_DIR"; exit 1; }

# ── Python-зависимости ──────────────────────────────────────────────────────
info "Python-зависимости..."
pip3 install -q "python-telegram-bot[job-queue]" 2>/dev/null || warn "python-telegram-bot не установлен (ботам требуется ручная установка)"

# ── Symlink ──────────────────────────────────────────────────────────────────
ln -sf "${INSTALL_DIR}/main.py" /usr/local/bin/hydra 2>/dev/null || true

# ── [5/5] Запуск ────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[5/5] Запуск${NC}"
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}     🐉 HYDRA v1.0 установлена!${NC}"
echo -e "${GREEN}${BOLD}     Запуск: sudo python3 ${INSTALL_DIR}/main.py${NC}"
echo -e "${GREEN}${BOLD}     Или:    sudo hydra${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${DIM}Лог: /var/log/hydra/install.log${NC}"
echo ""

if [[ -t 0 ]]; then
    exec python3 "$INSTALL_DIR/main.py" "$@"
fi
