#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# HYDRA v2.4.0 — Bootstrap Installer

# ═══════════════════════════════════════════════════════════════════════════════
# Установка:
#   curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/main/bootstrap.sh | sudo bash
#
# Что делает:
#   1. Проверяет root, ОС (Ubuntu/Debian), Python 3.10+
#   2. Устанавливает системные зависимости (curl, git, iptables, etc.)
#   3. Устанавливает Sing-Box (из официального репозитория)
#   4. Клонирует/обновляет репозиторий HYDRA
#   5. Запускает main.py
# ═══════════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail

# Keep the installer usable behind an explicitly configured proxy.  The old
# installer removed proxy variables and made otherwise reachable servers fail.
umask 022

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "  ${CYAN}→${NC} $*"; }
ok()    { echo -e "  ${GREEN}✓${NC} $*"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $*"; }
err()   { echo -e "  ${RED}✗${NC} $*"; }

step()  { echo -e "\n${BOLD}${CYAN}━━ $* ━━${NC}"; }

on_error() {
    local code=$?
    err "Установка прервана (строка ${BASH_LINENO[0]}, код ${code})."
    err "Подробный лог: /var/log/hydra/install.log"
    exit "$code"
}
trap on_error ERR

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

LOG_DIR=/var/log/hydra
LOG_FILE=${LOG_DIR}/install.log
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
# Keep output visible while also making the advertised install log real.
exec > >(tee -a "$LOG_FILE") 2>&1

# ── [2/5] Система ───────────────────────────────────────────────────────────
step "[2/5] Система"
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
command -v apt-get >/dev/null || { err "apt-get не найден"; exit 1; }

# ── [3/5] Зависимости ───────────────────────────────────────────────────────
step "[3/5] Зависимости"

apt-get update -qq

MISSING=()
command -v python3 &>/dev/null || MISSING+=("python3")
command -v curl    &>/dev/null || MISSING+=("curl")
command -v git     &>/dev/null || MISSING+=("git")
command -v tar     &>/dev/null || MISSING+=("tar")
command -v sha256sum &>/dev/null || MISSING+=("coreutils")
python3 -m venv --help &>/dev/null || MISSING+=("python3-venv")

for pkg in "${MISSING[@]}"; do
    info "Устанавливаю: $pkg"
    $PKG_INSTALL "$pkg"
done

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_OK=$(python3 -c "import sys; print(int(sys.version_info >= (3, 10)))")
if [[ "$PY_OK" != "1" ]]; then
    err "Требуется Python >= 3.10, найден $PY_VER"
    exit 1
fi
ok "Python $PY_VER: OK"

# Дополнительные пакеты
$PKG_INSTALL iptables iproute2 gnupg ca-certificates ufw

# ── Sing-Box Extended ──────────────────────────────────────────────────────
step "Sing-Box Extended"
if ! command -v sing-box &> /dev/null || ! sing-box version 2>/dev/null | head -1 | grep -q "extended"; then
    info "Установка sing-box-extended..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) SB_ARCH="amd64" ;;
        aarch64|arm64) SB_ARCH="arm64" ;;
        *) err "Неподдерживаемая архитектура: $ARCH"; exit 1 ;;
    esac

    SB_META=$(curl -fsSL --connect-timeout 30 --retry 3 https://api.github.com/repos/shtorm-7/sing-box-extended/releases/latest \
        | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data.get('assets', []):
    n = a['name']
    if 'linux-${SB_ARCH}.tar.gz' in n \
       and 'compressed' not in n and 'musl' not in n \
       and 'glibc' not in n and 'purego' not in n:
        print(a['browser_download_url'], a.get('digest') or ''); break
")

    read -r SB_URL SB_DIGEST <<< "$SB_META"
    [[ -n "$SB_URL" ]] || { err "Не удалось определить URL для sing-box-extended"; exit 1; }
    SB_TMP=$(mktemp -d /tmp/hydra-singbox.XXXXXX)
    curl -fsSL --connect-timeout 30 --retry 3 "$SB_URL" -o "$SB_TMP/sing-box.tar.gz"
    if [[ "$SB_DIGEST" == sha256:* ]]; then
        EXPECTED_SHA=${SB_DIGEST#sha256:}
        ACTUAL_SHA=$(sha256sum "$SB_TMP/sing-box.tar.gz" | awk '{print $1}')
        [[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || {
            err "Проверка целостности Sing-Box не пройдена"; exit 1;
        }
        ok "Проверка целостности Sing-Box: OK"
    else
        warn "GitHub не предоставил digest для выбранного релиза Sing-Box"
    fi
    tar -xzf "$SB_TMP/sing-box.tar.gz" -C "$SB_TMP"
    SB_BIN=$(find "$SB_TMP" -type f -name sing-box -size +1M -print -quit)
    [[ -n "$SB_BIN" ]] || { err "В архиве нет корректного бинарника sing-box"; exit 1; }
    install -m 0755 "$SB_BIN" /usr/local/bin/sing-box.new
    /usr/local/bin/sing-box.new version >/dev/null
    mv -f /usr/local/bin/sing-box.new /usr/local/bin/sing-box
    rm -rf "$SB_TMP"
    ok "Sing-Box Extended: $(sing-box version 2>/dev/null | head -1)"
else
    ok "Sing-Box: $(sing-box version 2>/dev/null | head -1)"
fi

# ── [4/5] Клонирование / обновление ─────────────────────────────────────────
step "[4/5] Загрузка HYDRA"
INSTALL_DIR="/opt/hydra"
REPO_URL="https://github.com/gr33nimax/HYDRA-ULTIMATE"
BRANCH="main"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Обновление репозитория..."
    cd "$INSTALL_DIR"
    if ! git diff --quiet || [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        err "В $INSTALL_DIR есть локальные изменения; обновление остановлено, чтобы их не удалить."
        exit 1
    fi
    git fetch --prune origin "$BRANCH"
    git checkout -q "$BRANCH"
    git reset --hard "origin/$BRANCH"
    ok "Репозиторий обновлён"
elif [[ -d "$INSTALL_DIR" ]]; then
    info "Установка без git — принудительное обновление..."
    ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
    UPDATE_TMP=$(mktemp -d /tmp/hydra-update.XXXXXX)
    curl -fsSL --connect-timeout 30 --retry 3 -o "$UPDATE_TMP/hydra.tar.gz" "$ARCHIVE"
    tar -xzf "$UPDATE_TMP/hydra.tar.gz" -C "$UPDATE_TMP"
    cp -a "$UPDATE_TMP/HYDRA-ULTIMATE-${BRANCH}/." "$INSTALL_DIR/"
    rm -rf "$UPDATE_TMP"
    ok "Файлы обновлены"
else
    info "Клонирование репозитория..."
    PARENT_TMP=$(mktemp -d /tmp/hydra-clone.XXXXXX)
    if git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$PARENT_TMP/repo"; then
        mkdir -p "$INSTALL_DIR"
        cp -a "$PARENT_TMP/repo/." "$INSTALL_DIR/"
    else
        warn "git clone не удался — загружаю архив..."
        ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
        curl -fsSL --connect-timeout 30 --retry 3 -o "$PARENT_TMP/hydra.tar.gz" "$ARCHIVE"
        tar -xzf "$PARENT_TMP/hydra.tar.gz" -C "$PARENT_TMP"
        mkdir -p "$INSTALL_DIR"
        cp -a "$PARENT_TMP/HYDRA-ULTIMATE-${BRANCH}/." "$INSTALL_DIR/"
    fi
    rm -rf "$PARENT_TMP"
    ok "Загружено в $INSTALL_DIR"
fi

[[ -f "${INSTALL_DIR}/main.py" ]] || { err "main.py не найден в $INSTALL_DIR"; exit 1; }

# ── Python-зависимости ──────────────────────────────────────────────────────
info "Изолированное Python-окружение..."
VENV_DIR="${INSTALL_DIR}/.venv"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade --quiet pip
"$VENV_DIR/bin/python" -m pip install --quiet "python-telegram-bot[job-queue]" "qrcode"

# ── Symlink ──────────────────────────────────────────────────────────────────
chmod +x "${INSTALL_DIR}/main.py"
cat > /usr/local/bin/hydra <<EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${INSTALL_DIR}/main.py" "\$@"
EOF
chmod 0755 /usr/local/bin/hydra

# ── [5/5] Запуск ────────────────────────────────────────────────────────────
step "[5/5] Готово"
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}     🐉 HYDRA v1.0 установлена!${NC}"
echo -e "${GREEN}${BOLD}     Запуск: sudo python3 ${INSTALL_DIR}/main.py${NC}"
echo -e "${GREEN}${BOLD}     Или:    sudo hydra${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${DIM}Лог: ${LOG_FILE}${NC}"
echo ""

if [[ -t 0 && -t 1 ]]; then
    exec "$VENV_DIR/bin/python" "$INSTALL_DIR/main.py" "$@"
fi
