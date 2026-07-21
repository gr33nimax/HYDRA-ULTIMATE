#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# HYDRA v2.5.2-dev — Bootstrap Installer

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
    if [[ -n "${HYDRA_PREVIOUS_REV:-}" && -d "${INSTALL_DIR:-}/.git" ]]; then
        warn "Возвращаю код HYDRA к предыдущей проверенной версии..."
        if [[ -n "${HYDRA_PREVIOUS_REF:-}" ]]; then
            git -C "$INSTALL_DIR" checkout -B "$HYDRA_PREVIOUS_REF" "$HYDRA_PREVIOUS_REV" >/dev/null 2>&1 || true
        else
            git -C "$INSTALL_DIR" checkout --detach "$HYDRA_PREVIOUS_REV" >/dev/null 2>&1 || true
        fi
    fi
    if [[ -n "${HYDRA_BACKUP_DIR:-}" && -d "$HYDRA_BACKUP_DIR/old" ]]; then
        warn "Восстанавливаю предыдущий каталог HYDRA..."
        if [[ -e "${INSTALL_DIR:-}" ]]; then
            mv "$INSTALL_DIR" "$HYDRA_BACKUP_DIR/failed" || true
        fi
        mv "$HYDRA_BACKUP_DIR/old" "$INSTALL_DIR" || true
    fi
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

# New installations get a private KDF secret. Existing state files retain the
# legacy derivation so current client links and credentials do not rotate.
if [[ ! -f /var/lib/hydra/state.json && ! -f /var/lib/hydra/master.key ]]; then
    mkdir -p /var/lib/hydra
    umask 077
    python3 -c 'import secrets; open("/var/lib/hydra/master.key", "wb").write(secrets.token_bytes(32))'
    chmod 600 /var/lib/hydra/master.key
    umask 022
fi

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
        err "GitHub не предоставил SHA-256 для Sing-Box; установка остановлена"
        exit 1
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
DEFAULT_BRANCH="dev"
HYDRA_REF="${HYDRA_REF:-$DEFAULT_BRANCH}"
if ! git check-ref-format --branch "$HYDRA_REF" >/dev/null 2>&1; then
    err "Некорректное имя ветки HYDRA_REF: $HYDRA_REF"
    exit 1
fi
HYDRA_REMOTE_REF="refs/heads/${HYDRA_REF}"
if ! HYDRA_TARGET_REV=$(git ls-remote --exit-code "$REPO_URL" "$HYDRA_REMOTE_REF" | awk 'NR == 1 {print $1}'); then
    err "Ветка $HYDRA_REF не найдена в $REPO_URL"
    exit 1
fi
if [[ ! "$HYDRA_TARGET_REV" =~ ^[0-9a-f]{40}$ ]]; then
    err "Не удалось определить commit ветки $HYDRA_REF"
    exit 1
fi
info "Выбрана ветка ${HYDRA_REF}, commit ${HYDRA_TARGET_REV:0:12}"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Обновление репозитория..."
    cd "$INSTALL_DIR"
    if ! git diff --quiet || [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        err "В $INSTALL_DIR есть локальные изменения; обновление остановлено, чтобы их не удалить."
        exit 1
    fi
    HYDRA_PREVIOUS_REV=$(git rev-parse HEAD)
    HYDRA_PREVIOUS_REF=$(git symbolic-ref --quiet --short HEAD || true)
    # Fetch the already resolved branch tip by SHA. A branch movement during
    # installation therefore cannot make different paths install different
    # revisions.
    git fetch --quiet "$REPO_URL" "$HYDRA_TARGET_REV"
    git checkout --quiet -B "$HYDRA_REF" "$HYDRA_TARGET_REV"
    ok "Репозиторий обновлён"
elif [[ -d "$INSTALL_DIR" ]]; then
    info "Установка без git — принудительное обновление..."
    ARCHIVE="${REPO_URL}/archive/${HYDRA_TARGET_REV}.tar.gz"
    UPDATE_TMP=$(mktemp -d /tmp/hydra-update.XXXXXX)
    HYDRA_BACKUP_DIR=$(mktemp -d /tmp/hydra-previous.XXXXXX)
    mv "$INSTALL_DIR" "$HYDRA_BACKUP_DIR/old"
    curl -fsSL --connect-timeout 30 --retry 3 -o "$UPDATE_TMP/hydra.tar.gz" "$ARCHIVE"
    mkdir -p "$INSTALL_DIR"
    tar -xzf "$UPDATE_TMP/hydra.tar.gz" -C "$INSTALL_DIR" --strip-components=1
    printf '%s\n' "$HYDRA_TARGET_REV" > "$INSTALL_DIR/.hydra-source-revision"
    rm -rf "$UPDATE_TMP"
    ok "Файлы обновлены"
else
    info "Клонирование репозитория..."
    PARENT_TMP=$(mktemp -d /tmp/hydra-clone.XXXXXX)
    if git clone --quiet --depth 1 --branch "$HYDRA_REF" "$REPO_URL" "$PARENT_TMP/repo" \
        && [[ "$(git -C "$PARENT_TMP/repo" rev-parse HEAD)" == "$HYDRA_TARGET_REV" ]]; then
        mkdir -p "$INSTALL_DIR"
        cp -a "$PARENT_TMP/repo/." "$INSTALL_DIR/"
    else
        warn "git clone не дал выбранный commit — загружаю точный архив..."
        rm -rf "$PARENT_TMP/repo"
        ARCHIVE="${REPO_URL}/archive/${HYDRA_TARGET_REV}.tar.gz"
        curl -fsSL --connect-timeout 30 --retry 3 -o "$PARENT_TMP/hydra.tar.gz" "$ARCHIVE"
        mkdir -p "$INSTALL_DIR"
        tar -xzf "$PARENT_TMP/hydra.tar.gz" -C "$INSTALL_DIR" --strip-components=1
        printf '%s\n' "$HYDRA_TARGET_REV" > "$INSTALL_DIR/.hydra-source-revision"
    fi
    rm -rf "$PARENT_TMP"
    ok "Загружено в $INSTALL_DIR"
fi

[[ -f "${INSTALL_DIR}/main.py" ]] || { err "main.py не найден в $INSTALL_DIR"; exit 1; }
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    HYDRA_INSTALLED_REV=$(git -C "$INSTALL_DIR" rev-parse HEAD)
else
    HYDRA_INSTALLED_REV=$(cat "$INSTALL_DIR/.hydra-source-revision" 2>/dev/null || true)
fi
if [[ "$HYDRA_INSTALLED_REV" != "$HYDRA_TARGET_REV" ]]; then
    err "Проверка версии не пройдена: ожидался $HYDRA_TARGET_REV, установлен ${HYDRA_INSTALLED_REV:-unknown}"
    exit 1
fi
ok "Проверка commit: ${HYDRA_INSTALLED_REV:0:12}"

# ── Python-зависимости ──────────────────────────────────────────────────────
info "Изолированное Python-окружение..."
VENV_DIR="${INSTALL_DIR}/.venv"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade --quiet pip
"$VENV_DIR/bin/python" -m pip install --quiet -r "${INSTALL_DIR}/requirements.lock"
"$VENV_DIR/bin/python" -m compileall -q "${INSTALL_DIR}/main.py" "${INSTALL_DIR}/hydra"
HYDRA_PREVIOUS_REV=""
if [[ -n "${HYDRA_BACKUP_DIR:-}" ]]; then
    rm -rf "$HYDRA_BACKUP_DIR"
    HYDRA_BACKUP_DIR=""
fi

# ── Symlink ──────────────────────────────────────────────────────────────────
chmod +x "${INSTALL_DIR}/main.py"
# Older releases created /usr/local/bin/hydra as a symlink to main.py.  Remove
# it before writing the wrapper, otherwise shell redirection follows the link
# and overwrites the Python entrypoint.
rm -f /usr/local/bin/hydra
cat > /usr/local/bin/hydra <<EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${INSTALL_DIR}/main.py" "\$@"
EOF
chmod 0755 /usr/local/bin/hydra

# ── [5/5] Запуск ────────────────────────────────────────────────────────────
step "[5/5] Готово"
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
HYDRA_VERSION=$("$VENV_DIR/bin/python" -c "from hydra import __version__; print(__version__)" 2>/dev/null || echo unknown)
echo -e "${GREEN}${BOLD}     🐉 HYDRA v${HYDRA_VERSION} установлена!${NC}"
echo -e "${GREEN}${BOLD}     Запуск: sudo hydra${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${DIM}Лог: ${LOG_FILE}${NC}"
echo ""

if [[ -t 0 && -t 1 ]]; then
    exec "$VENV_DIR/bin/python" "$INSTALL_DIR/main.py" "$@"
fi

