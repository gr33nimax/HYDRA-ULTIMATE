#!/usr/bin/env bash
# HYDRA — installer for a new Ubuntu/Debian VPS.
#
# Установка:
#   curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/main/bootstrap.sh | sudo bash
#
# Для обновления рабочей установки используйте updater.sh, а не этот файл.

set -Eeuo pipefail

# Keep the installer usable behind an explicitly configured proxy.  The old
# installer removed proxy variables and made otherwise reachable servers fail.
umask 022

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info() { echo -e "  ${CYAN}→${NC} $*"; }
ok() { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
err() { echo -e "  ${RED}✗${NC} $*"; }

title() {
    echo -e "${BOLD}${CYAN}HYDRA · $*${NC}"
    echo -e "${DIM}────────────────────────────────────────${NC}"
}

step() {
    local current=$1
    local total=$2
    shift 2
    echo -e "\n${BOLD}[${current}/${total}] $*${NC}"
}

result_ok() {
    echo -e "\n${GREEN}${BOLD}ГОТОВО: $*${NC}"
}

result_error() {
    echo -e "\n${RED}${BOLD}ОШИБКА: $*${NC}" >&2
}

support_reminder() {
    echo ""
    echo -e "  ${DIM}Поддержать разработку:${NC} ${CYAN}https://web.tribute.tg/d/QHN${NC}"
}

INSTALL_COMPLETED=0
ERROR_REPORTED=0

on_exit() {
    local code=$?
    trap - EXIT
    if ((code != 0 && ! INSTALL_COMPLETED && ! ERROR_REPORTED)); then
        result_error "Установка не завершена (код ${code})."
        err "Исправьте указанную выше ошибку и запустите ту же команду ещё раз."
        if [[ -f /var/log/hydra/install.log ]]; then
            err "Подробный лог: /var/log/hydra/install.log"
        fi
    fi
    exit "$code"
}

# Both a failed step and an interrupted one need the same cleanup: the checkout goes back to
# the previous verified revision, and the previous directory is put back in place.
restore_previous_installation() {
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
}

on_error() {
    local code=$?
    restore_previous_installation
    ERROR_REPORTED=1
    result_error "Установка не завершена (строка ${BASH_LINENO[0]}, код ${code})."
    err "Подробный лог: /var/log/hydra/install.log"
    exit "$code"
}

# A dropped SSH session used to kill the installer in the middle of pip, the sing-box download
# or the venv: no message, no cleanup, and a half-written checkout to guess about. An interrupt
# gets the same recovery as a failure, and says which one it was.
on_signal() {
    local name=$1
    local code=$2
    trap - ERR HUP INT TERM
    restore_previous_installation
    ERROR_REPORTED=1
    result_error "Установка прервана (${name}). Система осталась в промежуточном состоянии."
    err "Повторите ту же команду: установка продолжит с этого места."
    if [[ -f /var/log/hydra/install.log ]]; then
        err "Подробный лог: /var/log/hydra/install.log"
    fi
    exit "$code"
}

trap on_error ERR
trap on_exit EXIT
trap 'on_signal HUP 129' HUP
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM

title "УСТАНОВКА HYDRA"
step 1 5 "Проверка системы"
if [[ $EUID -ne 0 ]]; then
    err "Требуются права root"
    err "Запустите установочную команду с sudo."
    exit 1
fi
ok "Права root"

LOG_DIR=/var/log/hydra
LOG_FILE=${LOG_DIR}/install.log
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
# Keep output visible while also making the advertised install log real.
exec > >(tee -a "$LOG_FILE") 2>&1

if [[ -f /etc/os-release ]]; then
    # A system file that exists at run time on every supported host: shellcheck cannot follow it
    # and says so (SC1091), which is information rather than a defect to fix in the script.
    # shellcheck source=/dev/null
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    err "Не удалось определить ОС"
    exit 1
fi

case "$OS" in
ubuntu | debian)
    ok "ОС: $OS $VER"
    PKG_INSTALL="apt-get install -y -qq"
    ;;
*)
    err "Поддерживаются только Ubuntu/Debian. Обнаружено: $OS"
    exit 1
    ;;
esac
command -v apt-get >/dev/null || {
    err "apt-get не найден"
    exit 1
}

step 2 5 "Системные зависимости"

apt-get update -qq

MISSING=()
command -v python3 &>/dev/null || MISSING+=("python3")
command -v curl &>/dev/null || MISSING+=("curl")
command -v git &>/dev/null || MISSING+=("git")
command -v tar &>/dev/null || MISSING+=("tar")
command -v sha256sum &>/dev/null || MISSING+=("coreutils")
command -v file &>/dev/null || MISSING+=("file")
python3 -c 'import ensurepip' &>/dev/null || MISSING+=("python3-venv")

for pkg in "${MISSING[@]}"; do
    info "Устанавливаю: $pkg"
    $PKG_INSTALL "$pkg"
done

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_OK=$(python3 -c "import sys; print(int(sys.version_info >= (3, 10)))")
if [[ "$PY_OK" != "1" ]]; then
    err "Требуется Python >= 3.10, найден $PY_VER"
    err "Debian 11 (Python 3.9) и Ubuntu 20.04 (Python 3.8) не подходят: нужен Debian 12+ или Ubuntu 22.04+"
    exit 1
fi
ok "Python $PY_VER: подходит"

# New installations get a private KDF secret. Existing state files retain the
# legacy derivation so current client links and credentials do not rotate.
HYDRA_FRESH_INSTALL=0
if [[ ! -f /var/lib/hydra/state.json ]]; then
    HYDRA_FRESH_INSTALL=1
fi
if [[ ! -f /var/lib/hydra/state.json && ! -f /var/lib/hydra/master.key ]]; then
    mkdir -p /var/lib/hydra
    umask 077
    python3 -c 'import secrets; open("/var/lib/hydra/master.key", "wb").write(secrets.token_bytes(32))'
    chmod 600 /var/lib/hydra/master.key
    umask 022
fi

# Дополнительные пакеты
# nftables is required by every TPROXY transport: the binary used to be assumed present until
# the first apply failed on a minimal image.
$PKG_INSTALL iptables nftables iproute2 gnupg ca-certificates certbot ufw

step 3 5 "Совместимое ядро"
if command -v sing-box &>/dev/null &&
    sing-box version 2>/dev/null | head -1 | grep -qi "hydracore"; then
    info "Обнаружен Hydracore; установщик не заменяет стороннее ядро"
    ok "Ядро сохранено: $(sing-box version 2>/dev/null | head -1)"
else
    # The channel is the switch that decides which release is installed; the
    # version is always resolved at install time from GitHub.
    HC_CHANNEL="stable"
    info "Установка проверенного Hydracore VPS (канал ${HC_CHANNEL})..."
    ARCH=$(uname -m)
    case "$ARCH" in
    x86_64 | amd64) HC_ARCH="amd64" ;;
    aarch64 | arm64) HC_ARCH="arm64" ;;
    *)
        err "Неподдерживаемая архитектура: $ARCH"
        exit 1
        ;;
    esac

    HC_META=$(curl -fsSL --connect-timeout 30 --retry 3 "https://api.github.com/repos/gr33nimax/hydracore/releases?per_page=100" |
        python3 -c "
import sys, json
channel = '${HC_CHANNEL}'
asset_name = 'hydracore-vps-linux-${HC_ARCH}.tar.gz'

def eligible(release):
    if release.get('draft') or not str(release.get('tag_name') or ''):
        return False
    tag = str(release.get('tag_name'))
    if channel == 'stable':
        return not release.get('prerelease')
    # The debug channel serves the readable prereleases and never the retired
    # '-debug.<n>' form, matching the selector the running HYDRA uses.
    return (
        release.get('prerelease') is True
        and '-debug.' not in tag
        and ('-debug-' in tag or '-rc-' in tag)
    )

best = None
for release in json.load(sys.stdin):
    if not eligible(release):
        continue
    asset = next(
        (item for item in release.get('assets', []) if item.get('name') == asset_name),
        None,
    )
    if asset is None:
        continue
    order = (
        str(release.get('published_at') or ''),
        str(release.get('created_at') or ''),
        str(release.get('tag_name')),
    )
    if best is None or order > best[0]:
        best = (order, asset, str(release.get('tag_name')))

if best is not None:
    print(best[1].get('browser_download_url', ''), best[1].get('digest', ''), best[2])
")

    read -r HC_URL HC_DIGEST HC_TAG <<<"$HC_META"
    [[ -n "$HC_URL" && -n "$HC_TAG" ]] || {
        err "Не удалось определить релиз Hydracore для канала ${HC_CHANNEL}"
        exit 1
    }
    HC_TMP=$(mktemp -d /tmp/hydra-hydracore.XXXXXX)
    curl -fsSL --connect-timeout 30 --retry 3 "$HC_URL" -o "$HC_TMP/hydracore.tar.gz"
    if [[ "$HC_DIGEST" == sha256:* ]]; then
        EXPECTED_SHA=${HC_DIGEST#sha256:}
        ACTUAL_SHA=$(sha256sum "$HC_TMP/hydracore.tar.gz" | awk '{print $1}')
        [[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || {
            err "Проверка целостности Hydracore не пройдена"
            exit 1
        }
        ok "Проверка целостности Hydracore пройдена"
    else
        err "GitHub не предоставил SHA-256 для Hydracore; установка остановлена"
        exit 1
    fi
    tar -xzf "$HC_TMP/hydracore.tar.gz" -C "$HC_TMP"
    HC_BIN=$(find "$HC_TMP" -type f -name sing-box -size +1M -print -quit)
    [[ -n "$HC_BIN" ]] || {
        err "В архиве нет исполняемого файла Hydracore"
        exit 1
    }
    file "$HC_BIN" | grep -q 'ELF .* executable' || {
        err "Файл Hydracore не является исполняемым ELF-файлом"
        exit 1
    }
    install -m 0755 "$HC_BIN" /usr/local/bin/sing-box.new
    /usr/local/bin/sing-box.new version >/dev/null
    /usr/local/bin/sing-box.new version | head -1 | grep -qi "hydracore" || {
        err "Подлинность Hydracore не подтверждена"
        exit 1
    }
    mv -f /usr/local/bin/sing-box.new /usr/local/bin/sing-box
    rm -rf "$HC_TMP"
    ok "Hydracore: $(sing-box version 2>/dev/null | head -1)"
fi

step 4 5 "Загрузка и проверка HYDRA"
INSTALL_DIR="/opt/hydra"
REPO_URL="https://github.com/gr33nimax/HYDRA-ULTIMATE"
DEFAULT_BRANCH="main"
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
    err "Не удалось определить коммит ветки $HYDRA_REF"
    exit 1
fi
info "Выбрана ветка ${HYDRA_REF}, коммит ${HYDRA_TARGET_REV:0:12}"

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
    printf '%s\n' "$HYDRA_TARGET_REV" >"$INSTALL_DIR/.hydra-source-revision"
    rm -rf "$UPDATE_TMP"
    ok "Файлы обновлены"
else
    info "Клонирование репозитория..."
    PARENT_TMP=$(mktemp -d /tmp/hydra-clone.XXXXXX)
    if git clone --quiet --depth 1 --branch "$HYDRA_REF" "$REPO_URL" "$PARENT_TMP/repo" &&
        [[ "$(git -C "$PARENT_TMP/repo" rev-parse HEAD)" == "$HYDRA_TARGET_REV" ]]; then
        mkdir -p "$INSTALL_DIR"
        cp -a "$PARENT_TMP/repo/." "$INSTALL_DIR/"
    else
        warn "git clone не дал выбранный коммит — загружаю точный архив..."
        rm -rf "$PARENT_TMP/repo"
        ARCHIVE="${REPO_URL}/archive/${HYDRA_TARGET_REV}.tar.gz"
        curl -fsSL --connect-timeout 30 --retry 3 -o "$PARENT_TMP/hydra.tar.gz" "$ARCHIVE"
        mkdir -p "$INSTALL_DIR"
        tar -xzf "$PARENT_TMP/hydra.tar.gz" -C "$INSTALL_DIR" --strip-components=1
        printf '%s\n' "$HYDRA_TARGET_REV" >"$INSTALL_DIR/.hydra-source-revision"
    fi
    rm -rf "$PARENT_TMP"
    ok "Загружено в $INSTALL_DIR"
fi

[[ -f "${INSTALL_DIR}/main.py" ]] || {
    err "main.py не найден в $INSTALL_DIR"
    exit 1
}
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    HYDRA_INSTALLED_REV=$(git -C "$INSTALL_DIR" rev-parse HEAD)
else
    HYDRA_INSTALLED_REV=$(cat "$INSTALL_DIR/.hydra-source-revision" 2>/dev/null || true)
fi
if [[ "$HYDRA_INSTALLED_REV" != "$HYDRA_TARGET_REV" ]]; then
    err "Проверка версии не пройдена: ожидался $HYDRA_TARGET_REV, установлен ${HYDRA_INSTALLED_REV:-не определён}"
    exit 1
fi
ok "Проверка коммита: ${HYDRA_INSTALLED_REV:0:12}"

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

if ! bash "$INSTALL_DIR/deploy/apply-resource-defaults.sh"; then
    warn "Не удалось применить стандартные лимиты памяти и журналов; установка продолжена"
fi

# ── Symlink ──────────────────────────────────────────────────────────────────
chmod +x "${INSTALL_DIR}/main.py"
# Older releases created /usr/local/bin/hydra as a symlink to main.py.  Remove
# it before writing the wrapper, otherwise shell redirection follows the link
# and overwrites the Python entrypoint.
rm -f /usr/local/bin/hydra
cat >/usr/local/bin/hydra <<EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${INSTALL_DIR}/main.py" "\$@"
EOF
chmod 0755 /usr/local/bin/hydra

if [[ "$HYDRA_FRESH_INSTALL" == "1" ]]; then
    # The command answers in JSON, so stdout stays quiet — but a failure has to say why: the
    # apply behind this step names the missing prerequisite, and "строка N" does not.
    CREATE_USER_LOG=$(mktemp)
    if ! "$VENV_DIR/bin/python" "$INSTALL_DIR/main.py" user ensure-default >"$CREATE_USER_LOG" 2>&1; then
        err "Не удалось создать первого пользователя:"
        sed 's/^/    /' "$CREATE_USER_LOG" >&2
        rm -f "$CREATE_USER_LOG"
        exit 1
    fi
    rm -f "$CREATE_USER_LOG"
    ok "Создан первый пользователь: default"
fi

step 5 5 "Завершение"
HYDRA_VERSION=$("$VENV_DIR/bin/python" -c "from hydra import __version__; print(__version__)" 2>/dev/null || echo unknown)
result_ok "HYDRA v${HYDRA_VERSION} установлена"
echo -e "  Запуск: ${BOLD}sudo hydra${NC}"
echo -e "  Проверка: ${BOLD}hydra check${NC}"
echo -e "  Лог: ${DIM}${LOG_FILE}${NC}"
support_reminder
echo ""

INSTALL_COMPLETED=1
if [[ -t 0 && -t 1 ]]; then
    exec "$VENV_DIR/bin/python" "$INSTALL_DIR/main.py" "$@"
fi
