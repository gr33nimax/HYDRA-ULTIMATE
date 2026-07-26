#!/usr/bin/env bash
# Transactional updater for an existing HYDRA installation.
#
# Example:
#   curl -fsSL https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/upgrade.sh \
#     | sudo HYDRA_REF=dev bash

set -Eeuo pipefail
umask 022

INSTALL_DIR="${HYDRA_INSTALL_DIR:-/opt/hydra}"
RELEASES_DIR="${HYDRA_RELEASES_DIR:-/opt/hydra-releases}"
STATE_DIR="/var/lib/hydra"
BACKUP_ROOT="${HYDRA_UPGRADE_BACKUP_DIR:-/var/backups/hydra/upgrades}"
LOCK_FILE="${HYDRA_UPGRADE_LOCK_FILE:-/run/lock/hydra-upgrade.lock}"
WRAPPER="/usr/local/bin/hydra"
REPO_URL="${HYDRA_REPO_URL:-https://github.com/gr33nimax/HYDRA-ULTIMATE}"
HYDRA_REF="${HYDRA_REF:-dev}"

info() { printf '  -> %s\n' "$*"; }
ok() { printf '  OK %s\n' "$*"; }
fail() { printf '  ERROR %s\n' "$*" >&2; exit 1; }

require_absolute_safe_path() {
    local name=$1
    local value=$2
    [[ "$value" == /* && "$value" != "/" ]] || {
        fail "$name must be an absolute path other than /"
    }
}

require_absolute_safe_path HYDRA_INSTALL_DIR "$INSTALL_DIR"
require_absolute_safe_path HYDRA_RELEASES_DIR "$RELEASES_DIR"
require_absolute_safe_path HYDRA_UPGRADE_BACKUP_DIR "$BACKUP_ROOT"
require_absolute_safe_path HYDRA_UPGRADE_LOCK_FILE "$LOCK_FILE"

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "run this updater as root"
[[ -d "$INSTALL_DIR" || -L "$INSTALL_DIR" ]] || {
    fail "existing HYDRA installation was not found at $INSTALL_DIR"
}
[[ -f "$INSTALL_DIR/main.py" ]] || fail "$INSTALL_DIR is not a HYDRA installation"
git check-ref-format --branch "$HYDRA_REF" >/dev/null 2>&1 || {
    fail "invalid HYDRA_REF: $HYDRA_REF"
}

for command in git python3 systemctl flock cp mv readlink tee; do
    command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

mkdir -p "$(dirname "$LOCK_FILE")" "$BACKUP_ROOT" "$RELEASES_DIR" /var/log/hydra
chmod 0700 "$BACKUP_ROOT"
chmod 0755 "$RELEASES_DIR"
touch /var/log/hydra/upgrade.log
chmod 0600 /var/log/hydra/upgrade.log
exec > >(tee -a /var/log/hydra/upgrade.log) 2>&1

exec 9>"$LOCK_FILE"
flock -n 9 || fail "another HYDRA upgrade is already running"

STAMP=$(date -u +%Y%m%d-%H%M%SZ)
TARGET_SHA=""
CURRENT_SHA=""
STAGE_DIR=""
RELEASE_DIR=""
ROLLBACK_DIR=""
PREVIOUS_KIND=""
PREVIOUS_TARGET=""
PREVIOUS_DIR=""
STATE_SNAPSHOT_READY=0
STATE_EXISTED=0
WRAPPER_SNAPSHOT_READY=0
WRAPPER_EXISTED=0
SERVICES_QUIESCED=0
CUTOVER_STARTED=0
declare -a MANAGED_UNITS=()
declare -a ACTIVE_UNITS=()

discover_units() {
    mapfile -t MANAGED_UNITS < <(
        systemctl list-unit-files 'hydra-*' --no-legend --no-pager 2>/dev/null \
            | awk '$1 ~ /^hydra-.*\.(service|timer)$/ {print $1}' \
            | sort -u
    )
}

capture_active_units() {
    ACTIVE_UNITS=()
    local unit
    for unit in "${MANAGED_UNITS[@]}"; do
        if systemctl is-active --quiet "$unit"; then
            ACTIVE_UNITS+=("$unit")
        fi
    done
    if ((${#ACTIVE_UNITS[@]})); then
        printf '%s\n' "${ACTIVE_UNITS[@]}" > "$ROLLBACK_DIR/active-units.txt"
    else
        : > "$ROLLBACK_DIR/active-units.txt"
    fi
}

stop_managed_units() {
    local suffix unit
    for suffix in timer service; do
        for unit in "${MANAGED_UNITS[@]}"; do
            [[ "$unit" == *".$suffix" ]] || continue
            systemctl stop "$unit"
        done
    done
}

start_previous_units() {
    local suffix unit
    systemctl daemon-reload
    for suffix in service timer; do
        for unit in "${ACTIVE_UNITS[@]}"; do
            [[ "$unit" == *".$suffix" ]] || continue
            systemctl start "$unit"
        done
    done
}

wait_for_previous_units() {
    local attempt unit all_active
    for attempt in {1..30}; do
        all_active=1
        for unit in "${ACTIVE_UNITS[@]}"; do
            if ! systemctl is-active --quiet "$unit"; then
                all_active=0
                break
            fi
        done
        ((all_active)) && return 0
        sleep 1
    done
    for unit in "${ACTIVE_UNITS[@]}"; do
        systemctl is-active --quiet "$unit" || {
            printf 'unit did not recover: %s\n' "$unit" >&2
        }
    done
    return 1
}

restore_state_snapshot() {
    ((STATE_SNAPSHOT_READY)) || return 0
    local failed_state="$ROLLBACK_DIR/state-after-failed-upgrade"
    if [[ -e "$STATE_DIR" ]]; then
        [[ ! -e "$failed_state" ]] || failed_state="${failed_state}-${BASHPID}"
        mv "$STATE_DIR" "$failed_state"
    fi
    if ((STATE_EXISTED)); then
        cp -a "$ROLLBACK_DIR/state-before-upgrade" "$STATE_DIR"
    fi
}

restore_installation() {
    ((CUTOVER_STARTED)) || return 0
    if [[ "$PREVIOUS_KIND" == "symlink" ]]; then
        local link_tmp="${INSTALL_DIR}.rollback-${BASHPID}"
        ln -s "$PREVIOUS_TARGET" "$link_tmp"
        mv -Tf "$link_tmp" "$INSTALL_DIR"
    elif [[ "$PREVIOUS_KIND" == "directory" ]]; then
        if [[ -e "$INSTALL_DIR" || -L "$INSTALL_DIR" ]]; then
            mv "$INSTALL_DIR" "$ROLLBACK_DIR/failed-install-link"
        fi
        mv "$PREVIOUS_DIR" "$INSTALL_DIR"
    fi
}

restore_wrapper() {
    ((WRAPPER_SNAPSHOT_READY)) || return 0
    if [[ -e "$WRAPPER" || -L "$WRAPPER" ]]; then
        mv "$WRAPPER" "$ROLLBACK_DIR/wrapper-after-failed-upgrade"
    fi
    if ((WRAPPER_EXISTED)); then
        cp -a "$ROLLBACK_DIR/wrapper-before-upgrade" "$WRAPPER"
    fi
}

rollback() {
    local code=$1
    local line=$2
    trap - ERR
    set +e
    printf '\nUpgrade failed at line %s (exit %s); rolling back.\n' "$line" "$code" >&2
    if ((SERVICES_QUIESCED)); then
        discover_units
        stop_managed_units
    fi
    restore_state_snapshot
    restore_installation
    restore_wrapper
    if ((SERVICES_QUIESCED)); then
        start_previous_units
        wait_for_previous_units
    fi
    if [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" && -n "$ROLLBACK_DIR" ]]; then
        mv "$STAGE_DIR" "$ROLLBACK_DIR/failed-staged-release"
    fi
    printf 'Rollback artifacts: %s\n' "${ROLLBACK_DIR:-not created}" >&2
    exit "$code"
}
trap 'rollback $? $LINENO' ERR

info "Resolving $HYDRA_REF from $REPO_URL"
TARGET_SHA=$(
    git ls-remote --exit-code "$REPO_URL" "refs/heads/$HYDRA_REF" \
        | awk 'NR == 1 {print $1}'
)
[[ "$TARGET_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "could not resolve the target commit"

if [[ -d "$INSTALL_DIR/.git" ]]; then
    [[ -z "$(git -C "$INSTALL_DIR" status --porcelain --untracked-files=all)" ]] || {
        fail "local changes exist in $INSTALL_DIR; preserve or remove them before upgrading"
    }
    CURRENT_SHA=$(git -C "$INSTALL_DIR" rev-parse HEAD)
else
    CURRENT_SHA=$(tr -d '[:space:]' < "$INSTALL_DIR/.hydra-source-revision" 2>/dev/null || true)
fi
[[ "$CURRENT_SHA" =~ ^[0-9a-f]{40}$ ]] || {
    fail "cannot identify the currently installed revision"
}
[[ "$CURRENT_SHA" != "$TARGET_SHA" ]] || {
    ok "already running ${TARGET_SHA:0:12}; nothing to upgrade"
    exit 0
}

ROLLBACK_DIR="$BACKUP_ROOT/${STAMP}-${CURRENT_SHA:0:12}-to-${TARGET_SHA:0:12}"
mkdir "$ROLLBACK_DIR"
chmod 0700 "$ROLLBACK_DIR"
STAGE_DIR="$RELEASES_DIR/.staging-${TARGET_SHA}-${STAMP}-${BASHPID}"
RELEASE_DIR="$RELEASES_DIR/${TARGET_SHA}-${STAMP}"

cat > "$ROLLBACK_DIR/metadata.env" <<EOF
HYDRA_FROM_SHA=$CURRENT_SHA
HYDRA_TO_SHA=$TARGET_SHA
HYDRA_REF=$HYDRA_REF
HYDRA_REPO_URL=$REPO_URL
HYDRA_INSTALL_DIR=$INSTALL_DIR
EOF
chmod 0600 "$ROLLBACK_DIR/metadata.env"

info "Staging exact commit ${TARGET_SHA:0:12}"
git init --quiet "$STAGE_DIR"
git -C "$STAGE_DIR" remote add origin "$REPO_URL"
git -C "$STAGE_DIR" fetch --quiet --depth 1 origin "$TARGET_SHA"
[[ "$(git -C "$STAGE_DIR" rev-parse FETCH_HEAD)" == "$TARGET_SHA" ]] || {
    fail "downloaded commit does not match the resolved branch tip"
}
git -C "$STAGE_DIR" checkout --quiet --detach "$TARGET_SHA"

python3 -m venv "$STAGE_DIR/.venv"
"$STAGE_DIR/.venv/bin/python" -m pip install \
    --disable-pip-version-check --quiet -r "$STAGE_DIR/requirements.lock"
"$STAGE_DIR/.venv/bin/python" -m compileall -q \
    "$STAGE_DIR/main.py" "$STAGE_DIR/hydra"
HYDRA_INSTALL_DIR="$STAGE_DIR" "$STAGE_DIR/.venv/bin/python" \
    -c 'from hydra import __version__; print(__version__)' \
    > "$ROLLBACK_DIR/target-version.txt"

info "Running read-only target preflight against the live state"
(
    cd "$STAGE_DIR"
    export HYDRA_INSTALL_DIR="$STAGE_DIR"
    "$STAGE_DIR/.venv/bin/python" -m hydra.cli upgrade check \
        > "$ROLLBACK_DIR/preflight-upgrade.json"
    "$STAGE_DIR/.venv/bin/python" -m hydra.cli validate \
        > "$ROLLBACK_DIR/preflight-validate.json"
    "$STAGE_DIR/.venv/bin/python" -m hydra.cli plan \
        > "$ROLLBACK_DIR/preflight-plan.json"
    "$STAGE_DIR/.venv/bin/python" - "$ROLLBACK_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
upgrade = json.loads((root / "preflight-upgrade.json").read_text())
plan = json.loads((root / "preflight-plan.json").read_text())
if not upgrade.get("ready"):
    raise SystemExit(f"upgrade preflight failed: {upgrade.get('failures', [])}")
if not plan.get("valid"):
    raise SystemExit(f"configuration preflight failed: {plan.get('conflicts', [])}")
PY
)

discover_units
capture_active_units
info "Quiescing ${#ACTIVE_UNITS[@]} active HYDRA unit(s)"
SERVICES_QUIESCED=1
stop_managed_units

if [[ -d "$STATE_DIR" ]]; then
    cp -a "$STATE_DIR" "$ROLLBACK_DIR/state-before-upgrade"
    STATE_EXISTED=1
fi
STATE_SNAPSHOT_READY=1

if [[ -e "$WRAPPER" || -L "$WRAPPER" ]]; then
    cp -a "$WRAPPER" "$ROLLBACK_DIR/wrapper-before-upgrade"
    WRAPPER_EXISTED=1
fi
WRAPPER_SNAPSHOT_READY=1

info "Creating and verifying an application-level backup"
HYDRA_INSTALL_DIR="$STAGE_DIR" "$STAGE_DIR/.venv/bin/python" \
    -m hydra.cli backup \
    --output "$ROLLBACK_DIR/hydra-backup.tar.gz" \
    > "$ROLLBACK_DIR/backup.json"
HYDRA_INSTALL_DIR="$STAGE_DIR" "$STAGE_DIR/.venv/bin/python" \
    -m hydra.cli restore "$ROLLBACK_DIR/hydra-backup.tar.gz" --dry-run \
    > "$ROLLBACK_DIR/backup-verification.json"

info "Persisting the target state schema while writers are stopped"
HYDRA_INSTALL_DIR="$STAGE_DIR" "$STAGE_DIR/.venv/bin/python" \
    -m hydra.cli upgrade migrate-state \
    > "$ROLLBACK_DIR/state-migration.json"
HYDRA_INSTALL_DIR="$STAGE_DIR" "$STAGE_DIR/.venv/bin/python" \
    -m hydra.cli validate \
    > "$ROLLBACK_DIR/state-validation.json"

mv "$STAGE_DIR" "$RELEASE_DIR"
STAGE_DIR=""

info "Switching /opt entrypoint to the staged release"
if [[ -L "$INSTALL_DIR" ]]; then
    PREVIOUS_KIND="symlink"
    PREVIOUS_TARGET=$(readlink "$INSTALL_DIR")
    link_tmp="${INSTALL_DIR}.next-${BASHPID}"
    ln -s "$RELEASE_DIR" "$link_tmp"
    CUTOVER_STARTED=1
    mv -Tf "$link_tmp" "$INSTALL_DIR"
else
    PREVIOUS_KIND="directory"
    PREVIOUS_DIR="$RELEASES_DIR/previous-${CURRENT_SHA}-${STAMP}"
    CUTOVER_STARTED=1
    mv "$INSTALL_DIR" "$PREVIOUS_DIR"
    ln -s "$RELEASE_DIR" "$INSTALL_DIR"
fi

wrapper_tmp=$(mktemp "$(dirname "$WRAPPER")/.hydra-wrapper.XXXXXX")
printf '#!/usr/bin/env bash\nexec "%s/.venv/bin/python" "%s/main.py" "$@"\n' \
    "$INSTALL_DIR" "$INSTALL_DIR" > "$wrapper_tmp"
chmod 0755 "$wrapper_tmp"
mv -f "$wrapper_tmp" "$WRAPPER"

start_previous_units

info "Running post-cutover validation"
HYDRA_INSTALL_DIR="$INSTALL_DIR" "$INSTALL_DIR/.venv/bin/python" \
    -m hydra.cli validate > "$ROLLBACK_DIR/post-validate.json"
HYDRA_INSTALL_DIR="$INSTALL_DIR" "$INSTALL_DIR/.venv/bin/python" \
    -m hydra.cli plan > "$ROLLBACK_DIR/post-plan.json"
HYDRA_INSTALL_DIR="$INSTALL_DIR" "$INSTALL_DIR/.venv/bin/python" \
    -m hydra.cli status > "$ROLLBACK_DIR/post-status.json"
HYDRA_INSTALL_DIR="$INSTALL_DIR" "$INSTALL_DIR/.venv/bin/python" \
    - "$ROLLBACK_DIR/post-plan.json" <<'PY'
import json
import pathlib
import sys

plan = json.loads(pathlib.Path(sys.argv[1]).read_text())
if not plan.get("valid"):
    raise SystemExit(f"post-cutover plan failed: {plan.get('conflicts', [])}")
PY
wait_for_previous_units

[[ "$(git -C "$INSTALL_DIR" rev-parse HEAD)" == "$TARGET_SHA" ]] || {
    fail "installed revision changed during cutover"
}

printf '%s\n' "$TARGET_SHA" > "$ROLLBACK_DIR/SUCCESS"
chmod 0600 "$ROLLBACK_DIR/SUCCESS"
SERVICES_QUIESCED=0
CUTOVER_STARTED=0
STATE_SNAPSHOT_READY=0
WRAPPER_SNAPSHOT_READY=0
trap - ERR

ok "HYDRA upgraded ${CURRENT_SHA:0:12} -> ${TARGET_SHA:0:12} from $HYDRA_REF"
ok "Rollback snapshot retained at $ROLLBACK_DIR"
