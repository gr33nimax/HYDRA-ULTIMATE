#!/usr/bin/env bash
# Transactional updater for an existing HYDRA installation.
#
# Download the complete script before executing it. See docs/DEV_UPGRADE.md.

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
fail() { printf '  ERROR %s\n' "$*" >&2; return 1; }

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

for command in git python3 systemctl flock cp mv readlink stat tee; do
    command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

mkdir -p "$(dirname "$LOCK_FILE")" "$BACKUP_ROOT" "$RELEASES_DIR" /var/log/hydra
chmod 0700 "$BACKUP_ROOT"
chmod 0755 "$RELEASES_DIR"
if [[ ! -L "$INSTALL_DIR" ]]; then
    [[ "$(stat -c %d -- "$INSTALL_DIR")" == "$(stat -c %d -- "$RELEASES_DIR")" ]] || {
        fail "HYDRA_INSTALL_DIR and HYDRA_RELEASES_DIR must share a filesystem"
    }
fi
touch /var/log/hydra/upgrade.log
chmod 0600 /var/log/hydra/upgrade.log
exec > >(tee -a /var/log/hydra/upgrade.log) 2>&1

exec 9>"$LOCK_FILE"
flock -n 9 || fail "another HYDRA upgrade is already running"

STAMP=$(date -u +%Y%m%d-%H%M%SZ)
UPDATER_BASHPID=$BASHPID
TARGET_SHA=""
CURRENT_SHA=""
STAGE_DIR=""
RELEASE_DIR=""
ROLLBACK_DIR=""
PREVIOUS_KIND=""
PREVIOUS_TARGET=""
PREVIOUS_DIR=""
STATE_ROLLBACK_DIR="${STATE_DIR}.upgrade-rollback-${STAMP}-${UPDATER_BASHPID}"
STATE_SNAPSHOT_READY=0
STATE_EXISTED=0
STATE_MUTATION_STARTED=0
WRAPPER_SNAPSHOT_READY=0
WRAPPER_EXISTED=0
WRAPPER_MUTATION_STARTED=0
WRAPPER_TMP=""
CUTOVER_LINK=""
SERVICES_QUIESCED=0
CUTOVER_STARTED=0
declare -a MANAGED_UNITS=()
declare -a ACTIVE_UNITS=()

run_stage_python() {
    (
        trap - ERR HUP INT TERM
        cd "$STAGE_DIR"
        PYTHONPATH="$STAGE_DIR" HYDRA_INSTALL_DIR="$STAGE_DIR" \
            "$STAGE_DIR/.venv/bin/python" "$@"
    )
}

run_install_python() {
    (
        trap - ERR HUP INT TERM
        cd "$INSTALL_DIR"
        PYTHONPATH="$INSTALL_DIR" HYDRA_INSTALL_DIR="$INSTALL_DIR" \
            "$INSTALL_DIR/.venv/bin/python" "$@"
    )
}

discover_units() {
    local state unit unit_files
    MANAGED_UNITS=()
    if ! unit_files=$(
        systemctl list-unit-files 'hydra-*' --no-legend --no-pager 2>/dev/null
    ); then
        fail "cannot enumerate HYDRA systemd units"
        return 1
    fi
    while read -r unit state _; do
        [[ "$unit" =~ ^hydra-.*\.(service|timer)$ ]] || continue
        MANAGED_UNITS+=("$unit")
    done <<< "$unit_files"
}

capture_active_units() {
    ACTIVE_UNITS=()
    local active_state key properties remain_after_exit unit unit_type value
    for unit in "${MANAGED_UNITS[@]}"; do
        if ! properties=$(
            systemctl show "$unit" \
                --property=ActiveState,Type,RemainAfterExit \
                --no-pager 2>/dev/null
        ); then
            fail "cannot inspect systemd unit: $unit"
            return 1
        fi
        active_state=""
        unit_type=""
        remain_after_exit=""
        while IFS="=" read -r key value; do
            case "$key" in
                ActiveState) active_state=$value ;;
                Type) unit_type=$value ;;
                RemainAfterExit) remain_after_exit=$value ;;
            esac
        done <<< "$properties"
        [[ -n "$active_state" ]] || {
            fail "systemd returned incomplete state for unit: $unit"
            return 1
        }
        case "$active_state" in
            active | activating | reloading) ;;
            *) continue ;;
        esac
        if [[ "$unit_type" == "oneshot" && "$remain_after_exit" != "yes" ]]; then
            continue
        fi
        ACTIVE_UNITS+=("$unit")
    done
    if ((${#ACTIVE_UNITS[@]})); then
        printf '%s\n' "${ACTIVE_UNITS[@]}" > "$ROLLBACK_DIR/active-units.txt"
    else
        : > "$ROLLBACK_DIR/active-units.txt"
    fi
}

stop_managed_units() {
    local failed=0
    local suffix unit
    for suffix in timer service; do
        for unit in "${MANAGED_UNITS[@]}"; do
            [[ "$unit" == *".$suffix" ]] || continue
            systemctl stop "$unit" || failed=1
        done
    done
    return "$failed"
}

start_previous_units() {
    local failed=0
    local suffix unit
    systemctl daemon-reload || return 1
    for suffix in service timer; do
        for unit in "${ACTIVE_UNITS[@]}"; do
            [[ "$unit" == *".$suffix" ]] || continue
            systemctl start "$unit" || failed=1
        done
    done
    return "$failed"
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
    ((STATE_MUTATION_STARTED)) || return 0
    ((STATE_SNAPSHOT_READY)) || return 1
    local archived_state="$ROLLBACK_DIR/state-after-failed-upgrade"
    local failed_state="${STATE_DIR}.failed-upgrade-${STAMP}-${UPDATER_BASHPID}"
    if ((STATE_EXISTED)) && [[ ! -d "$STATE_ROLLBACK_DIR" ]]; then
        printf 'same-filesystem state rollback copy is missing: %s\n' \
            "$STATE_ROLLBACK_DIR" >&2
        return 1
    fi
    if [[ -e "$STATE_DIR" || -L "$STATE_DIR" ]]; then
        mv "$STATE_DIR" "$failed_state" || return 1
    fi
    if ((STATE_EXISTED)); then
        if ! mv "$STATE_ROLLBACK_DIR" "$STATE_DIR"; then
            [[ ! -e "$STATE_DIR" && -e "$failed_state" ]] \
                && mv "$failed_state" "$STATE_DIR"
            return 1
        fi
    fi
    if [[ -e "$failed_state" ]] && ! mv "$failed_state" "$archived_state"; then
        printf 'failed state retained at %s\n' "$failed_state" >&2
    fi
    return 0
}

restore_installation() {
    ((CUTOVER_STARTED)) || return 0
    if [[ "$PREVIOUS_KIND" == "symlink" ]]; then
        local link_tmp="${INSTALL_DIR}.rollback-${BASHPID}"
        ln -s "$PREVIOUS_TARGET" "$link_tmp" || return 1
        mv -Tf "$link_tmp" "$INSTALL_DIR" || return 1
    elif [[ "$PREVIOUS_KIND" == "directory" ]]; then
        [[ -e "$PREVIOUS_DIR" ]] || return 0
        if [[ -L "$INSTALL_DIR" ]]; then
            rm -f -- "$INSTALL_DIR" || return 1
        elif [[ -e "$INSTALL_DIR" ]]; then
            mv "$INSTALL_DIR" \
                "$RELEASES_DIR/failed-install-${TARGET_SHA}-${STAMP}-${UPDATER_BASHPID}" \
                || return 1
        fi
        mv "$PREVIOUS_DIR" "$INSTALL_DIR" || return 1
    fi
}

restore_wrapper() {
    ((WRAPPER_MUTATION_STARTED)) || return 0
    ((WRAPPER_SNAPSHOT_READY)) || return 1
    if [[ -e "$WRAPPER" || -L "$WRAPPER" ]]; then
        mv "$WRAPPER" "$ROLLBACK_DIR/wrapper-after-failed-upgrade" || return 1
    fi
    if ((WRAPPER_EXISTED)); then
        cp -a "$ROLLBACK_DIR/wrapper-before-upgrade" "$WRAPPER" || return 1
    fi
}

cleanup_transient_paths() {
    if [[ -n "$CUTOVER_LINK" && "$CUTOVER_LINK" == "${INSTALL_DIR}.next-"* ]]; then
        rm -f -- "$CUTOVER_LINK" || true
    fi
    if [[ -n "$WRAPPER_TMP" && "$WRAPPER_TMP" == "$(dirname "$WRAPPER")/.hydra-wrapper."* ]]; then
        rm -f -- "$WRAPPER_TMP" || true
    fi
    if (( ! STATE_MUTATION_STARTED )) \
        && [[ -n "$STATE_ROLLBACK_DIR" ]] \
        && [[ "$STATE_ROLLBACK_DIR" == "${STATE_DIR}.upgrade-rollback-"* ]] \
        && [[ -d "$STATE_ROLLBACK_DIR" ]]; then
        rm -rf -- "$STATE_ROLLBACK_DIR" || {
            printf 'stale rollback copy retained at %s\n' \
                "$STATE_ROLLBACK_DIR" >&2
        }
    fi
    return 0
}

rollback() {
    local code=$1
    local line=$2
    local critical_restore_ok=1
    local stop_ok=1
    trap - ERR
    trap '' HUP INT TERM
    set +e
    printf '\nUpgrade failed at line %s (exit %s); rolling back.\n' "$line" "$code" >&2
    if ((SERVICES_QUIESCED)); then
        stop_managed_units || stop_ok=0
    fi
    if ((stop_ok)); then
        restore_state_snapshot || critical_restore_ok=0
        restore_installation || critical_restore_ok=0
        restore_wrapper || {
            printf 'command wrapper restoration failed\n' >&2
        }
    elif ((STATE_MUTATION_STARTED || CUTOVER_STARTED)); then
        critical_restore_ok=0
        printf 'services could not be quiesced; state/code restore was skipped\n' >&2
    fi
    cleanup_transient_paths
    if ((SERVICES_QUIESCED && critical_restore_ok)); then
        start_previous_units || critical_restore_ok=0
        ((critical_restore_ok)) && wait_for_previous_units \
            || critical_restore_ok=0
    fi
    if ((!critical_restore_ok)); then
        printf 'automatic rollback was incomplete; inspect HYDRA units before restarting\n' >&2
    fi
    if [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" && -n "$ROLLBACK_DIR" ]]; then
        mv "$STAGE_DIR" "$ROLLBACK_DIR/failed-staged-release"
    fi
    printf 'Rollback artifacts: %s\n' "${ROLLBACK_DIR:-not created}" >&2
    exit "$code"
}

handle_error() {
    local code=$1
    local line=$2
    if [[ "$BASHPID" != "$UPDATER_BASHPID" ]]; then
        trap - ERR
        return "$code"
    fi
    rollback "$code" "$line"
}

handle_signal() {
    local code=$1
    local line=$2
    if [[ "$BASHPID" != "$UPDATER_BASHPID" ]]; then
        trap - ERR HUP INT TERM
        exit "$code"
    fi
    rollback "$code" "$line"
}

trap 'handle_error $? $LINENO' ERR
trap 'handle_signal 129 $LINENO' HUP
trap 'handle_signal 130 $LINENO' INT
trap 'handle_signal 143 $LINENO' TERM

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

ROLLBACK_DIR="$BACKUP_ROOT/${STAMP}-${UPDATER_BASHPID}-${CURRENT_SHA:0:12}-to-${TARGET_SHA:0:12}"
mkdir "$ROLLBACK_DIR"
chmod 0700 "$ROLLBACK_DIR"
STAGE_DIR="$RELEASES_DIR/.staging-${TARGET_SHA}-${STAMP}-${BASHPID}"
RELEASE_DIR="$RELEASES_DIR/${TARGET_SHA}-${STAMP}-${UPDATER_BASHPID}"

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
run_stage_python -m compileall -q \
    "$STAGE_DIR/main.py" "$STAGE_DIR/hydra"
run_stage_python \
    -c 'from hydra import __version__; print(__version__)' \
    > "$ROLLBACK_DIR/target-version.txt"

info "Running read-only target preflight against the live state"
run_stage_python -m hydra.cli upgrade check \
    > "$ROLLBACK_DIR/preflight-upgrade.json"
run_stage_python -m hydra.cli validate \
    > "$ROLLBACK_DIR/preflight-validate.json"
run_stage_python -m hydra.cli plan \
    > "$ROLLBACK_DIR/preflight-plan.json"
run_stage_python - "$ROLLBACK_DIR" <<'PY'
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

discover_units
capture_active_units
info "Quiescing ${#ACTIVE_UNITS[@]} active HYDRA unit(s)"
SERVICES_QUIESCED=1
stop_managed_units

if [[ -d "$STATE_DIR" ]]; then
    [[ ! -e "$STATE_ROLLBACK_DIR" ]] || {
        fail "temporary state rollback path already exists: $STATE_ROLLBACK_DIR"
    }
    cp -a "$STATE_DIR" "$STATE_ROLLBACK_DIR"
    STATE_EXISTED=1
    STATE_SNAPSHOT_READY=1
    cp -a "$STATE_ROLLBACK_DIR" "$ROLLBACK_DIR/state-before-upgrade"
else
    STATE_SNAPSHOT_READY=1
fi

if [[ -e "$WRAPPER" || -L "$WRAPPER" ]]; then
    cp -a "$WRAPPER" "$ROLLBACK_DIR/wrapper-before-upgrade"
    WRAPPER_EXISTED=1
fi
WRAPPER_SNAPSHOT_READY=1

info "Creating and verifying an application-level backup"
run_stage_python \
    -m hydra.cli backup \
    --output "$ROLLBACK_DIR/hydra-backup.tar.gz" \
    > "$ROLLBACK_DIR/backup.json"
run_stage_python \
    -m hydra.cli restore "$ROLLBACK_DIR/hydra-backup.tar.gz" --dry-run \
    > "$ROLLBACK_DIR/backup-verification.json"

info "Persisting the target state schema while writers are stopped"
STATE_MUTATION_STARTED=1
run_stage_python \
    -m hydra.cli upgrade migrate-state \
    > "$ROLLBACK_DIR/state-migration.json"
run_stage_python \
    -m hydra.cli validate \
    > "$ROLLBACK_DIR/state-validation.json"

mv "$STAGE_DIR" "$RELEASE_DIR"
STAGE_DIR=""

info "Switching /opt entrypoint to the staged release"
if [[ -L "$INSTALL_DIR" ]]; then
    PREVIOUS_KIND="symlink"
    PREVIOUS_TARGET=$(readlink "$INSTALL_DIR")
    CUTOVER_LINK="${INSTALL_DIR}.next-${UPDATER_BASHPID}"
    ln -s "$RELEASE_DIR" "$CUTOVER_LINK"
    CUTOVER_STARTED=1
    mv -Tf "$CUTOVER_LINK" "$INSTALL_DIR"
    CUTOVER_LINK=""
else
    PREVIOUS_KIND="directory"
    PREVIOUS_DIR="$RELEASES_DIR/previous-${CURRENT_SHA}-${STAMP}"
    CUTOVER_STARTED=1
    mv "$INSTALL_DIR" "$PREVIOUS_DIR"
    ln -s "$RELEASE_DIR" "$INSTALL_DIR"
fi

WRAPPER_TMP=$(mktemp "$(dirname "$WRAPPER")/.hydra-wrapper.XXXXXX")
printf '#!/usr/bin/env bash\nexec "%s/.venv/bin/python" "%s/main.py" "$@"\n' \
    "$INSTALL_DIR" "$INSTALL_DIR" > "$WRAPPER_TMP"
chmod 0755 "$WRAPPER_TMP"
WRAPPER_MUTATION_STARTED=1
mv -f "$WRAPPER_TMP" "$WRAPPER"
WRAPPER_TMP=""

start_previous_units

info "Running post-cutover validation"
run_install_python \
    -m hydra.cli validate > "$ROLLBACK_DIR/post-validate.json"
run_install_python \
    -m hydra.cli plan > "$ROLLBACK_DIR/post-plan.json"
run_install_python \
    -m hydra.cli status > "$ROLLBACK_DIR/post-status.json"
run_install_python \
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
STATE_MUTATION_STARTED=0
WRAPPER_MUTATION_STARTED=0
cleanup_transient_paths
trap - ERR HUP INT TERM

ok "HYDRA upgraded ${CURRENT_SHA:0:12} -> ${TARGET_SHA:0:12} from $HYDRA_REF"
ok "Rollback snapshot retained at $ROLLBACK_DIR"
