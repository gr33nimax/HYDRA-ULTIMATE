#!/usr/bin/env bash
set -Eeuo pipefail

[[ $(id -u) -eq 0 ]] || {
    echo "upgrade smoke requires root" >&2
    exit 1
}

report_error() {
    local status=$1
    local line=$2
    local command=$3
    printf 'upgrade smoke failed at line %s (exit %s): %s\n' \
        "$line" "$status" "$command" >&2
    exit "$status"
}
trap 'report_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

workspace="${GITHUB_WORKSPACE:-$PWD}"
git_workspace() {
    git -c safe.directory="$workspace" -C "$workspace" "$@"
}
install_dir=/opt/hydra
unit=/etc/systemd/system/hydra-ci-upgrade.service
calls_unit=/etc/systemd/system/hydra-headless-creator-vk-calls@.service
calls_instance=hydra-headless-creator-vk-calls@a-1.service
wrapper=/usr/local/bin/hydra
tmp_dir=$(mktemp -d /tmp/hydra-upgrade-integration.XXXXXX)
remote="$tmp_dir/remote.git"
sentinel="$tmp_dir/upgrade-sentinel.sh"
fail_next_start="$tmp_dir/fail-next-service-start"
wrapper_backup="$tmp_dir/original-hydra-wrapper"
wrapper_fixture="$tmp_dir/fixture-hydra-wrapper"
wrapper_existed=0

[[ ! -e "$install_dir" && ! -L "$install_dir" ]] || {
    echo "$install_dir already exists on the integration runner" >&2
    exit 1
}
[[ ! -e /var/lib/hydra ]] || {
    echo "/var/lib/hydra already exists on the integration runner" >&2
    exit 1
}

cleanup() {
    systemctl stop hydra-ci-upgrade.service >/dev/null 2>&1 || true
    systemctl stop "$calls_instance" >/dev/null 2>&1 || true
    rm -f "$unit" "$calls_unit"
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ -L "$install_dir" ]]; then
        rm -f "$install_dir"
    elif [[ -d "$install_dir" ]]; then
        mv "$install_dir" "$tmp_dir/install-left-after-test" >/dev/null 2>&1 || true
    fi
    rm -f \
        /var/lib/hydra/state.json \
        /var/lib/hydra/state.json.bak \
        /var/lib/hydra/state.json.corrupt \
        /var/lib/hydra/state.lock
    rmdir /var/lib/hydra >/dev/null 2>&1 || true
    if ((wrapper_existed)); then
        rm -f "$wrapper"
        cp -a "$wrapper_backup" "$wrapper"
    else
        rm -f "$wrapper"
    fi
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

if [[ -e "$wrapper" || -L "$wrapper" ]]; then
    cp -a "$wrapper" "$wrapper_backup"
    wrapper_existed=1
fi
printf '#!/usr/bin/env bash\nexit 77\n' > "$wrapper_fixture"
chmod 0755 "$wrapper_fixture"
cp -a "$wrapper_fixture" "$wrapper"

if [[ "$(git_workspace rev-parse --is-shallow-repository)" == "true" ]]; then
    git_workspace fetch --quiet --unshallow origin
fi
git_workspace fetch --quiet --no-tags origin \
    +refs/heads/main:refs/remotes/origin/main
target_sha=$(git_workspace rev-parse HEAD)
main_sha=$(git_workspace rev-parse refs/remotes/origin/main)
git init --bare --quiet "$remote"
git_workspace push --quiet "$remote" \
    "$main_sha":refs/heads/main \
    "$target_sha":refs/heads/dev

git clone --quiet --branch main "$remote" "$install_dir"
python3 -m venv "$install_dir/.venv"
"$install_dir/.venv/bin/python" -m pip install \
    --disable-pip-version-check --quiet \
    -r "$install_dir/requirements.lock"

install -d -m 0700 /var/lib/hydra
install -m 0600 \
    "$workspace/tests/fixtures/state-2.5.3.json" \
    /var/lib/hydra/state.json
python3 - <<'PY'
import json
from pathlib import Path

path = Path("/var/lib/hydra/state.json")
state = json.loads(path.read_text())
state["protocols"]["warp"]["enabled"] = False
state["protocols"]["custom-transport"]["enabled"] = False
state["network"]["warp_enabled"] = False
state["network"]["dnscrypt_enabled"] = False
for key in state["security"]:
    state["security"][key] = False
path.write_text(json.dumps(state, indent=2) + "\n")
PY

cat > "$sentinel" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ -e "$fail_next_start" ]]; then
    rm -f "$fail_next_start"
    exit 1
fi
exit 0
EOF
chmod 0755 "$sentinel"

cat > "$unit" <<EOF
[Unit]
Description=HYDRA upgrade transaction integration sentinel

[Service]
Type=simple
ExecStartPre=$sentinel
ExecStart=/bin/sleep infinity
EOF
cat > "$calls_unit" <<'EOF'
[Unit]
Description=HYDRA Calls template upgrade sentinel %i

[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
systemctl daemon-reload
systemctl start hydra-ci-upgrade.service
systemctl start "$calls_instance"
systemctl is-active --quiet hydra-ci-upgrade.service
systemctl is-active --quiet "$calls_instance"

neutral_cwd="$tmp_dir/neutral-cwd"
mkdir "$neutral_cwd"
target_version=$(
    cd "$neutral_cwd"
    PYTHONPATH="$workspace" python3 -c \
        'from hydra import __version__; print(__version__)'
)
run_updater() {
    (
        cd "$neutral_cwd"
        HYDRA_REPO_URL="$remote" \
        HYDRA_REF=dev \
        HYDRA_INSTALL_DIR="$install_dir" \
        HYDRA_RELEASES_DIR="$tmp_dir/releases" \
        HYDRA_UPGRADE_BACKUP_DIR="$tmp_dir/backups" \
        HYDRA_UPGRADE_LOCK_FILE="$tmp_dir/upgrade.lock" \
            bash "$workspace/upgrade.sh"
    )
}

touch "$fail_next_start"
if run_updater; then
    echo "fault-injected upgrade unexpectedly succeeded" >&2
    exit 1
fi

[[ -d "$install_dir" && ! -L "$install_dir" ]]
[[ "$(git -C "$install_dir" rev-parse HEAD)" == "$main_sha" ]]
cmp -s "$wrapper" "$wrapper_fixture"
systemctl is-active --quiet hydra-ci-upgrade.service
systemctl is-active --quiet "$calls_instance"
PYTHONPATH="$install_dir" "$install_dir/.venv/bin/python" - <<'PY'
import json
from pathlib import Path

state = json.loads(Path("/var/lib/hydra/state.json").read_text())
assert state["version"] == 3
assert state["users"][0]["credentials"]["naive"]["password"] == "preserve-me"
assert state["telegram"]["admin_token"] == "preserve-admin-token"
PY
test "$(find "$tmp_dir/backups" -name SUCCESS -type f | wc -l)" = "0"
test "$(find /var/lib -maxdepth 1 -name 'hydra.upgrade-rollback-*' | wc -l)" = "0"

run_updater

[[ -L "$install_dir" ]]
[[ "$(git -C "$install_dir" rev-parse HEAD)" == "$target_sha" ]]
! cmp -s "$wrapper" "$wrapper_fixture"
installed_version=$(
    cd "$neutral_cwd"
    PYTHONPATH="$install_dir" "$install_dir/.venv/bin/python" -c \
        'from hydra import __version__; print(__version__)'
)
[[ "$installed_version" == "$target_version" ]]
systemctl is-active --quiet hydra-ci-upgrade.service
systemctl is-active --quiet "$calls_instance"

PYTHONPATH="$install_dir" "$install_dir/.venv/bin/python" - <<'PY'
import json
from pathlib import Path

from hydra.core.state_models import SCHEMA_VERSION

state = json.loads(Path("/var/lib/hydra/state.json").read_text())
assert state["version"] == SCHEMA_VERSION
assert state["users"][0]["device_limit"] == 2
assert state["users"][0]["credentials"]["naive"]["password"] == "preserve-me"
assert state["telegram"]["admin_token"] == "preserve-admin-token"
assert state["network"]["clash_api_secret"] == "preserve-clash-secret"
assert state["protocols"]["warp"]["enabled"] is False
assert "fail2ban" not in state["protocols"]
PY

test "$(find "$tmp_dir/backups" -name SUCCESS -type f | wc -l)" = "1"
test "$(find "$tmp_dir/backups" -name hydra-backup.tar.gz -type f | wc -l)" = "2"
test "$(find "$tmp_dir/backups" -name state-after-failed-upgrade -type d | wc -l)" = "1"
