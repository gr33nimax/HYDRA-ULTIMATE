#!/usr/bin/env bash
set -Eeuo pipefail

[[ $(id -u) -eq 0 ]] || {
    echo "upgrade smoke requires root" >&2
    exit 1
}

workspace="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
install_dir=/opt/hydra
unit=/etc/systemd/system/hydra-ci-upgrade.service
wrapper=/usr/local/bin/hydra
tmp_dir=$(mktemp -d /tmp/hydra-upgrade-integration.XXXXXX)
remote="$tmp_dir/remote.git"
wrapper_backup="$tmp_dir/original-hydra-wrapper"
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
    rm -f "$unit"
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

git config --global --add safe.directory "$workspace"
git -C "$workspace" rev-parse --verify origin/main >/dev/null
git init --bare --quiet "$remote"
git -C "$workspace" push --quiet "$remote" \
    origin/main:refs/heads/main \
    HEAD:refs/heads/dev

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

cat > "$unit" <<'EOF'
[Unit]
Description=HYDRA upgrade transaction integration sentinel

[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
systemctl daemon-reload
systemctl start hydra-ci-upgrade.service
systemctl is-active --quiet hydra-ci-upgrade.service

target_sha=$(git -C "$workspace" rev-parse HEAD)
HYDRA_REPO_URL="$remote" \
HYDRA_REF=dev \
HYDRA_INSTALL_DIR="$install_dir" \
HYDRA_RELEASES_DIR="$tmp_dir/releases" \
HYDRA_UPGRADE_BACKUP_DIR="$tmp_dir/backups" \
HYDRA_UPGRADE_LOCK_FILE="$tmp_dir/upgrade.lock" \
    bash "$workspace/upgrade.sh"

[[ -L "$install_dir" ]]
[[ "$(git -C "$install_dir" rev-parse HEAD)" == "$target_sha" ]]
[[ "$("$install_dir/.venv/bin/python" -c \
    'from hydra import __version__; print(__version__)')" == "2.5.4" ]]
systemctl is-active --quiet hydra-ci-upgrade.service

"$install_dir/.venv/bin/python" - <<'PY'
import json
from pathlib import Path

state = json.loads(Path("/var/lib/hydra/state.json").read_text())
assert state["version"] == 4
assert state["users"][0]["device_limit"] == 2
assert state["users"][0]["credentials"]["naive"]["password"] == "preserve-me"
assert state["telegram"]["admin_token"] == "preserve-admin-token"
assert state["network"]["clash_api_secret"] == "preserve-clash-secret"
assert state["protocols"]["warp"]["enabled"] is False
assert "fail2ban" not in state["protocols"]
PY

test "$(find "$tmp_dir/backups" -name SUCCESS -type f | wc -l)" = "1"
test "$(find "$tmp_dir/backups" -name hydra-backup.tar.gz -type f | wc -l)" = "1"
