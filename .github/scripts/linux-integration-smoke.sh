#!/usr/bin/env bash
set -Eeuo pipefail

[[ $(id -u) -eq 0 ]] || { echo "integration smoke requires root" >&2; exit 1; }

tmp_dir=$(mktemp -d /tmp/hydra-integration.XXXXXX)
unit=/etc/systemd/system/hydra-ci-smoke.service
cleanup() {
    systemctl stop hydra-ci-smoke.service >/dev/null 2>&1 || true
    rm -f "$unit"
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf "$tmp_dir"
    rm -f \
        /var/lib/hydra/state.json \
        /var/lib/hydra/state.json.bak \
        /var/lib/hydra/state.json.corrupt \
        /var/lib/hydra/state.lock
    rmdir /var/lib/hydra >/dev/null 2>&1 || true
}
trap cleanup EXIT

install -d -m 0700 /var/lib/hydra
install -m 0600 tests/fixtures/state-2.5.3.json /var/lib/hydra/state.json

cat > "$unit" <<'EOF'
[Unit]
Description=HYDRA CI systemd smoke

[Service]
Type=simple
ExecStart=/bin/sleep infinity
EOF
systemctl daemon-reload
systemctl start hydra-ci-smoke.service
systemctl is-active --quiet hydra-ci-smoke.service

cat > "$tmp_dir/nftables.conf" <<'EOF'
table inet hydra_ci_smoke {
    chain input {
        type filter hook input priority filter; policy accept;
    }
}
EOF
nft --check --file "$tmp_dir/nftables.conf"

export HYDRA_BACKUP_DIR="$tmp_dir/backups"
python -m hydra.cli validate
python -m hydra.cli doctor
python -m hydra.cli upgrade check
python -m hydra.cli upgrade migrate-state
test "$(python -c 'import json; print(json.load(open("/var/lib/hydra/state.json"))["version"])')" = "4"
python -m hydra.cli backup > "$tmp_dir/backup.json"
archive=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["archive"])' "$tmp_dir/backup.json")
python -m hydra.cli restore "$archive" --dry-run

test -s "$archive"
test "$(stat -c '%a' "$archive")" = "600"
