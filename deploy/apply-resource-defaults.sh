#!/usr/bin/env bash
# Install idempotent host resource defaults owned by HYDRA.

set -Eeuo pipefail

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
JOURNAL_SOURCE="$SOURCE_DIR/90-hydra-journald.conf"
SINGBOX_SOURCE="$SOURCE_DIR/90-hydra-singbox-memory.conf"
JOURNAL_TARGET=/etc/systemd/journald.conf.d/90-hydra-journald.conf
SINGBOX_TARGET=/etc/systemd/system/sing-box.service.d/90-hydra-memory.conf

install_if_changed() {
    local source=$1
    local target=$2
    local target_dir pending

    target_dir=$(dirname -- "$target")
    install -d -m 0755 "$target_dir"
    if [[ -f "$target" ]] && cmp -s -- "$source" "$target"; then
        return 1
    fi
    pending="${target}.hydra-${BASHPID}.pending"
    if ! install -m 0644 "$source" "$pending"; then
        rm -f -- "$pending"
        return 2
    fi
    if ! mv -f -- "$pending" "$target"; then
        rm -f -- "$pending"
        return 2
    fi
    return 0
}

journal_changed=0
singbox_changed=0
if install_if_changed "$JOURNAL_SOURCE" "$JOURNAL_TARGET"; then
    journal_changed=1
fi
if install_if_changed "$SINGBOX_SOURCE" "$SINGBOX_TARGET"; then
    singbox_changed=1
fi

if ((singbox_changed)); then
    systemctl daemon-reload
    if systemctl is-active --quiet sing-box.service; then
        systemctl try-restart sing-box.service
    fi
fi

if ((journal_changed)); then
    systemctl restart systemd-journald.service
fi

# Rotation makes the size bound effective for journals created before HYDRA
# installed this policy. Only archives outside the 128 MiB budget are removed.
journalctl --rotate --vacuum-size=128M
