"""The clean node installation must not create a base-server setup."""

from pathlib import Path


ROOT = Path(__file__).parent.parent
BOOTSTRAP = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
NODE_UNIT = ROOT / "deploy" / "hydra-node-control.service"


def test_bootstrap_defaults_to_main_and_rejects_unknown_roles():
    assert 'HYDRA_ROLE="${HYDRA_ROLE:-main}"' in BOOTSTRAP
    assert 'HYDRA_ROLE" != "main" && "$HYDRA_ROLE" != "node"' in BOOTSTRAP


def test_node_bootstrap_refuses_to_convert_an_existing_installation():
    assert 'HYDRA_ROLE" == "node"' in BOOTSTRAP
    assert "/var/lib/hydra/state.json" in BOOTSTRAP
    assert "( -f /var/lib/hydra/state.json || -f /opt/hydra/main.py )" in BOOTSTRAP


def test_node_bootstrap_accepts_only_a_full_pinned_commit_from_the_manager():
    assert 'if [[ -n "${HYDRA_TARGET_REV:-}" ]]; then' in BOOTSTRAP
    assert "HYDRA_TARGET_REV должен быть полным SHA-1 коммита" in BOOTSTRAP
    assert 'git fetch --quiet "$REPO_URL" "$HYDRA_TARGET_REV"' in BOOTSTRAP


def test_node_bootstrap_skips_default_user_and_installs_only_disabled_agent_unit():
    assert 'HYDRA_ROLE" == "main"' in BOOTSTRAP[BOOTSTRAP.index('if [[ "$HYDRA_FRESH_INSTALL"') :]
    assert "hydra-node-control.service" in BOOTSTRAP
    assert "daemon-reload" in BOOTSTRAP
    assert "ожидает удостоверение" in BOOTSTRAP
    assert NODE_UNIT.exists()
    unit = NODE_UNIT.read_text(encoding="utf-8")
    assert "hydra.entrypoints.node_control" in unit
    assert "After=network-online.target nftables.service firewalld.service ufw.service" in unit
    assert "WantedBy=multi-user.target" in unit
    assert "systemctl enable hydra-node-control.service" not in BOOTSTRAP
