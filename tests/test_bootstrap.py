"""Regression checks for the public one-command installer."""
from pathlib import Path


ROOT = Path(__file__).parent.parent
BOOTSTRAP = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_bootstrap_download_and_install_default_to_main():
    assert "HYDRA-ULTIMATE/main/bootstrap.sh" in BOOTSTRAP
    assert 'DEFAULT_BRANCH="main"' in BOOTSTRAP
    assert 'HYDRA_REF="${HYDRA_REF:-$DEFAULT_BRANCH}"' in BOOTSTRAP
    assert 'DEFAULT_BRANCH="dev"' not in BOOTSTRAP


def test_every_fresh_install_path_uses_selected_ref():
    assert 'git clone --quiet --depth 1 --branch "$HYDRA_REF"' in BOOTSTRAP
    assert 'HYDRA_REMOTE_REF="refs/heads/${HYDRA_REF}"' in BOOTSTRAP
    assert 'git ls-remote --exit-code "$REPO_URL" "$HYDRA_REMOTE_REF"' in BOOTSTRAP
    assert BOOTSTRAP.count('ARCHIVE="${REPO_URL}/archive/${HYDRA_TARGET_REV}.tar.gz"') == 2
    assert BOOTSTRAP.count("--strip-components=1") == 2


def test_bootstrap_verifies_exact_remote_commit_before_dependencies():
    assert 'git fetch --quiet "$REPO_URL" "$HYDRA_TARGET_REV"' in BOOTSTRAP
    assert 'git checkout --quiet -B "$HYDRA_REF" "$HYDRA_TARGET_REV"' in BOOTSTRAP
    assert 'git symbolic-ref --quiet --short HEAD' in BOOTSTRAP
    assert BOOTSTRAP.count('.hydra-source-revision') >= 3
    assert 'if [[ "$HYDRA_INSTALLED_REV" != "$HYDRA_TARGET_REV" ]]' in BOOTSTRAP
    assert BOOTSTRAP.index('if [[ "$HYDRA_INSTALLED_REV" != "$HYDRA_TARGET_REV" ]]') < BOOTSTRAP.index(
        'info "Изолированное Python-окружение..."'
    )


def test_readme_one_command_installs_main():
    assert (
        "curl -fsSL https://raw.githubusercontent.com/gr33nimax/"
        "HYDRA-ULTIMATE/main/bootstrap.sh | sudo bash"
    ) in README
    assert "git clone -b main" in README
    assert ".venv/bin/python -m pip install -r requirements.lock" in README
    assert "sudo python3 main.py" not in README
