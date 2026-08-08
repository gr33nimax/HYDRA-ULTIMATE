"""Regression checks for the public one-command installer."""
from pathlib import Path


ROOT = Path(__file__).parent.parent
BOOTSTRAP = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
INSTALL_GUIDE = (ROOT / "docs" / "UPGRADE.md").read_text(encoding="utf-8")
DOCS_INDEX = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_main_bootstrap_download_and_install_default_to_main():
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


def test_development_readme_one_command_installs_dev():
    assert (
        "curl -fsSL https://raw.githubusercontent.com/gr33nimax/"
        "HYDRA-ULTIMATE/dev/bootstrap.sh | sudo env HYDRA_REF=dev bash"
    ) in README
    assert "HYDRA-ULTIMATE/main/bootstrap.sh" not in README
    assert "sudo python3 main.py" not in README


def test_readme_overview_table_has_no_empty_header_row():
    assert "| | |" not in README
    assert '<tr><th scope="row">Транспорты</th><td>12</td></tr>' in README


def test_public_docs_do_not_reference_retired_branch():
    retired_branch = "legacy" + "-main"
    assert all(
        retired_branch not in document
        for document in (README, INSTALL_GUIDE, DOCS_INDEX, CHANGELOG)
    )


def test_installer_has_numbered_progress_and_unambiguous_result():
    assert 'title "УСТАНОВКА HYDRA"' in BOOTSTRAP
    assert 'step 1 5 "Проверка системы"' in BOOTSTRAP
    assert 'step 5 5 "Завершение"' in BOOTSTRAP
    assert 'result_ok "HYDRA v${HYDRA_VERSION} установлена"' in BOOTSTRAP
    assert 'result_error "Установка не завершена (' in BOOTSTRAP
    assert "SING-BOX MULTI-PROXY MANAGER v1.0" not in BOOTSTRAP


def test_fresh_install_includes_certbot_before_tls_protocol_activation():
    package_line = next(
        line for line in BOOTSTRAP.splitlines()
        if line.startswith("$PKG_INSTALL iptables")
    )

    assert "certbot" in package_line.split()


def test_install_guide_runs_sources_through_the_isolated_environment():
    assert "git clone -b main" in INSTALL_GUIDE
    assert "git clone -b dev" not in INSTALL_GUIDE
    assert ".venv/bin/python -m pip install -r requirements.lock" in INSTALL_GUIDE
    assert "sudo python3 main.py" not in INSTALL_GUIDE
