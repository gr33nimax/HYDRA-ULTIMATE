from pathlib import Path


README = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")


def test_main_readme_targets_main_channel():
    assert "badge.svg?branch=main" in README
    assert "текущая версия ветки `main`" in README
    assert (
        "HYDRA-ULTIMATE/main/bootstrap.sh | "
        "sudo bash"
    ) in README
    assert (
        "HYDRA-ULTIMATE/main/updater.sh | "
        "sudo bash"
    ) in README


def test_main_readme_has_no_development_branch_install_links():
    assert "badge.svg?branch=dev" not in README
    assert "HYDRA-ULTIMATE/dev/bootstrap.sh" not in README
    assert "HYDRA-ULTIMATE/dev/updater.sh" not in README
    assert "sudo env HYDRA_REF=dev bash" not in README
