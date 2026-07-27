from pathlib import Path


README = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")


def test_development_readme_targets_dev_channel():
    assert "badge.svg?branch=dev" in README
    assert "текущая версия ветки `dev`" in README
    assert (
        "HYDRA-ULTIMATE/dev/bootstrap.sh | "
        "sudo env HYDRA_REF=dev bash"
    ) in README
    assert (
        "HYDRA-ULTIMATE/dev/updater.sh | "
        "sudo env HYDRA_REF=dev bash"
    ) in README


def test_development_readme_has_no_release_branch_install_links():
    assert "badge.svg?branch=main" not in README
    assert "HYDRA-ULTIMATE/main/bootstrap.sh" not in README
    assert "HYDRA-ULTIMATE/main/updater.sh" not in README
