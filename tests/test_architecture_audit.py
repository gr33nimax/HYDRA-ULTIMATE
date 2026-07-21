from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_transport_layers_do_not_reintroduce_global_application_services():
    files = [ROOT / "hydra" / "cli.py", ROOT / "hydra" / "ui" / "menus.py"]
    forbidden = ("APP = production_application()", "_user_service =", "_protocol_service =")
    violations = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        for marker in forbidden:
            if marker in source:
                violations.append(f"{path.relative_to(ROOT)}: {marker}")
    assert violations == [], "global application services returned: " + ", ".join(violations)


def test_version_is_consistent_across_runtime_and_entrypoint():
    from hydra import __version__

    entrypoint = (ROOT / "main.py").read_text(encoding="utf-8")
    assert __version__ == "2.5.2"
    assert f"HYDRA v{__version__}" in entrypoint


def test_operational_documentation_is_kept_with_the_repository():
    cli = ROOT / "docs" / "CLI.md"
    text = cli.read_text(encoding="utf-8")
    assert "hydra apply" in text
    assert "tls_mux" in text
