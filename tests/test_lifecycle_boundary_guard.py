from pathlib import Path


def test_managers_delegate_plugin_lifecycle_to_orchestrator():
    root = Path(__file__).parents[1] / "hydra" / "plugins"
    violations: list[str] = []
    for path in root.rglob("manager.py"):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(token in line for token in (
                "plugin.install(", "plugin.uninstall(",
                "plugin.on_enable(", "plugin.on_disable(",
            )):
                violations.append(f"{path}:{line_no}")
    assert violations == [], "manager bypasses orchestrator lifecycle: " + ", ".join(violations)
