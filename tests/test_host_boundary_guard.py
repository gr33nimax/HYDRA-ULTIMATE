from pathlib import Path


def test_production_code_keeps_subprocess_calls_inside_host_boundary():
    root = Path(__file__).parents[1] / "hydra"
    violations: list[str] = []
    for path in root.rglob("*.py"):
        if path.as_posix().endswith("hydra/utils/commands.py"):
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        if any("# audit: allow-generated-runtime-subprocess" in line for line in lines):
            continue
        for line_no, line in enumerate(lines, 1):
            if "subprocess.run(" in line or "subprocess.Popen(" in line:
                violations.append(f"{path}:{line_no}")
    assert violations == [], "direct subprocess calls bypass HostBackend: " + ", ".join(violations)
