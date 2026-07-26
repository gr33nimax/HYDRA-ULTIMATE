from pathlib import Path
from unittest.mock import patch

from hydra.core import install_layout


def test_project_root_prefers_explicit_install_dir(tmp_path):
    configured = tmp_path / "managed"
    with patch.dict(
        install_layout.os.environ,
        {install_layout.INSTALL_ROOT_ENV: str(configured)},
    ):
        assert install_layout.project_root(tmp_path / "fallback") == configured


def test_project_root_uses_repository_fallback_without_managed_install(
    tmp_path,
):
    fallback = tmp_path / "checkout"
    with patch.dict(install_layout.os.environ, {}, clear=True), patch.object(
        install_layout,
        "DEFAULT_INSTALL_ROOT",
        tmp_path / "missing",
    ):
        assert install_layout.project_root(fallback) == fallback


def test_python_executable_uses_stable_managed_virtualenv(tmp_path):
    root = tmp_path / "hydra"
    interpreter = root / ".venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.touch()

    with patch.dict(
        install_layout.os.environ,
        {install_layout.INSTALL_ROOT_ENV: str(root)},
    ):
        assert install_layout.python_executable() == interpreter


def test_python_executable_falls_back_to_running_interpreter(tmp_path):
    with patch.dict(install_layout.os.environ, {}, clear=True), patch.object(
        install_layout,
        "DEFAULT_INSTALL_ROOT",
        tmp_path / "missing",
    ):
        assert install_layout.python_executable(tmp_path) == Path(
            install_layout.sys.executable,
        )
