"""Telemt installation uses a dedicated least-privilege service identity."""

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from hydra.plugins.telemt import installation


class _Host:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, command: list[str], **_kwargs) -> CompletedProcess[str]:
        self.commands.append(command)
        return CompletedProcess(command, 0, "", "")

    def atomic_write(self, path, content, *, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content) if isinstance(content, bytes) else path.write_text(content, encoding="utf-8")
        path.chmod(mode)

    def ensure_directory(self, path, *, mode=0o755):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)

    def remove_file(self, path):
        path.unlink(missing_ok=True)


def test_service_is_hydra_owned_and_least_privilege(tmp_path):
    host = _Host()
    service_file = tmp_path / "telemt.service"
    work_dir = tmp_path / "work"

    assert installation.write_service(
        host=host,
        work_dir=work_dir,
        service_file=service_file,
        bin_path=Path("/usr/local/bin/telemt"),
        config_file=Path("/etc/hydra/telemt/config.toml"),
        service_name="telemt",
    )

    unit = service_file.read_text(encoding="utf-8")
    assert "User=telemt" in unit
    assert "Group=telemt" in unit
    assert "CAP_NET_BIND_SERVICE" in unit
    assert "CAP_NET_ADMIN" not in unit
    assert "User=root" not in unit
    assert ["systemctl", "daemon-reload"] in host.commands


def test_service_user_is_created_as_a_non_login_user():
    host = _Host()
    host.run = lambda command, **_kwargs: CompletedProcess(command, 1 if command[0] == "getent" else 0, "", "")

    assert installation.ensure_service_user(host)


def test_failed_download_or_extract_keeps_the_previous_binary(tmp_path):
    binary = tmp_path / "telemt"
    binary.write_bytes(b"\\x7fELFold")
    archive = tmp_path / "telemt.tar.gz"

    assert not installation.download_and_extract(
        "telemt-x86_64-linux-gnu.tar.gz",
        tmp_path,
        archive,
        repo="telemt/telemt",
        bin_path=binary,
        download_asset=lambda *_args, **_kwargs: False,
    )
    assert binary.read_bytes() == b"\\x7fELFold"

    def extract_invalid(_archive, destination):
        (destination / "telemt").write_bytes(b"not an ELF")
        return destination

    assert not installation.download_and_extract(
        "telemt-x86_64-linux-gnu.tar.gz",
        tmp_path,
        archive,
        repo="telemt/telemt",
        bin_path=binary,
        download_asset=lambda *_args, **_kwargs: True,
        extract_archive=extract_invalid,
    )
    assert binary.read_bytes() == b"\\x7fELFold"


def test_failed_install_restores_binary_and_service_unit(tmp_path):
    binary = tmp_path / "telemt"
    service_file = tmp_path / "telemt.service"
    binary.write_bytes(b"old binary")
    service_file.write_bytes(b"old unit")
    host = _Host()

    def download_new(**_kwargs):
        binary.write_bytes(b"new binary")
        return True

    with (
        patch("hydra.plugins.telemt.installation.download_binary", side_effect=download_new),
        patch(
            "hydra.plugins.telemt.installation.verify_elf", side_effect=lambda path: path.read_bytes() == b"new binary"
        ),
        patch("hydra.plugins.telemt.installation.ensure_service_user", return_value=False),
    ):
        assert not installation.install(
            host=host,
            repo="telemt/telemt",
            bin_path=binary,
            work_dir=tmp_path / "work",
            service_file=service_file,
            config_file=tmp_path / "config.toml",
            service_name="telemt",
        )

    assert binary.read_bytes() == b"old binary"
    assert service_file.read_bytes() == b"old unit"


def test_failed_first_install_removes_new_partial_binary(tmp_path):
    binary = tmp_path / "telemt"
    host = _Host()

    def download_new(**_kwargs):
        binary.write_bytes(b"new binary")
        return True

    with (
        patch("hydra.plugins.telemt.installation.download_binary", side_effect=download_new),
        patch("hydra.plugins.telemt.installation.ensure_service_user", return_value=False),
    ):
        assert not installation.install(
            host=host,
            repo="telemt/telemt",
            bin_path=binary,
            work_dir=tmp_path / "work",
            service_file=tmp_path / "telemt.service",
            config_file=tmp_path / "config.toml",
            service_name="telemt",
        )

    assert not binary.exists()


def test_failed_install_reports_the_failed_stage(tmp_path):
    binary = tmp_path / "telemt"
    stages: list[str] = []

    def download_new(**_kwargs):
        binary.write_bytes(b"new binary")
        return True

    with (
        patch("hydra.plugins.telemt.installation.download_binary", side_effect=download_new),
        patch("hydra.plugins.telemt.installation.verify_elf", return_value=True),
        patch("hydra.plugins.telemt.installation.ensure_service_user", return_value=False),
    ):
        assert not installation.install(
            host=_Host(),
            repo="telemt/telemt",
            bin_path=binary,
            work_dir=tmp_path / "work",
            service_file=tmp_path / "telemt.service",
            config_file=tmp_path / "config.toml",
            service_name="telemt",
            on_failure=stages.append,
        )

    assert stages == ["не удалось создать сервисного пользователя Telemt"]


def test_failed_manual_update_restores_previous_binary(tmp_path):
    binary = tmp_path / "telemt"
    binary.write_bytes(b"old binary")
    host = _Host()

    def run(command, **_kwargs):
        host.commands.append(command)
        failed = command[:2] == ["systemctl", "restart"]
        return CompletedProcess(command, int(failed), "active\\n", "")

    host.run = run

    def install_new(**_kwargs):
        binary.write_bytes(b"new binary")
        return True

    with (
        patch("hydra.utils.downloader.latest_release", return_value="3.5.8"),
        patch("hydra.plugins.telemt.installation.download_binary", side_effect=install_new),
    ):
        assert not installation.update_binary(
            host=host,
            repo="telemt/telemt",
            bin_path=binary,
            service_name="telemt",
        )

    assert binary.read_bytes() == b"old binary"
