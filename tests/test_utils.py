"""
tests/test_utils.py — Тесты для hydra/utils (firewall, downloader, crypto, net).
"""
from __future__ import annotations

import string
import io
import tarfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from hydra.utils import crypto, net


# ══════════════════════════════════════════════════════════════════════════════
#  crypto
# ══════════════════════════════════════════════════════════════════════════════

class TestGenPassword:
    def test_gen_password_length(self):
        """Пароль имеет запрошенную длину."""
        for length in (8, 16, 32, 64):
            pw = crypto.gen_password(length)
            assert len(pw) == length, f"Ожидается длина {length}, получено {len(pw)}"

    def test_gen_password_chars(self):
        """Все символы из алфавита _PASSWORD_CHARS (без 0/O, 1/l/I)."""
        allowed = set(crypto._PASSWORD_CHARS)
        forbidden = set("0OlI1")
        for _ in range(100):
            pw = crypto.gen_password(32)
            assert set(pw).issubset(allowed), f"Недопустимые символы: {set(pw) - allowed}"
            assert not set(pw) & forbidden, f"Запрещённые символы найдены: {set(pw) & forbidden}"

    def test_gen_password_randomness(self):
        """Два подряд сгенерированных пароля с высокой вероятностью различаются."""
        assert crypto.gen_password(32) != crypto.gen_password(32)


class TestGenToken:
    def test_gen_token_length(self):
        """Токен имеет ожидаемую длину (base64-encoded nbytes)."""
        token = crypto.gen_token(24)
        # token_urlsafe(24) даёт 32 символа
        assert len(token) == 32

    def test_gen_token_urlsafe(self):
        """Токен содержит только URL-safe символы."""
        for _ in range(100):
            token = crypto.gen_token(16)
            allowed = set(string.ascii_letters + string.digits + "-_=")
            assert set(token).issubset(allowed)


class TestDeriveKey:
    def test_derive_key_deterministic(self):
        """Одинаковый purpose и seed → одинаковый ключ."""
        k1 = crypto.derive_key("test", "seed-123")
        k2 = crypto.derive_key("test", "seed-123")
        assert k1 == k2

    def test_derive_key_different_purpose(self):
        """Разный purpose → разный ключ при том же seed."""
        k1 = crypto.derive_key("test-a", "seed-123")
        k2 = crypto.derive_key("test-b", "seed-123")
        assert k1 != k2

    def test_derive_key_different_seed(self):
        """Разный seed → разный ключ при том же purpose."""
        k1 = crypto.derive_key("test", "seed-aaa")
        k2 = crypto.derive_key("test", "seed-bbb")
        assert k1 != k2

    def test_derive_key_is_base64(self):
        """Результат — корректная base64-строка."""
        key = crypto.derive_key("p", "s")
        decoded = __import__("base64").b64decode(key)
        assert len(decoded) == 32  # SHA-256


class TestDeriveHexKey:
    def test_derive_hex_key_deterministic(self):
        """Одинаковый purpose и seed → одинаковый ключ."""
        k1 = crypto.derive_hex_key("test", "seed-123")
        k2 = crypto.derive_hex_key("test", "seed-123")
        assert k1 == k2

    def test_derive_hex_key_different_purpose(self):
        """Разный purpose → разный ключ при том же seed."""
        k1 = crypto.derive_hex_key("test-a", "seed-123")
        k2 = crypto.derive_hex_key("test-b", "seed-123")
        assert k1 != k2

    def test_derive_hex_key_is_hex(self):
        """Результат — корректная шестнадцатеричная строка из 64 символов."""
        key = crypto.derive_hex_key("p", "s")
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)


# ══════════════════════════════════════════════════════════════════════════════
#  downloader — verify_elf
# ══════════════════════════════════════════════════════════════════════════════

class TestVerifyElf:
    def test_verify_elf_valid(self, tmp_path):
        """Файл с ELF-заголовком → True."""
        from hydra.utils import downloader
        elf_file = tmp_path / "test.bin"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert downloader.verify_elf(elf_file) is True

    def test_verify_elf_invalid(self, tmp_path):
        """Файл без ELF-заголовка → False."""
        from hydra.utils import downloader
        non_elf = tmp_path / "text.txt"
        non_elf.write_bytes(b"xxxx")
        assert downloader.verify_elf(non_elf) is False

    def test_verify_elf_missing(self, tmp_path):
        """Несуществующий файл → False (не Exception)."""
        from hydra.utils import downloader
        assert downloader.verify_elf(tmp_path / "nope") is False


def test_extract_tarball_rejects_parent_traversal(tmp_path):
    from hydra.utils import downloader
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("../outside.txt")
        payload = b"unsafe"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    with pytest.raises(ValueError, match="Unsafe path"):
        downloader.extract_tarball(archive, tmp_path / "extract")


def test_iptables_close_uses_owner_comment():
    from hydra.utils import firewall
    with patch.object(firewall, "_ipt_rule_exists", side_effect=[True, False]), \
         patch.object(firewall, "_run") as run:
        firewall._ipt_close("tcp", 443, 443, "naive")

    delete = run.call_args_list[0].args[0]
    assert delete == [
        "iptables", "-t", "filter", "-D", "INPUT", "-p", "tcp",
        "--dport", "443", "-j", "ACCEPT", "-m", "comment",
        "--comment", "naive",
    ]


# ══════════════════════════════════════════════════════════════════════════════
#  net
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectArch:
    @patch("hydra.utils.net.platform.machine")
    def test_detect_arch_amd64(self, mock_machine):
        mock_machine.return_value = "x86_64"
        assert net.detect_arch() == "amd64"

    @patch("hydra.utils.net.platform.machine")
    def test_detect_arch_amd64_upper(self, mock_machine):
        mock_machine.return_value = "AMD64"
        assert net.detect_arch() == "amd64"

    @patch("hydra.utils.net.platform.machine")
    def test_detect_arch_arm64(self, mock_machine):
        mock_machine.return_value = "aarch64"
        assert net.detect_arch() == "arm64"

    @patch("hydra.utils.net.platform.machine")
    def test_detect_arch_arm64_alt(self, mock_machine):
        mock_machine.return_value = "arm64"
        assert net.detect_arch() == "arm64"

    @patch("hydra.utils.net.platform.machine")
    def test_detect_arch_unknown(self, mock_machine):
        mock_machine.return_value = "mips"
        assert net.detect_arch() == "mips"


class TestLocalIp:
    @patch("hydra.utils.net.socket.socket")
    def test_local_ip_success(self, mock_socket_cls):
        """Успешное определение локального IP."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 12345)
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
        assert net.local_ip() == "192.168.1.100"

    @patch("hydra.utils.net.socket.socket", side_effect=Exception("fail"))
    def test_local_ip_fallback(self, _mock):
        """При ошибке сокета → 127.0.0.1."""
        assert net.local_ip() == "127.0.0.1"


class TestPublicIp:
    @patch("hydra.utils.net.subprocess.run")
    def test_public_ip_success(self, mock_run):
        """Успешное получение публичного IP через curl."""
        mock_run.return_value = MagicMock(
            stdout="203.0.113.42\n",
            returncode=0,
        )
        assert net.public_ip() == "203.0.113.42"

    @patch("hydra.utils.net.subprocess.run", side_effect=Exception("fail"))
    def test_public_ip_fallback(self, _mock):
        """При ошибке → 127.0.0.1."""
        assert net.public_ip() == "127.0.0.1"
