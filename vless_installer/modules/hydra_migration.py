"""
HYDRA backup export/import and scheduled backup.
Extracted from vless_installer/_core.py (Phase 4).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import threading
from datetime import datetime
from pathlib import Path


class _LazyCore:
    """Late-bind to vless_installer._core (avoids circular import at load time)."""
    _mod = None

    def _m(self):
        if self._mod is None:
            import vless_installer._core as m
            self._mod = m
        return self._mod

    def __getattr__(self, name: str):
        return getattr(self._m(), name)


core = _LazyCore()


_HYDRA_BACKUP_FILES = (
    core.STATE_FILE,
    Path("/var/lib/xray-installer/naiveproxy.json"),
    Path("/var/lib/xray-installer/mieru.json"),
    Path("/var/lib/xray-installer/sub_server.json"),
    Path("/var/lib/xray-installer/tg_bot.json"),
    Path("/var/lib/xray-installer/ingress_geoip.json"),
    Path("/var/lib/xray-installer/ipban.json"),
)


def collect_backup_paths() -> list[tuple[Path, str]]:
    items: list[tuple[Path, str]] = []
    for p in _HYDRA_BACKUP_FILES:
        if p.exists():
            items.append((p, p.name))
    sub_dir = Path("/var/lib/xray-installer/subscriptions")
    if sub_dir.is_dir():
        for f in sub_dir.glob("*.json"):
            items.append((f, f"subscriptions/{f.name}"))
    return items
def export_backup(encrypt: bool = False) -> None:
    """Архив state + конфигов HYDRA-стека."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_path = Path(f"/root/hydra-backup-{ts}.tar.gz")
    items = collect_backup_paths()
    if not items:
        core.warn("Нет файлов для экспорта — сначала выполните установку HYDRA")
        return
    core.info(f"Экспорт HYDRA → {archive_path}")
    import tarfile
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        manifest = []
        for src, arcname in items:
            dst = tmpdir / arcname
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            manifest.append(arcname)
        (tmpdir / "MANIFEST.txt").write_text("\n".join(manifest), encoding="utf-8")
        with tarfile.open(archive_path, "w:gz") as tar:
            for f in tmpdir.rglob("*"):
                if f.is_file():
                    tar.add(f, arcname=f.relative_to(tmpdir).as_posix())
    archive_path.chmod(0o600)
    core.success(f"Архив создан: {archive_path} ({len(items)} файлов)")
    if encrypt:
        try:
            import getpass
            pwd = getpass.getpass("  Пароль для шифрования: ")
            pwd2 = getpass.getpass("  Повторите пароль: ")
        except Exception:
            pwd = input("  Пароль: ").strip()
            pwd2 = input("  Повторите: ").strip()
        if pwd != pwd2 or not pwd:
            core.warn("Пароли не совпали — архив оставлен без шифрования")
            return
        enc = backup_encrypt(archive_path, pwd)
        if enc:
            archive_path.unlink(missing_ok=True)
            core.success(f"Зашифровано: {enc}")


def import_backup() -> None:
    """Восстановление state/конфигов HYDRA из tar.gz."""
    raw = input("  Путь к архиву (.tar.gz или .gz.enc): ").strip()
    ap = Path(raw)
    if not ap.exists():
        core.warn(f"Файл не найден: {ap}")
        return
    if ap.suffix == ".enc":
        try:
            import getpass
            pwd = getpass.getpass("  Пароль для расшифровки: ")
        except Exception:
            pwd = input("  Пароль: ").strip()
        dec_path = ap.with_suffix("").with_suffix(".tar.gz")
        if not backup_decrypt(ap, pwd, dec_path):
            return
        ap = dec_path
    import tarfile
    import tempfile
    core.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        with tarfile.open(ap, "r:gz") as tar:
            tar.extractall(tmpdir)
        restored = 0
        for f in tmpdir.rglob("*"):
            if not f.is_file() or f.name == "MANIFEST.txt":
                continue
            rel = f.relative_to(tmpdir)
            if str(rel).startswith("subscriptions/"):
                dest = Path("/var/lib/xray-installer") / rel
            else:
                dest = Path("/var/lib/xray-installer") / f.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
            dest.chmod(0o600)
            restored += 1
    core.success(f"Восстановлено файлов: {restored}")
    core.warn("Перезапустите сервисы HYDRA при необходимости (Naive, Mieru, sub-server, боты)")


def backup_encrypt(archive_path: Path, password: str) -> Path | None:
    """
    Шифрует tar.gz архив через openssl AES-256-CBC → .tar.gz.enc
    Возвращает путь к зашифрованному файлу или None при ошибке.
    """
    enc_path = archive_path.with_suffix(".gz.enc")
    r = core._run([
        "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "310000",
        "-in",  str(archive_path),
        "-out", str(enc_path),
        "-pass", f"pass:{password}",
    ], capture=True, check=False)
    if r.returncode != 0:
        core.warn(f"openssl enc завершился с ошибкой: {r.stderr[:200]}")
        return None
    enc_path.chmod(0o600)
    return enc_path


def backup_decrypt(enc_path: Path, password: str, out_path: Path) -> bool:
    """
    Расшифровывает .tar.gz.enc → tar.gz через openssl.
    Возвращает True при успехе.
    """
    r = core._run([
        "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "310000",
        "-in",  str(enc_path),
        "-out", str(out_path),
        "-pass", f"pass:{password}",
    ], capture=True, check=False)
    if r.returncode != 0:
        core.warn(f"Расшифровка не удалась: {r.stderr[:200]}")
        return False
    return True


def scheduled_backup_run() -> None:
    """Cron: архив state и конфигов HYDRA."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(f"/root/hydra-backup-{ts}.tar.gz")
    items = collect_backup_paths()
    if not items:
        core.log_to_file("WARN", "Scheduled backup: no HYDRA files found")
        return
    import tarfile
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for src, arcname in items:
            dst = tmpdir / arcname
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        with tarfile.open(out, "w:gz") as tar:
            for f in tmpdir.rglob("*"):
                if f.is_file():
                    tar.add(f, arcname=f.relative_to(tmpdir).as_posix())
    sz = out.stat().st_size // 1024
    core.log_to_file("SUCCESS", f"Scheduled backup created: {out} ({sz} КБ)")
    all_archives = sorted(
        list(Path("/root").glob("hydra-backup-*.tar.gz"))
        + list(Path("/root").glob("xray-backup-*.tar.gz")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in all_archives[7:]:
        try:
            old.unlink()
            core.log_to_file("INFO", f"Scheduled backup rotated (removed): {old.name}")
        except Exception:
            pass
