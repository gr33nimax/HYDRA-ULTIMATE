"""Bounded, scoped snapshots of one Certbot lineage (including its live symlinks)."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from itertools import chain
from pathlib import Path

from hydra.core.host import HostBackend


MAX_FILES = 1024
MAX_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class CertificateFile:
    path: str
    mode: int
    content: bytes = field(repr=False)
    sha256: str = ""


@dataclass(frozen=True)
class CertificateSnapshot:
    name: str
    files: tuple[CertificateFile, ...]
    directories: tuple[tuple[str, int], ...]
    links: tuple[tuple[str, str], ...]
    owners: tuple[tuple[str, int, int], ...]


@dataclass(frozen=True)
class CertificateFiles:
    host: HostBackend
    root: Path = Path("/etc/letsencrypt")

    def scopes(self, name: str) -> tuple[Path, ...]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", name) or ".." in name:
            raise ValueError("Некорректное имя сертификата")
        if not self.root.is_absolute() or self.root.resolve() != self.root.absolute():
            raise ValueError("Каталог Certbot должен быть абсолютным и без symlink")
        for directory in ("live", "archive", "renewal"):
            if (self.root / directory).is_symlink():
                raise ValueError("Каталоги Certbot не должны быть symlink")
        return self.root / "live" / name, self.root / "archive" / name, self.root / "renewal" / f"{name}.conf"

    def read(self, name: str, filename: str) -> bytes:
        live, archive, _ = self.scopes(name)
        if filename not in {"fullchain.pem", "privkey.pem"}:
            raise ValueError("Неизвестный TLS-файл")
        target = (live / filename).resolve()
        if not (target.is_relative_to(live) or target.is_relative_to(archive)):
            raise ValueError("TLS symlink выходит за пределы сертификата")
        if not stat.S_ISREG(target.lstat().st_mode):
            raise ValueError("TLS-материал должен быть обычным файлом")
        return self.host.read_bytes(target, max_bytes=128 * 1024)

    def snapshot(self, name: str) -> CertificateSnapshot:
        files, directories, links, owners = [], [], [], []
        total = 0
        for scope in self.scopes(name):
            if scope.is_symlink():
                raise ValueError("Корень lineage не должен быть symlink")
            paths = chain((scope,), scope.rglob("*") if scope.is_dir() else ())
            for path in paths:
                if len(files) + len(directories) + len(links) >= MAX_FILES:
                    raise ValueError("Слишком много файлов сертификата")
                relative = path.relative_to(self.root).as_posix()
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    continue
                owners.append((relative, metadata.st_uid, metadata.st_gid))
                mode = stat.S_IMODE(metadata.st_mode)
                if not path.is_symlink() and mode & ~0o777:
                    raise ValueError("Нестандартные права TLS-файлов: операция отменена")
                if path.is_symlink():
                    target = os.readlink(path)
                    self._check_link(name, relative, target)
                    links.append((relative, target))
                elif path.is_dir():
                    directories.append((relative, mode))
                elif stat.S_ISREG(metadata.st_mode):
                    data = self.host.read_bytes(path, max_bytes=min(MAX_BYTES - total, 128 * 1024))
                    total += len(data)
                    files.append(CertificateFile(relative, mode, data, hashlib.sha256(data).hexdigest()))
                else:
                    raise ValueError("Нестандартный тип файла в lineage")
        return CertificateSnapshot(name, tuple(files), tuple(directories), tuple(links), tuple(owners))

    def restore(self, snapshot: CertificateSnapshot) -> None:
        scopes = self.scopes(snapshot.name)
        seen: set[str] = set()
        total = 0
        for relative in [
            *(item.path for item in snapshot.files),
            *(p for p, _ in snapshot.directories),
            *(p for p, _ in snapshot.links),
        ]:
            path = self.root / relative
            if (
                Path(relative).is_absolute()
                or relative in seen
                or ".." in Path(relative).parts
                or not any(path == s or path.is_relative_to(s) for s in scopes)
            ):
                raise ValueError("Некорректный manifest сертификата")
            seen.add(relative)
        if len(seen) > MAX_FILES:
            raise ValueError("Слишком большой manifest")
        non_directories = {item.path for item in snapshot.files} | {path for path, _ in snapshot.links}
        if any(parent.as_posix() in non_directories for path in seen for parent in Path(path).parents):
            raise ValueError("Файл или symlink не может быть родителем записи manifest")
        for item in snapshot.files:
            total += len(item.content)
            if total > MAX_BYTES or hashlib.sha256(item.content).hexdigest() != item.sha256:
                raise ValueError("Повреждённый snapshot сертификата")
            if item.mode & ~0o777:
                raise ValueError("Недопустимые права snapshot")
        for relative, target in snapshot.links:
            self._check_link(snapshot.name, relative, target)
        if (
            {path for path, _, _ in snapshot.owners} != seen
            or len(snapshot.owners) != len(seen)
            or any(
                type(value) is not int or not 0 <= value < 2**32 - 1
                for _, uid, gid in snapshot.owners
                for value in (uid, gid)
            )
        ):
            raise ValueError("Некорректные владельцы в manifest")
        if any(mode & ~0o777 for _, mode in snapshot.directories):
            raise ValueError("Недопустимые права каталога в manifest")
        for scope in scopes:
            result = self.host.run(["rm", "-rf", "--", str(scope)], timeout=15)
            if result.returncode:
                raise RuntimeError("Не удалось очистить lineage при откате")
        for relative, mode in sorted(snapshot.directories, key=lambda item: len(Path(item[0]).parts)):
            self.host.ensure_directory(self.root / relative, mode=mode & 0o777)
        for item in snapshot.files:
            self.host.atomic_write(self.root / item.path, item.content, mode=item.mode, durable=True)
        for relative, target in snapshot.links:
            result = self.host.run(["ln", "-s", "--", target, str(self.root / relative)], timeout=10)
            if result.returncode:
                raise RuntimeError("Не удалось восстановить TLS symlink")
        for relative, uid, gid in snapshot.owners:
            result = self.host.run(["chown", "-h", "--", f"{uid}:{gid}", str(self.root / relative)], timeout=10)
            if result.returncode:
                raise RuntimeError("Не удалось восстановить владельца TLS-файла")

    def _check_link(self, name: str, relative: str, target: str) -> None:
        live, archive, _ = self.scopes(name)
        path = self.root / relative
        destination = (path.parent / target).resolve()
        if not path.is_relative_to(live) or not destination.is_relative_to(archive):
            raise ValueError("Symlink сертификата выходит за пределы archive lineage")
