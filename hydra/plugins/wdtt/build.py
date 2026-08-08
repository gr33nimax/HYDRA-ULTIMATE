"""Go source build and toolchain management for WDTT."""
from __future__ import annotations

from pathlib import Path

from hydra.plugins.wdtt.model import WdttEnvironment

def _go_env(env: WdttEnvironment) -> dict:
    e = dict(env.os_module.environ)
    e.setdefault('GOPATH', '/root/go')
    return e

def _go_arch(env: WdttEnvironment) -> str:
    m = env.platform_module.machine().lower()
    return {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(m, 'amd64')

def _go_required_version(env: WdttEnvironment, gomod: Path) -> str:
    if gomod.exists():
        try:
            m = env.re_module.search('^go\\s+(\\d+\\.\\d+(?:\\.\\d+)?)', gomod.read_text(), env.re_module.M)
            if m:
                return m.group(1)
        except Exception:
            pass
    return '1.21.0'

def _ver_tuple(env: WdttEnvironment, s: str) -> tuple:
    parts = env.re_module.findall('\\d+', s)[:3]
    parts += ['0'] * (3 - len(parts))
    return tuple((int(p) for p in parts))



class WdttBuildMixin:
    def _build_wdtt_server(self) -> bool:
        tmp = Path(self._wdtt_env().tempfile_module.mkdtemp())
        try:
            archive = tmp / 'master.tar.gz'
            print(f'  Скачиваю исходники qWDTT...')
            self._wdtt_env().urllib_module.request.urlretrieve(self._wdtt_env().source_url, str(archive))
            print(f'  Распаковываю...')
            self._wdtt_env().host.run(['tar', '-xzf', str(archive), '-C', str(tmp)], capture_output=True, check=True, timeout=self._wdtt_env().source_extract_timeout)
            src_dirs = list(tmp.glob('proxy-turn-vk-android-*'))
            if not src_dirs:
                print(f'  Не найдена директория с исходниками.')
                return False
            src_dir = src_dirs[0]
            gomod = src_dir / 'go.mod'
            required = self._go_required_version(gomod)
            go = self._ensure_go(required)
            if not go:
                print(f'  Не удалось установить Go {required}+.')
                return False
            print(f'  Разрешаю зависимости Go-модуля...')
            r = self._wdtt_env().host.run([go, 'mod', 'tidy'], capture_output=True, text=True, cwd=str(src_dir), env={**self._go_env(), 'GOSUMDB': 'off'}, timeout=self._wdtt_env().go_module_timeout)
            if r.returncode != 0:
                print(f"  go mod tidy: {(r.stderr or '')[:300]}")
                return False
            print(f'  Компилирую wdtt-server...')
            env = {**self._go_env(), 'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': self._go_arch()}
            r = self._wdtt_env().host.run([go, 'build', '-o', str(tmp / 'wdtt-server'), '-ldflags', '-s -w', '.'], capture_output=True, text=True, env=env, cwd=str(src_dir), timeout=self._wdtt_env().go_build_timeout)
            if r.returncode != 0:
                print(f"  Ошибка компиляции: {(r.stderr or '')[:300]}")
                return False
            built = tmp / 'wdtt-server'
            if not built.exists():
                print(f'  Бинарник не создан.')
                return False
            self._wdtt_env().bin_path.parent.mkdir(parents=True, exist_ok=True)
            if self._wdtt_env().bin_path.exists():
                try:
                    self._wdtt_env().bin_path.unlink()
                except Exception:
                    pass
            self._wdtt_env().shutil_module.copy2(str(built), str(self._wdtt_env().bin_path))
            self._wdtt_env().bin_path.chmod(493)
            print(f'  wdtt-server установлен: {self._wdtt_env().bin_path}')
            return True
        except Exception as e:
            print(f'  Ошибка: {e}')
            return False
        finally:
            self._wdtt_env().shutil_module.rmtree(tmp, ignore_errors=True)

    def _check_go(self) -> str | None:
        go = '/usr/local/bin/go' if Path('/usr/local/bin/go').exists() else self._wdtt_env().shutil_module.which('go')
        if go:
            r = self._wdtt_env().host.run([go, 'version'], capture_output=True, text=True)
            if r.returncode == 0:
                return go
        return None

    def _go_installed_version(self, go: str) -> tuple:
        r = self._wdtt_env().host.run([go, 'version'], capture_output=True, text=True)
        m = self._wdtt_env().re_module.search('go(\\d+\\.\\d+(?:\\.\\d+)?)', r.stdout or '')
        if not m:
            return (0, 0, 0)
        parts = self._wdtt_env().re_module.findall('\\d+', m.group(1))[:3]
        parts += ['0'] * (3 - len(parts))
        return tuple((int(p) for p in parts))

    def _ensure_go(self, required: str) -> str | None:
        go = self._check_go()
        if go and self._go_installed_version(go) >= self._ver_tuple(required):
            return go
        print(f'  Нужен Go {required}+, устанавливаю...')
        return self._install_go_toolchain(required)

    def _install_go_toolchain(self, required: str) -> str | None:
        arch = self._go_arch()
        try:
            req = self._wdtt_env().urllib_module.request.Request('https://go.dev/VERSION?m=text', headers={'User-Agent': 'HYDRA-WDTT'})
            with self._wdtt_env().urllib_module.request.urlopen(req, timeout=15) as r:
                version = r.read().decode('utf-8', errors='replace').splitlines()[0].strip()
            if not version.startswith('go'):
                version = f'go{required}'
        except Exception:
            version = f'go{required}'
        url = f'{self._wdtt_env().go_dl_url}{version}.linux-{arch}.tar.gz'
        tarball = Path(f'/tmp/{version}.linux-{arch}.tar.gz')
        print(f'  Скачиваю {version} ({arch})...')
        try:
            self._wdtt_env().urllib_module.request.urlretrieve(url, str(tarball))
        except Exception as e:
            print(f'  Не удалось скачать Go: {e}')
            return None
        go_dir = Path('/usr/local/go')
        if go_dir.exists():
            self._wdtt_env().host.run(['rm', '-rf', str(go_dir)], capture_output=True)
        r = self._wdtt_env().host.run(['tar', '-C', '/usr/local', '-xzf', str(tarball)], capture_output=True)
        tarball.unlink(missing_ok=True)
        if r.returncode != 0:
            print(f'  Не удалось распаковать Go.')
            return None
        for exe in ('go', 'gofmt'):
            src = go_dir / 'bin' / exe
            dst = Path('/usr/local/bin') / exe
            if src.exists():
                try:
                    if dst.exists() or dst.is_symlink():
                        dst.unlink()
                    dst.symlink_to(src)
                except Exception:
                    pass
        return self._check_go()
