"""Launch environment: cwd, PATH/LD_LIBRARY_PATH, and native-install staging.

GUI apps resolve assets via GetModuleFileName / argv[0], not process cwd.
A cache work-copy must be staged next to Packages/ and sibling DLLs before smoke.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from argus.binary.file_io import copy_binary_resilient

_SKIP_NAMES = {".argus-work", ".argus-sandbox", ".argus-exec", ".argus-shadow"}
_ASSET_DIR_NAMES = ("Packages", "resources", "Resources", "lib", "plugins", "share", "data")


def _has_native_assets(install: Path) -> bool:
    """True when directory looks like a real app install (not a lone exe copy)."""
    if not install.is_dir():
        return False
    for name in _ASSET_DIR_NAMES:
        if (install / name).is_dir():
            return True
    try:
        dlls = list(install.glob("*.dll"))
        if len(dlls) >= 2:
            return True
        data_files = [
            p
            for p in install.iterdir()
            if p.is_file()
            and p.suffix.lower() in (".pak", ".dat", ".bin", ".qml", ".so", ".dylib")
        ]
        if len(data_files) >= 2:
            return True
    except OSError:
        return False
    return False


def _normalize_exe_basename(name: str) -> str:
    low = name.lower()
    if low.endswith("_orig.exe"):
        return name[: -len("_orig.exe")] + ".exe"
    if low.endswith("_orig"):
        return name[: -len("_orig")]
    return name


def _find_install_with_assets(
    exe_name: str,
    *,
    reference_size: Optional[int] = None,
) -> Optional[Path]:
    """Locate a Program Files-style install that ships sibling assets."""
    if os.name != "nt":
        return None
    roots: list[Path] = []
    for key in ("ProgramFiles", "ProgramFiles(x86)"):
        v = os.environ.get(key)
        if v:
            roots.append(Path(v))
    roots.extend([Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)")])
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for child in root.iterdir():
                if not child.is_dir():
                    continue
                cand_exe = child / exe_name
                if not cand_exe.is_file():
                    continue
                key = str(child.resolve())
                if key in seen:
                    continue
                seen.add(key)
                if not _has_native_assets(child):
                    continue
                if reference_size is not None:
                    try:
                        delta = abs(cand_exe.stat().st_size - reference_size)
                        if delta > max(reference_size // 20, 64_000):
                            continue
                    except OSError:
                        continue
                return child.resolve()
        except OSError:
            continue
    return None


def resolve_native_install_dir(
    binary: str | Path,
    *,
    original: Optional[str | Path] = None,
) -> Path:
    """Best install root for sibling assets — not workspace/testdrop cache."""
    seed: Optional[Path] = None
    ref_path: Optional[Path] = None
    if original:
        op = Path(original).resolve()
        ref_path = op if op.is_file() else None
        if op.is_file():
            seed = op.parent
        elif op.is_dir():
            return op
    if seed is None:
        bp = Path(binary).resolve()
        ref_path = ref_path or (bp if bp.is_file() else None)
        seed = bp.parent.parent if bp.parent.name == ".argus-work" else bp.parent

    assert seed is not None
    if _has_native_assets(seed):
        return seed

    exe_name = _normalize_exe_basename(
        Path(original).name if original and Path(original).is_file() else Path(binary).name
    )
    ref_size = ref_path.stat().st_size if ref_path and ref_path.is_file() else None
    found = _find_install_with_assets(exe_name, reference_size=ref_size)
    if found:
        return found

    explicit = os.environ.get("ARGUS_INSTALL_DIR", "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_dir():
            return p.resolve()

    try:
        from argus.llm.session import get_session

        sess = get_session()
        if sess.install_dir:
            sid = Path(sess.install_dir)
            if sid.is_dir() and _has_native_assets(sid):
                return sid.resolve()
    except Exception:
        pass

    return seed


def install_dir_for(
    binary: str | Path,
    *,
    original: Optional[str | Path] = None,
) -> Path:
    """Native install directory (sibling assets), not workspace cache."""
    return resolve_native_install_dir(binary, original=original)


@dataclass
class StagedLaunch:
    path: Path
    cwd: str
    ephemeral: bool = False


def launch_env_for(binary: str | Path) -> tuple[str, dict[str, str]]:
    """Return cwd + env. cwd is the directory that should contain sibling libs.

    Prefer the staged exe's native root (.argus-work parent or exe dir).
    Session install_dir is only used as a PATH/LD extra search dir — it must not
    become cwd while the exe still lives in a cache folder.
    """
    p = Path(binary).resolve()
    cwd = str(p.parent)
    work_dir: Optional[str] = None
    if p.parent.name == ".argus-work":
        work_dir = str(p.parent)
        cwd = str(p.parent.parent)

    install: Optional[str] = None
    extra_install: Optional[str] = None
    try:
        from argus.llm.session import get_session

        sess = get_session()
        orig = sess.original_binary or None
        install = str(install_dir_for(p, original=orig))
        if sess.install_dir:
            extra_install = str(Path(sess.install_dir))
    except Exception:
        install = None
    if not install:
        install = str(install_dir_for(p))

    search_dirs: List[str] = []
    if work_dir:
        search_dirs.append(work_dir)
    search_dirs.append(cwd)
    for cand in (install, extra_install):
        if cand and cand not in search_dirs:
            search_dirs.append(cand)
    if str(p.parent) not in search_dirs:
        search_dirs.append(str(p.parent))

    env = os.environ.copy()
    prev_ld = env.get("LD_LIBRARY_PATH", "")
    parts_ld = search_dirs + ([prev_ld] if prev_ld else [])
    env["LD_LIBRARY_PATH"] = ":".join(dict.fromkeys(x for x in parts_ld if x))

    if os.name == "nt":
        prev_p = env.get("PATH", "")
        parts_p = search_dirs + ([prev_p] if prev_p else [])
        env["PATH"] = os.pathsep.join(dict.fromkeys(x for x in parts_p if x))

    return cwd, env


def _writable_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("x")
        probe.unlink()
        return True
    except OSError:
        return False


def _dir_link(src: Path, dst: Path) -> bool:
    if dst.exists():
        return True
    dst.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        r = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(dst), str(src)],
            capture_output=True,
            timeout=15,
        )
        if r.returncode == 0 and dst.exists():
            return True
        try:
            os.symlink(src, dst, target_is_directory=True)
            return True
        except OSError:
            return False
    try:
        os.symlink(src, dst, target_is_directory=True)
        return True
    except OSError:
        return False


def _file_link(src: Path, dst: Path) -> None:
    if dst.exists():
        return
    try:
        os.link(src, dst)
        return
    except OSError:
        pass
    try:
        os.symlink(src, dst)
        return
    except OSError:
        pass
    shutil.copy2(src, dst)


def _populate_shadow(install: Path, shadow: Path, exe_name: str) -> None:
    shadow.mkdir(parents=True, exist_ok=True)
    for child in install.iterdir():
        if child.name in _SKIP_NAMES or child.name.startswith(".argus"):
            continue
        dest = shadow / child.name
        if child.is_dir():
            _dir_link(child, dest)
            continue
        if child.name.lower() == exe_name.lower():
            continue
        _file_link(child, dest)


def _shadow_root(install: Path) -> Path:
    key = hashlib.sha256(str(install.resolve()).encode()).hexdigest()[:16]
    cache = Path(
        os.environ.get("ARGUS_WORK_DIR")
        or (Path.home() / ".cache" / "argus" / "workspaces")
    )
    return cache / "launch-shadows" / f"{install.name}-{key}"


def stage_native_executable(
    patched: str | Path,
    *,
    original: Optional[str | Path] = None,
) -> StagedLaunch:
    """Place a copy of `patched` where GetModuleFileName sees sibling assets."""
    src = Path(patched).resolve()
    if not src.is_file():
        return StagedLaunch(path=src, cwd=str(src.parent), ephemeral=False)

    install = install_dir_for(src, original=original)
    if original and Path(original).is_file():
        exe_name = _normalize_exe_basename(Path(original).resolve().name)
    else:
        exe_name = _normalize_exe_basename(src.name)

    # Already sitting in the install tree (or .argus-work under it).
    try:
        src.relative_to(install)
        if src.parent == install or src.parent.name == ".argus-work":
            cwd = str(install) if src.parent.name == ".argus-work" else str(src.parent)
            return StagedLaunch(path=src, cwd=cwd, ephemeral=False)
    except ValueError:
        pass

    local_work = install / ".argus-work"
    if _writable_dir(local_work):
        dest = local_work / exe_name
        if dest.resolve() != src:
            copy_binary_resilient(src, dest, fallback_src=original)
        return StagedLaunch(path=dest, cwd=str(install), ephemeral=False)

    smoke = install / f".argus_smoke_{exe_name}"
    try:
        copy_binary_resilient(src, smoke, fallback_src=original)
        return StagedLaunch(path=smoke, cwd=str(install), ephemeral=True)
    except OSError:
        pass

    shadow = _shadow_root(install)
    _populate_shadow(install, shadow, exe_name)
    dest = shadow / exe_name
    copy_binary_resilient(src, dest, fallback_src=original)
    return StagedLaunch(path=dest, cwd=str(shadow), ephemeral=False)


def write_install_launcher(
    install_root: Path | str,
    exe_name: str,
    *,
    launcher_name: str | None = None,
) -> Path:
    """
    Write a wrapper next to the exe so bundled sibling .so/.dll resolve
    (e.g. BCompare + lib7z.so). Linux: LD_LIBRARY_PATH; Windows: PATH + cwd.
    """
    root = Path(install_root).resolve()
    exe = root / exe_name
    if not exe.is_file():
        raise FileNotFoundError(str(exe))
    stem = Path(exe_name).stem
    if os.name == "nt":
        out = root / (launcher_name or f"run-{stem}.cmd")
        out.write_text(
            "@echo off\r\n"
            f'set "ROOT=%~dp0"\r\n'
            f'set "PATH=%ROOT%;%PATH%"\r\n'
            f'cd /d "%ROOT%"\r\n'
            f'"%ROOT%\\{exe_name}" %*\r\n',
            encoding="utf-8",
        )
        return out
    out = root / (launcher_name or f"run-{stem}.sh")
    out.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
        'export LD_LIBRARY_PATH="${ROOT}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"\n'
        f'exec "${{ROOT}}/{exe_name}" "$@"\n',
        encoding="utf-8",
    )
    out.chmod(0o755)
    return out
