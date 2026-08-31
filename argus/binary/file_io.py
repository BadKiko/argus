"""Cross-platform resilient binary copy (handles transient exe locks after GUI launch)."""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, Path]


def release_binary_lock(path: PathLike) -> None:
    """Best-effort: terminate processes that may hold the executable open."""
    from argus.behavior import terminate_process_by_name

    name = Path(path).name
    if not name:
        return
    terminate_process_by_name(name)
    time.sleep(0.5)


def _copy_windows_shared_read(src: Path, dst: Path) -> None:
    import ctypes
    import msvcrt

    kernel32 = ctypes.windll.kernel32
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    INVALID = ctypes.c_void_p(-1).value

    handle = kernel32.CreateFileW(
        str(src),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == INVALID:
        raise OSError(f"CreateFile failed for {src}")
    try:
        size = src.stat().st_size
        buf = (ctypes.c_char * size)()
        read = ctypes.c_ulong(0)
        ok = kernel32.ReadFile(handle, buf, size, ctypes.byref(read), None)
        if not ok:
            raise OSError(f"ReadFile failed for {src}")
        fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o755)
        try:
            os.write(fd, bytes(buf[: read.value]))
        finally:
            os.close(fd)
    finally:
        kernel32.CloseHandle(handle)


def copy_binary_resilient(
    src: PathLike,
    dst: PathLike,
    *,
    fallback_src: Optional[PathLike] = None,
    retries: int = 4,
) -> Path:
    """Copy executable bytes; retry after releasing locks. Never mutates src."""
    sp = Path(src).resolve()
    dp = Path(dst)
    dp.parent.mkdir(parents=True, exist_ok=True)
    if sp == dp.resolve():
        return dp

    sources = [sp]
    if fallback_src:
        fb = Path(fallback_src).resolve()
        if fb.is_file() and fb not in sources:
            sources.append(fb)

    last_err: Optional[BaseException] = None
    for attempt in range(retries):
        if attempt:
            for p in (sp, dp):
                release_binary_lock(p)
        for candidate in sources:
            try:
                if sys.platform == "win32":
                    _copy_windows_shared_read(candidate, dp)
                else:
                    shutil.copy2(candidate, dp)
                try:
                    dp.chmod(candidate.stat().st_mode)
                except OSError:
                    pass
                return dp
            except OSError as e:
                last_err = e
                time.sleep(0.35 * (attempt + 1))
    if last_err:
        raise last_err
    raise OSError(f"copy failed: {src} -> {dst}")
