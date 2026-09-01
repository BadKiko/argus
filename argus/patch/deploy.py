from __future__ import annotations

"""In-place install deploy: backup under original/, patch native paths, elevate when needed."""

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

PathLike = Union[str, Path]


@dataclass
class DeployResult:
    ok: bool
    target: str
    backup: Optional[str] = None
    elevated: bool = False
    detail: str = ""
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "target": self.target,
            "backup": self.backup,
            "elevated": self.elevated,
            "detail": self.detail,
            "errors": list(self.errors),
        }


def patch_mode() -> str:
    """in_place (default) | workspace (legacy copy-only under .argus-work)."""
    return os.environ.get("ARGUS_PATCH_MODE", "in_place").strip().lower()


def in_place_enabled() -> bool:
    return patch_mode() not in ("workspace", "copy", "legacy", "off", "0", "false", "no")


def original_dir_for(install_root: PathLike) -> Path:
    """Directory for pristine backups: <install>/original/."""
    return Path(install_root).resolve() / "original"


def is_under_original(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return "original" in parts


def install_root_for(target: PathLike) -> Path:
    p = Path(target).resolve()
    if p.parent.name == ".argus-work":
        return p.parent.parent
    return p.parent


def backup_path_for(target: PathLike, *, install_root: Optional[PathLike] = None) -> Path:
    t = Path(target).resolve()
    root = Path(install_root).resolve() if install_root else install_root_for(t)
    return original_dir_for(root) / t.name


def _path_writable(path: Path) -> bool:
    if not path.exists():
        parent = path.parent
        return os.access(parent, os.W_OK)
    return os.access(path, os.W_OK)


def _dir_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("x")
        probe.unlink()
        return True
    except OSError:
        return False


def _run_elevated(args: List[str], *, detail: str = "") -> subprocess.CompletedProcess:
    if sys.platform == "win32":
        # cmd /c with runas via PowerShell Start-Process -Verb RunAs
        ps_args = " ".join(f"'{a.replace(chr(39), chr(39)+chr(39))}'" for a in args)
        script = (
            f"Start-Process -FilePath '{args[0]}' "
            f"-ArgumentList @({','.join(repr(a) for a in args[1:])}) "
            "-Wait -Verb RunAs"
        )
        return subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
        )
    # Linux / macOS: prefer sudo -n (passwordless), then interactive sudo
    for prefix in (["sudo", "-n"], ["sudo"]):
        try:
            cp = subprocess.run(
                [*prefix, *args],
                capture_output=True,
                text=True,
                check=False,
            )
            if cp.returncode == 0:
                return cp
        except FileNotFoundError:
            break
    raise PermissionError(detail or f"elevated command failed: {args}")


def ensure_writable_dir(path: Path, *, elevate: bool = True) -> bool:
    if _dir_writable(path):
        return True
    if not elevate:
        return False
    try:
        if sys.platform == "win32":
            _run_elevated(["icacls", str(path.parent), "/grant", f"{os.getlogin()}:F"])
        else:
            _run_elevated(["chmod", "-R", "u+w", str(path.parent)])
        return _dir_writable(path)
    except (OSError, PermissionError, subprocess.SubprocessError):
        return False


def ensure_original_backup(
    target: PathLike,
    *,
    install_root: Optional[PathLike] = None,
    elevate: bool = True,
) -> Path:
    """
    Copy target -> <install>/original/<basename> once (never overwrite existing backup).
    Returns backup path.
    """
    from argus.binary.file_io import copy_binary_resilient

    t = Path(target).resolve()
    if not t.is_file() or is_under_original(t):
        return t
    root = Path(install_root).resolve() if install_root else install_root_for(t)
    backup = backup_path_for(t, install_root=root)
    if backup.is_file():
        return backup
    if not ensure_writable_dir(backup.parent, elevate=elevate):
        # Fallback: user cache mirror when install/original is not creatable
        cache = Path(
            os.environ.get("ARGUS_ORIGINAL_DIR")
            or (Path.home() / ".cache" / "argus" / "original")
        )
        key = root.name or "install"
        backup = cache / key / t.name
        backup.parent.mkdir(parents=True, exist_ok=True)
    if not backup.is_file():
        copy_binary_resilient(t, backup, fallback_src=t)
    return backup


def install_replace(
    patched: PathLike,
    target: PathLike,
    *,
    install_root: Optional[PathLike] = None,
    elevate: bool = True,
) -> DeployResult:
    """Replace install target with patched bytes; backup under original/ first."""
    from argus.binary.file_io import copy_binary_resilient, release_binary_lock

    src = Path(patched).resolve()
    dst = Path(target).resolve()
    if not src.is_file():
        return DeployResult(ok=False, target=str(dst), detail="patched source missing")
    root = Path(install_root).resolve() if install_root else install_root_for(dst)
    try:
        backup = ensure_original_backup(dst, install_root=root, elevate=elevate)
    except OSError as exc:
        return DeployResult(ok=False, target=str(dst), detail=f"backup failed: {exc}")

    release_binary_lock(dst)
    elevated = False
    try:
        if _path_writable(dst):
            copy_binary_resilient(src, dst, fallback_src=src)
            return DeployResult(
                ok=True,
                target=str(dst),
                backup=str(backup),
                detail="replaced in place",
            )
    except OSError as first_err:
        if not elevate:
            return DeployResult(
                ok=False,
                target=str(dst),
                backup=str(backup),
                detail=str(first_err),
            )

    # Elevated replace: write via temp + cp
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=dst.suffix) as tmp:
            tmp_path = Path(tmp.name)
        copy_binary_resilient(src, tmp_path, fallback_src=src)
        try:
            dst.chmod(src.stat().st_mode)
        except OSError:
            pass
        if sys.platform == "win32":
            _run_elevated(["cmd", "/c", "copy", "/Y", str(tmp_path), str(dst)])
        else:
            _run_elevated(["cp", str(tmp_path), str(dst)])
        elevated = True
        tmp_path.unlink(missing_ok=True)
        return DeployResult(
            ok=True,
            target=str(dst),
            backup=str(backup),
            elevated=True,
            detail="replaced via elevation",
        )
    except (OSError, PermissionError, subprocess.SubprocessError) as exc:
        return DeployResult(
            ok=False,
            target=str(dst),
            backup=str(backup),
            elevated=elevated,
            detail=f"elevated replace failed: {exc}",
        )


def deploy_patched_modules(
    module_outs: Dict[str, str],
    *,
    primary: str,
    elevate: bool = True,
) -> Dict[str, object]:
    """Deploy all module outputs to their native install paths."""
    results: List[DeployResult] = []
    primary_p = Path(primary).resolve()
    for mod, outp in module_outs.items():
        mod_p = Path(mod).resolve()
        out_p = Path(outp).resolve()
        native = mod_p
        # Work-space copy -> install sibling
        if out_p.parent.name == ".argus-work" and not in_place_enabled():
            native = install_root_for(mod_p) / mod_p.name
            r = install_replace(out_p, native, elevate=elevate)
        elif out_p != mod_p:
            r = install_replace(out_p, native, elevate=elevate)
        elif in_place_enabled():
            results.append(
                DeployResult(
                    ok=True,
                    target=str(native),
                    backup=str(backup_path_for(native)),
                    detail="already patched in place",
                )
            )
            continue
        else:
            r = install_replace(out_p, native, elevate=elevate)
        results.append(r)

    ok = all(r.ok for r in results)
    return {
        "ok": ok,
        "mode": patch_mode(),
        "results": [r.to_dict() for r in results],
        "primary": str(primary_p),
    }


def restore_from_original(target: PathLike, *, install_root: Optional[PathLike] = None) -> DeployResult:
    """Restore install file from original/ backup."""
    t = Path(target).resolve()
    backup = backup_path_for(t, install_root=install_root)
    if not backup.is_file():
        return DeployResult(ok=False, target=str(t), detail="no backup in original/")
    return install_replace(backup, t, install_root=install_root)
