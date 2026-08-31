from __future__ import annotations

"""Agent workspace: never mutate the user's original binary."""

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def _writable_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("x")
        probe.unlink()
        return True
    except OSError:
        return False


def work_dir_for(original: Path) -> Path:
    """Prefer <binary-dir>/.argus-work; fall back to user cache when not writable."""
    local = original.parent / ".argus-work"
    if _writable_dir(local):
        return local

    cache_root = Path(
        os.environ.get("ARGUS_WORK_DIR")
        or (Path.home() / ".cache" / "argus" / "workspaces")
    )
    key = hashlib.sha256(str(original.resolve()).encode()).hexdigest()[:16]
    safe_name = original.name.replace(os.sep, "_")
    remote = cache_root / f"{safe_name}-{key}"
    if not _writable_dir(remote):
        raise PermissionError(
            f"cannot create workspace in {local} or {remote} (need a writable directory)"
        )
    return remote


def prepare_work_binary(original: str) -> Tuple[str, str]:
    """
    Copy original into a writable work dir (local .argus-work or ~/.cache/argus/workspaces).
    Returns (work_path, original_resolved).
    """
    orig = Path(original).resolve()
    if not orig.is_file():
        raise FileNotFoundError(str(orig))
    work_dir = work_dir_for(orig)
    work = (work_dir / orig.name).resolve()
    if not work.is_file() or orig.stat().st_mtime > work.stat().st_mtime:
        from argus.binary.file_io import copy_binary_resilient, release_binary_lock

        release_binary_lock(work)
        copy_binary_resilient(orig, work, fallback_src=orig)
    try:
        work.chmod(orig.stat().st_mode)
    except OSError:
        pass
    return str(work), str(orig)


def _resolve(path: Optional[str]) -> Optional[Path]:
    if not path:
        return None
    try:
        return Path(path).resolve()
    except OSError:
        return Path(path)


def is_same_file(a: Optional[str], b: Optional[str]) -> bool:
    pa, pb = _resolve(a), _resolve(b)
    if pa is None or pb is None:
        return False
    try:
        return pa.samefile(pb)
    except OSError:
        return pa == pb


def default_patch_output(work_binary: str) -> str:
    p = Path(work_binary)
    stem = p.name
    while stem.endswith(".patched"):
        stem = stem[: -len(".patched")]
    return str(p.parent / f"{stem}.patched")


def resolve_work_binary_path(
    val: Optional[str],
    *,
    work_binary: str,
    original_binary: str,
) -> Optional[str]:
    """Map model-supplied paths to existing workspace files (handles missing .argus-work paths)."""
    if not val:
        return val
    p = Path(val)
    work = Path(work_binary)
    orig = Path(original_binary)
    if p.is_file():
        return str(p.resolve())
    # Only remap workspace-ish paths — not arbitrary missing absolute paths.
    if p.is_absolute() and p.name not in (work.name, orig.name) and not p.name.endswith(".patched"):
        return str(val)
    candidates = [
        work,
        work.parent / p.name,
        Path(default_patch_output(str(work))),
        work.parent / f"{work.name}.patched",
    ]
    if p.name.endswith(".patched"):
        candidates.insert(0, work.parent / p.name)
    for c in candidates:
        if c.is_file():
            return str(c.resolve())
    if p.name in (work.name, orig.name) and work.is_file():
        return str(work.resolve())
    return str(val)


def rewrite_tool_paths(arguments: Dict[str, Any], *, work_binary: str, original_binary: str) -> Dict[str, Any]:
    """Route tool I/O to the work copy; block writes to the original."""
    args = dict(arguments)
    work = _resolve(work_binary)
    orig = _resolve(original_binary)
    if work is None or orig is None:
        return args

    for key in ("binary", "module"):
        val = args.get(key)
        if not val:
            continue
        p = _resolve(str(val))
        if p is None:
            continue
        try:
            if p.samefile(orig) or p.samefile(work):
                args[key] = str(work)
                continue
        except OSError:
            if p == orig or p == work:
                args[key] = str(work)
                continue
        resolved = resolve_work_binary_path(str(val), work_binary=str(work), original_binary=str(orig))
        if resolved:
            args[key] = resolved

    out = args.get("output")
    if out:
        po = _resolve(str(out))
        if po is not None:
            try:
                if po.samefile(orig):
                    args["output"] = default_patch_output(str(work))
            except OSError:
                if po == orig:
                    args["output"] = default_patch_output(str(work))
    return args


def assert_not_original_target(path: Optional[str], original_binary: str) -> Optional[str]:
    """Return error message if path is the original binary (write target)."""
    if not path or not original_binary:
        return None
    if is_same_file(path, original_binary):
        return (
            "refused: cannot write to original binary — use work copy "
            f"({original_binary} is read-only for the agent)"
        )
    return None


def assert_not_install_write(path: Optional[str], original_binary: str) -> Optional[str]:
    """Refuse writes into the install directory (except workspace subdirs)."""
    if not path or not original_binary:
        return None
    p = _resolve(path)
    orig = _resolve(original_binary)
    if p is None or orig is None:
        return None
    if is_same_file(str(p), original_binary):
        return assert_not_original_target(str(p), original_binary)
    install = orig.parent
    try:
        if p.is_relative_to(install):
            name = p.name.lower()
            if name.startswith(".argus") or name.startswith(".sandbox_"):
                return None
            if p.parent.name == ".argus-work":
                return None
            return (
                f"refused: cannot write into install directory ({install}) — "
                "use workspace cache or .argus-work"
            )
    except (AttributeError, ValueError):
        if str(p).startswith(str(install) + os.sep):
            return f"refused: cannot write into install directory ({install})"
    return None


def exec_workspace_dir(work_binary: str) -> Path:
    """Writable directory for argus_exec scripts (never install dir)."""
    work = Path(work_binary).resolve()
    d = work.parent / ".argus-exec"
    d.mkdir(parents=True, exist_ok=True)
    return d
