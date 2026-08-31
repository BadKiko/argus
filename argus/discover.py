from __future__ import annotations

"""Discover target binaries and related DLL/SO modules (universal, no vendor recipes)."""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

# Reuse the same generic needle classes as license slice (imported lazily to avoid cycles)
_PATH_RX = re.compile(
    r"(?P<p>"
    r"(?:[A-Za-z]:[\\/]|/)(?:[\w.-]+[\\/])*[\w.-]+"
    r"|(?:\.{1,2}[\\/])(?:[\w.-]+[\\/])*[\w.-]+"
    r"|(?:[\w.-]+[\\/])*[\w.-]+\.(?:exe|dll|so|bin|elf|dylib)[\w.-]*"
    r")"
)

_DIR_RX = re.compile(r"(?P<d>(?:[A-Za-z]:[\\/]|/)(?:[\w.-]+[\\/])*[\w.-]+)")

_SYSTEM_DLL = {
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "ws2_32.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
    "vcruntime140.dll",
    "msvcp140.dll",
    "combase.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "shlwapi.dll",
    "imm32.dll",
    "winmm.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "version.dll",
}

_SYSTEM_SO = {
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "librt.so.1",
    "libpthread.so.0",
    "ld-linux-x86-64.so.2",
    "libgcc_s.so.1",
    "libstdc++.so.6",
    "libglib-2.0.so.0",
    "libgobject-2.0.so.0",
    "libgtk-3.so.0",
    "libgdk-3.so.0",
    "libX11.so.6",
    "libxcb.so.1",
}


def _needle_bytes() -> List[bytes]:
    from argus.find_slice import _UI_SUBS, _VALIDATE_SUBS

    return list(_VALIDATE_SUBS) + list(_UI_SUBS)


def is_binary_file(path: Path) -> bool:
    try:
        if not path.is_file() or path.stat().st_size < 64:
            return False
        with path.open("rb") as f:
            mag = f.read(4)
        if mag[:4] == b"\x7fELF":
            return True
        if mag[:2] == b"MZ":
            return True
        name = path.name.lower()
        if name.endswith(".dll") or ".so" in name or name.endswith(".dylib"):
            # still require magic when possible
            return mag[:4] == b"\x7fELF" or mag[:2] == b"MZ"
    except OSError:
        return False
    return False


def signal_score(path: Path | str, *, max_read: int = 8_000_000) -> int:
    """Cheap score: count of generic license/UI needle hits in file bytes."""
    p = Path(path)
    try:
        data = p.read_bytes()[:max_read]
    except OSError:
        return 0
    score = 0
    for n in _needle_bytes():
        if len(n) < 4:
            continue
        c = data.count(n)
        if c:
            score += c * max(1, len(n) // 4)
    return score


def extract_paths_from_text(text: str) -> List[str]:
    """Pull candidate filesystem paths from free-form prompt text."""
    out: List[str] = []
    seen: set[str] = set()
    for m in _PATH_RX.finditer(text or ""):
        raw = m.group("p").rstrip(".,;:)")
        if len(raw) < 3:
            continue
        # expand ~
        cand = os.path.expanduser(raw)
        if cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
    return out


def extract_dirs_from_text(text: str) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for m in _DIR_RX.finditer(text or ""):
        d = m.group("d").rstrip("/")
        if d in seen or len(d) < 2:
            continue
        if Path(d).is_dir():
            seen.add(d)
            out.append(d)
    return out


def scan_binaries(root: Path, *, max_depth: int = 2, limit: int = 40) -> List[Path]:
    """Find ELF/PE under root up to max_depth."""
    root = root.resolve()
    found: List[Path] = []
    if not root.is_dir():
        return found
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        p = Path(dirpath)
        depth = len(p.parts) - root_depth
        if depth > max_depth:
            dirnames[:] = []
            continue
        # skip huge / noise trees
        dirnames[:] = [
            d
            for d in dirnames
            if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}
        ]
        for name in filenames:
            fp = p / name
            if is_binary_file(fp):
                found.append(fp)
                if len(found) >= limit:
                    return found
    return found


def _is_system_dep(name: str) -> bool:
    low = name.lower()
    base = Path(low).name
    if base in _SYSTEM_DLL or base in _SYSTEM_SO:
        return True
    if base.startswith("api-ms-win-") or base.startswith("ext-ms-"):
        return True
    if base.startswith("lib") and base.endswith(".so.6") and "license" not in base:
        # keep non-generic; already covered common libs above
        pass
    return False


def list_dependency_names(path: Path | str) -> List[str]:
    p = Path(path)
    try:
        with p.open("rb") as f:
            mag = f.read(4)
    except OSError:
        return []
    try:
        if mag[:4] == b"\x7fELF":
            from argus.binary.elf import list_elf_needed

            return list_elf_needed(p)
        if mag[:2] == b"MZ":
            from argus.binary.pe import list_pe_dependent_dlls

            return list_pe_dependent_dlls(p)
    except Exception:
        return []
    return []


def resolve_dependency(primary: Path, dep_name: str) -> Optional[Path]:
    """Resolve DLL/SO name next to primary, then a few common lib dirs."""
    if _is_system_dep(dep_name):
        return None
    base = Path(dep_name).name
    siblings = [
        primary.parent / base,
        primary.parent / dep_name,
    ]
    for c in siblings:
        if c.is_file() and is_binary_file(c):
            return c.resolve()
    # ELF: try unversioned
    if ".so" in base:
        for c in primary.parent.glob(base.split(".so")[0] + ".so*"):
            if c.is_file() and is_binary_file(c) and not _is_system_dep(c.name):
                return c.resolve()
    extra = [
        Path("/usr/lib"),
        Path("/usr/lib/x86_64-linux-gnu"),
        Path("/lib/x86_64-linux-gnu"),
    ]
    for d in extra:
        c = d / base
        if c.is_file() and is_binary_file(c) and not _is_system_dep(base):
            # Prefer non-system only — skip if denylisted
            return None  # never pull system libs from /usr for patching
    return None


def sibling_modules(primary: Path, *, limit: int = 24) -> List[Path]:
    """Same-directory PE DLL / ELF SO siblings (non-system)."""
    out: List[Path] = []
    parent = primary.parent
    if not parent.is_dir():
        return out
    for fp in sorted(parent.iterdir()):
        if not fp.is_file() or fp.resolve() == primary.resolve():
            continue
        name = fp.name.lower()
        if not (name.endswith(".dll") or ".so" in name or name.endswith(".dylib")):
            continue
        if _is_system_dep(fp.name):
            continue
        if is_binary_file(fp):
            out.append(fp.resolve())
        if len(out) >= limit:
            break
    return out


def sibling_binaries(primary: Path, *, limit: int = 40) -> List[Path]:
    """Any ELF/PE in the same directory (not only .dll/.so)."""
    out: List[Path] = []
    parent = primary.parent
    if not parent.is_dir():
        return out
    for fp in sorted(parent.iterdir()):
        if not fp.is_file() or fp.resolve() == primary.resolve():
            continue
        if _is_system_dep(fp.name):
            continue
        if is_binary_file(fp):
            out.append(fp.resolve())
        if len(out) >= limit:
            break
    return out


def is_workspace_cache_path(path: Path | str) -> bool:
    s = str(path).replace("\\", "/")
    return "/.cache/argus/workspaces/" in s or "/.argus-work/" in s


def resolve_link_base(primary: str | Path, install_root: Optional[str] = None) -> Path:
    """Map workspace work copy back to install-dir binary for sibling/linked scans."""
    prim = Path(primary).resolve()
    if install_root and is_workspace_cache_path(prim):
        alt = Path(install_root) / prim.name
        if alt.is_file():
            return alt.resolve()
    return prim


def merge_install_discover(
    info: Dict[str, Any],
    install_root: str,
    *,
    binary: Optional[str] = None,
) -> Dict[str, Any]:
    """Attach install-dir candidates/linked (work copy lives in cache, modules do not)."""
    root = Path(install_root)
    if not root.is_dir():
        return info
    link = resolve_link_base(binary or info.get("primary") or "", install_root)
    extra = discover_targets("", root=str(root), binary=str(link) if link.is_file() else None)
    out = dict(info)
    out["install_dir"] = str(root)
    by_path: Dict[str, Dict[str, Any]] = {}
    for c in (out.get("candidates") or []) + (extra.get("candidates") or []):
        p = c.get("path")
        if p:
            by_path[p] = c
    out["candidates"] = sorted(
        by_path.values(),
        key=lambda x: (-int(x.get("score") or 0), str(x.get("name") or "").lower()),
    )[:20]
    by_link: Dict[str, Dict[str, Any]] = {}
    for m in (out.get("linked") or []) + (extra.get("linked") or []):
        p = m.get("path")
        if p:
            by_link[p] = m
    out["linked"] = sorted(
        by_link.values(),
        key=lambda x: (-int(x.get("score") or 0), str(x.get("name") or "").lower()),
    )[:12]
    scored = [c for c in out["candidates"] if int(c.get("score") or 0) > 0]
    if scored:
        out["install_modules_hint"] = [c["path"] for c in scored[:8]]
    return out


def widen_modules(
    primary: str | Path,
    *,
    tried: Optional[Sequence[str]] = None,
    limit: int = 12,
    root: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    When primary/linked slice is empty: expand search to nearby binaries
    (same-dir ELF/PE, linked deps, shallow scan of install dir), ranked by needles.
    """
    prim = resolve_link_base(primary, root)
    tried_set: Set[str] = {str(Path(t).resolve()) for t in (tried or []) if t}
    tried_set.add(str(prim))
    tried_set.add(str(Path(primary).resolve()))

    pool: List[Path] = []
    pool.extend(sibling_binaries(prim, limit=40))
    pool.extend(linked_modules(prim, limit=16))
    scan_root = Path(root) if root else prim.parent
    if scan_root.is_dir():
        pool.extend(scan_binaries(scan_root, max_depth=2, limit=40))

    ranked: List[Tuple[int, Path]] = []
    seen: Set[str] = set()
    for p in pool:
        key = str(p.resolve())
        if key in tried_set or key in seen:
            continue
        if not p.is_file() or not is_binary_file(p):
            continue
        seen.add(key)
        ranked.append((signal_score(p), p.resolve()))

    ranked.sort(key=lambda t: (-t[0], t[1].name.lower()))
    # Prefer score>0; if none, still return a few nearby binaries to try
    positive = [(s, p) for s, p in ranked if s > 0]
    pick = positive[:limit] if positive else ranked[: min(limit, 6)]
    return [{"path": str(p), "score": s, "name": p.name} for s, p in pick]


def linked_modules(primary: Path | str, *, limit: int = 16) -> List[Path]:
    """Dependency modules resolved on disk + same-dir siblings, ranked later by caller."""
    prim = Path(primary).resolve()
    found: List[Path] = []
    seen: Set[str] = {str(prim)}
    for dep in list_dependency_names(prim):
        resolved = resolve_dependency(prim, dep)
        if resolved is None:
            continue
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        found.append(resolved)
        if len(found) >= limit:
            break
    for sib in sibling_modules(prim, limit=limit):
        key = str(sib)
        if key in seen:
            continue
        seen.add(key)
        found.append(sib)
        if len(found) >= limit * 2:
            break
    return found


def _is_library_name(name: str) -> bool:
    n = name.lower()
    return n.startswith("lib") or ".so" in n or n.endswith((".dll", ".dylib"))


def _pick_primary(ranked: Sequence[Tuple[int, Path]]) -> Optional[Path]:
    """Prefer main app binary over .so/.dll when license scores are close."""
    if not ranked:
        return None
    top_score = ranked[0][0]
    if top_score <= 0:
        return ranked[0][1]
    threshold = max(1, int(top_score * 0.85))
    pool = [(sc, p) for sc, p in ranked if sc >= threshold]

    def sort_key(item: Tuple[int, Path]) -> Tuple[int, int, int, str]:
        sc, p = item
        name = p.name
        is_lib = _is_library_name(name)
        try:
            app_like = os.access(p, os.X_OK) and not is_lib
        except OSError:
            app_like = False
        return (1 if app_like else 0, sc, -1 if is_lib else 0, name.lower())

    pool.sort(key=sort_key, reverse=True)
    return pool[0][1]


def discover_targets(
    prompt: str = "",
    *,
    root: Optional[str] = None,
    binary: Optional[str] = None,
    max_linked: int = 8,
) -> Dict[str, Any]:
    """
    Discover primary binary + related modules.

    Order: explicit binary arg → paths in prompt → scan root/cwd.
    """
    candidates: List[Dict[str, Any]] = []
    seeds: List[Path] = []

    if binary and Path(binary).is_file():
        seeds.append(resolve_link_base(binary, root).resolve())

    for raw in extract_paths_from_text(prompt):
        p = Path(raw)
        if p.is_file() and is_binary_file(p):
            seeds.append(p.resolve())
        elif p.is_dir():
            seeds.extend(scan_binaries(p, max_depth=2, limit=40))

    scan_roots: List[Path] = []
    if root:
        scan_roots.append(Path(root))
    for d in extract_dirs_from_text(prompt):
        scan_roots.append(Path(d))
    if not seeds:
        scan_roots.append(Path(root) if root else Path.cwd())

    for r in scan_roots:
        if r.is_dir():
            seeds.extend(scan_binaries(r, max_depth=2, limit=40))

    # Dedup + score
    seen: Set[str] = set()
    ranked: List[Tuple[int, Path]] = []
    for s in seeds:
        key = str(s.resolve()) if s.exists() else str(s)
        if key in seen:
            continue
        if not s.is_file() or not is_binary_file(s):
            continue
        seen.add(key)
        scored = signal_score(s)
        ranked.append((scored, s.resolve()))

    ranked.sort(key=lambda t: (-t[0], t[1].name.lower()))
    for score, path in ranked:
        candidates.append(
            {
                "path": str(path),
                "score": score,
                "name": path.name,
            }
        )

    picked = _pick_primary(ranked)
    primary = str(picked) if picked else None
    linked: List[Dict[str, Any]] = []
    link_base = resolve_link_base(primary, root) if primary else None
    if link_base and link_base.is_file():
        for mod in linked_modules(link_base, limit=max_linked * 2):
            sc = signal_score(mod)
            linked.append({"path": str(mod), "score": sc, "name": Path(mod).name})
        linked.sort(key=lambda x: (-int(x["score"]), x["name"]))
        # Prefer modules that actually look license-related for unlock expansion
        linked = [m for m in linked if int(m["score"]) > 0][:max_linked] or linked[:max_linked]

    return {
        "ok": bool(primary),
        "summary": (
            f"discover primary={primary or 'none'} candidates={len(candidates)} "
            f"linked={len(linked)}"
        ),
        "primary": primary,
        "candidates": candidates[:20],
        "linked": linked,
        "next_hint": (
            f"Use binary={primary}; related modules listed in linked[] for argus_slice / apply_plan"
            if primary
            else "No ELF/PE found — pass a path or run from a directory containing the binary"
        ),
    }
