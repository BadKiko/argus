from __future__ import annotations

"""Host vs payload classification, archive index, and text-IR gates.

Universal: magic and install layout only — no product names. Agent tools stay
discover / find / atlas / diagnose_failure / apply_plan.
"""

import io
import json
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_ASSET_DIR_NAMES = ("Packages", "resources", "Resources", "lib", "plugins", "share", "data")
_HOST_SIBLING_NAMES = frozenset(
    {
        "chrome-sandbox",
        "chrome_crashpad_handler",
        "libnode.so",
    }
)
_HOST_SONAME_MARKERS = ("libnode", "electron", "libchromium")
_TEXT_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".json", ".jsx", ".vue", ".py", ".lua"})
_ARCHIVE_SUFFIXES = frozenset({".asar", ".zip", ".jar", ".pak"})
_PATH_IN_ELF = re.compile(
    rb"(?:(?:resources|Resources|lib|share|data)/[\w./+-]+\.(?:asar|js|mjs|json|jar|zip|pak))"
    rb"|(?:[\w./+-]+\.asar)"
)
_IF_RX = re.compile(
    rb"if\s*\(\s*(!?)\s*([\w.$]+)\s*\)",
)
_RETURN_BOOL_RX = re.compile(
    rb"return\s+(false|true|!0|!1)\s*;",
    re.IGNORECASE,
)
_TERNARY_RX = re.compile(
    rb"([\w.$]+)\s*\?\s*([\w.'\"]+)\s*:\s*([\w.'\"]+)",
)

_LISTING_CAP = 30
_SIDECAR_CAP = 16
_STRING_SCAN = 4_000_000
_KIND_WEIGHT = {
    "archive": 400,
    "text": 250,
    "host": 40,
    "native": 50,
    "unknown": 10,
}
# Legal dumps, GPU, Chromium helpers — not product payloads.
_DEMOTE_NAME_RX = re.compile(
    r"(?i)(?:^|/)(LICENSE|LICENSES|COPYING|NOTICE|CREDITS)(?:[. _]|$)|"
    r"LICENSES\.|LICENSE\.|"
    r"chrome-sandbox|chrome_crashpad|"
    r"libGLES|libEGL|libvulkan|libGL\.so"
)
_ENGINE_NEEDLES = (
    "origintrial",
    "origin-trial",
    "origin_trial",
    ".license.txt",
    "license.txt */",
    "blink.mojom",
    "fieldtrial",
    "field-trial",
)


def looks_host_engine_string(preview: str) -> bool:
    """Chromium/runtime engine strings — not product UI."""
    p = (preview or "").lower().replace("_", "")
    compact = p.replace("-", "")
    for n in _ENGINE_NEEDLES:
        if n.replace("-", "").replace("_", "") in compact or n in p:
            return True
    return False


def sniff_magic(path: Path | str, *, head: Optional[bytes] = None) -> str:
    p = Path(path)
    try:
        raw = head if head is not None else p.read_bytes()[:64]
    except OSError:
        return "unknown"
    if len(raw) >= 4 and raw[:4] == b"\x7fELF":
        return "elf"
    if len(raw) >= 2 and raw[:2] == b"MZ":
        return "pe"
    if len(raw) >= 4 and raw[:2] == b"PK":
        return "zip"
    if _asar_header_ok(raw, p):
        return "asar"
    if raw[:2] == b"#!":
        return "shebang"
    if _looks_text_bytes(raw):
        return "text"
    name = p.name.lower()
    if name.endswith(".asar"):
        return "asar"
    if any(name.endswith(s) for s in _TEXT_SUFFIXES):
        return "text"
    return "unknown"


def _looks_text_bytes(raw: bytes) -> bool:
    if not raw or raw[:1] in (b"\x00", b"\x7f"):
        return False
    sample = raw[:256]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _asar_header_ok(head: bytes, path: Path) -> bool:
    if path.suffix.lower() == ".asar":
        return True
    if len(head) < 16:
        return False
    pickle_size = struct.unpack_from("<I", head, 0)[0]
    if pickle_size < 8 or pickle_size > 50_000_000:
        return False
    json_size = struct.unpack_from("<I", head, 4)[0]
    if json_size < 8 or json_size > pickle_size:
        return False
    return head[8:16].lstrip().startswith(b"{")


def _elf_arch(path: Path) -> str:
    try:
        with path.open("rb") as f:
            ident = f.read(20)
        if ident[:4] != b"\x7fELF" or len(ident) < 20:
            return ""
        endian = "<" if ident[5] == 1 else ">"
        machine = struct.unpack_from(endian + "H", ident, 18)[0]
        return {3: "x86", 62: "x86_64"}.get(machine, f"em_{machine}")
    except OSError:
        return ""


def classify_path(path: Path | str) -> Dict[str, Any]:
    p = Path(path)
    size = 0
    try:
        size = int(p.stat().st_size) if p.is_file() else 0
    except OSError:
        pass
    magic = sniff_magic(p) if p.is_file() else "unknown"
    execution = "native"
    payload_ir = "native"
    if magic in ("elf", "pe"):
        if _host_runtime_layout(p):
            execution = "host_runtime"
            payload_ir = "text"
            payloads = list_payload_modules(p)
            if any(x.get("kind") == "archive" for x in payloads):
                payload_ir = "archive"
        else:
            execution = "native"
            payload_ir = "native"
    elif magic in ("zip", "asar"):
        execution = "archive"
        payload_ir = "archive"
    elif magic in ("shebang", "text"):
        execution = "interpreted_text"
        payload_ir = "text"
    else:
        execution = "native"
        payload_ir = "native"
    return {
        "path": str(p.resolve()) if p.exists() else str(p),
        "name": p.name,
        "size": size,
        "magic": magic,
        "arch": _elf_arch(p) if magic == "elf" else "",
        "execution": execution,
        "payload_ir": payload_ir,
        "kind": _kind_from_magic(magic, execution),
    }


def _kind_from_magic(magic: str, execution: str) -> str:
    if execution == "host_runtime":
        return "host"
    if magic in ("zip", "asar"):
        return "archive"
    if magic in ("shebang", "text"):
        return "text"
    if magic in ("elf", "pe"):
        return "native"
    return magic or "unknown"


def _host_runtime_layout(primary: Path) -> bool:
    parent = primary.parent
    if not parent.is_dir():
        return False
    try:
        names = {c.name.lower() for c in parent.iterdir()}
    except OSError:
        names = set()
    if names & {n.lower() for n in _HOST_SIBLING_NAMES}:
        return True
    if "license.electron" in names:
        return True
    for res_name in ("resources", "Resources"):
        res = parent / res_name
        if res.is_dir():
            try:
                if any(c.suffix.lower() == ".asar" for c in res.iterdir() if c.is_file()):
                    return True
            except OSError:
                pass
    try:
        from argus.discover import list_dependency_names

        for dep in list_dependency_names(primary):
            low = (dep or "").lower()
            if any(m in low for m in _HOST_SONAME_MARKERS):
                return True
    except Exception:
        pass
    return False


def is_payload_file(path: Path | str) -> bool:
    p = Path(path)
    if not p.is_file():
        return False
    try:
        if is_patch_artifact_name(p.name):
            return False
    except Exception:
        pass
    magic = sniff_magic(p)
    if magic in ("asar", "zip", "text", "shebang"):
        return True
    name = p.name.lower()
    if any(name.endswith(s) for s in _TEXT_SUFFIXES | _ARCHIVE_SUFFIXES):
        return True
    return False


def is_patch_artifact_name(name: str) -> bool:
    from argus.discover import is_patch_artifact

    return is_patch_artifact(name)


def sibling_payloads(primary: Path | str, *, limit: int = 24) -> List[Path]:
    """Sidecar archives and text bundles next to / under the primary install."""
    prim = Path(primary).resolve()
    parent = prim.parent
    out: List[Path] = []
    seen: set[str] = {str(prim)}

    def _add(fp: Path) -> None:
        if not fp.is_file():
            return
        key = str(fp.resolve())
        if key in seen or key == str(prim):
            return
        if is_patch_artifact_name(fp.name):
            return
        if is_payload_file(fp):
            seen.add(key)
            out.append(fp.resolve())

    if parent.is_dir():
        try:
            for fp in sorted(parent.iterdir()):
                _add(fp)
                if len(out) >= limit:
                    return out[:limit]
        except OSError:
            pass
        for dname in _ASSET_DIR_NAMES:
            d = parent / dname
            if not d.is_dir():
                continue
            try:
                for fp in sorted(d.rglob("*")):
                    if not fp.is_file():
                        continue
                    _add(fp)
                    if len(out) >= limit:
                        return out[:limit]
            except OSError:
                continue
    for hop in _string_sidecar_hops(prim):
        _add(hop)
        if len(out) >= limit:
            break
    return out[:limit]


def _string_sidecar_hops(primary: Path) -> List[Path]:
    out: List[Path] = []
    try:
        blob = primary.read_bytes()[:_STRING_SCAN]
    except OSError:
        return out
    parent = primary.parent
    seen: set[str] = set()
    for m in _PATH_IN_ELF.finditer(blob):
        rel = m.group(0).decode("utf-8", errors="ignore").lstrip("./")
        if not rel or rel in seen:
            continue
        seen.add(rel)
        cand = parent / rel
        if cand.is_file():
            out.append(cand.resolve())
    return out[:12]


def demote_observe_name(name: str) -> bool:
    """True for legal/engine sidecars that drown payload ranking."""
    n = name or ""
    if _DEMOTE_NAME_RX.search(n):
        return True
    low = n.lower()
    if low.endswith((".html", ".htm", ".md", ".txt")) and "license" in low:
        return True
    return False


def observe_rank(row: Dict[str, Any]) -> int:
    """Prefer large archives/text over native GPU libs and LICENSE* files.

    signal_score only reads the first 8MB, so a 300MB asar often scores 0.
    """
    name = str(row.get("name") or Path(str(row.get("path") or "")).name)
    kind = str(row.get("kind") or "unknown")
    try:
        size = int(row.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    try:
        score = int(row.get("score") or 0)
    except (TypeError, ValueError):
        score = 0
    w = int(_KIND_WEIGHT.get(kind, 10))
    if kind == "archive":
        w += min(80, size // (512 * 1024))
    elif kind == "text":
        w += min(20, size // (64 * 1024))
    if demote_observe_name(name):
        w -= 300
    return w * 10_000 + min(max(score, 0), 999) * 10 + min(size // (1024 * 1024), 99)


def rank_observe_modules(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort modules for 'look here first'; pin archives; drop demoted names from the top."""
    items = [dict(r) for r in rows if r]
    items.sort(
        key=lambda r: (-observe_rank(r), str(r.get("name") or "").lower()),
    )
    return items


def prefer_observe_linked(
    rows: Sequence[Dict[str, Any]],
    *,
    cap: int = 8,
) -> List[Dict[str, Any]]:
    """Pin archive/text payloads first; drop LICENSE*/GPU names from the top of linked[]."""
    ranked = rank_observe_modules(rows)
    archives = [
        m
        for m in ranked
        if str(m.get("kind") or "") in ("archive", "text")
        and not demote_observe_name(str(m.get("name") or Path(str(m.get("path") or "")).name))
    ]
    arch_paths = {str(m.get("path") or "") for m in archives}
    rest = [
        m
        for m in ranked
        if str(m.get("path") or "") not in arch_paths
        and not demote_observe_name(str(m.get("name") or Path(str(m.get("path") or "")).name))
    ]
    scored = [m for m in rest if int(m.get("score") or 0) > 0]
    seen: set[str] = set()
    ordered: List[Dict[str, Any]] = []
    for m in archives + scored:
        pth = str(m.get("path") or "")
        if not pth or pth in seen:
            continue
        seen.add(pth)
        ordered.append(m)
        if len(ordered) >= cap:
            break
    return ordered or ranked[:cap]


def list_payload_modules(primary: Path | str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for fp in sibling_payloads(primary):
        cls = classify_path(fp)
        rows.append(
            {
                "path": str(fp),
                "name": fp.name,
                "score": _payload_signal_score(fp),
                "kind": cls["kind"],
                "magic": cls["magic"],
                "size": cls["size"],
            }
        )
    return rank_observe_modules(rows)[:_SIDECAR_CAP]


def _payload_signal_score(path: Path) -> int:
    from argus.discover import signal_score

    return signal_score(path)


def list_install_entries(install: Path, *, cap: int = _LISTING_CAP) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not install.is_dir():
        return rows
    files: List[Path] = []
    try:
        for fp in install.iterdir():
            if fp.is_file():
                files.append(fp)
            elif fp.is_dir() and fp.name in _ASSET_DIR_NAMES:
                try:
                    files.extend(c for c in fp.rglob("*") if c.is_file())
                except OSError:
                    pass
    except OSError:
        return rows
    files.sort(key=lambda p: (-_safe_size(p), p.name.lower()))
    for fp in files[:cap]:
        magic = sniff_magic(fp)
        rows.append(
            {
                "name": str(fp.relative_to(install)) if _is_relative(fp, install) else fp.name,
                "path": str(fp.resolve()),
                "size": _safe_size(fp),
                "kind": _kind_from_magic(magic, "native"),
                "magic": magic,
            }
        )
    return rows


def _is_relative(fp: Path, root: Path) -> bool:
    try:
        fp.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_size(p: Path) -> int:
    try:
        return int(p.stat().st_size)
    except OSError:
        return 0


def list_archive_entries(path: Path | str) -> List[Dict[str, Any]]:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError:
        return []
    magic = sniff_magic(p, head=data[:64])
    if magic == "zip":
        return _zip_entries(data)
    if magic == "asar":
        return _asar_entries(data)
    return []


def _zip_entries(data: bytes) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return out
    for info in zf.infolist()[:200]:
        if info.is_dir():
            continue
        out.append(
            {
                "inner": info.filename,
                "offset": int(info.header_offset),
                "size": int(info.file_size),
                "compress_size": int(info.compress_size),
            }
        )
    return out


def _asar_entries(data: bytes) -> List[Dict[str, Any]]:
    header_end, tree = _asar_tree(data)
    if tree is None:
        return []
    files = tree.get("files") or {}
    out: List[Dict[str, Any]] = []

    def walk(node: Dict[str, Any], prefix: str) -> None:
        for name, rec in (node or {}).items():
            if not isinstance(rec, dict):
                continue
            rel = f"{prefix}/{name}" if prefix else name
            if "files" in rec:
                walk(rec.get("files") or {}, rel)
                continue
            try:
                off = int(rec.get("offset") or 0)
                size = int(rec.get("size") or 0)
            except (TypeError, ValueError):
                continue
            out.append(
                {
                    "inner": rel,
                    "offset": header_end + off,
                    "size": size,
                    "rel_offset": off,
                }
            )

    walk(files, "")
    return out


def _asar_tree(data: bytes) -> Tuple[int, Optional[Dict[str, Any]]]:
    if len(data) < 16:
        return 0, None
    pickle_size = struct.unpack_from("<I", data, 0)[0]
    json_size = struct.unpack_from("<I", data, 4)[0]
    if 8 + json_size <= len(data) and pickle_size >= json_size + 4:
        blob = data[8 : 8 + json_size]
        header_end = 4 + pickle_size
        header_end = (header_end + 3) & ~3
        try:
            tree = json.loads(blob.decode("utf-8"))
            if isinstance(tree, dict) and "files" in tree:
                return header_end, tree
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            pass
    idx = data.find(b'{"files":')
    if idx < 0:
        return 0, None
    decoder = json.JSONDecoder()
    try:
        tree, end = decoder.raw_decode(data[idx:].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return 0, None
    header_end = idx + end
    header_end = (header_end + 3) & ~3
    if isinstance(tree, dict):
        return header_end, tree
    return 0, None


def pack_asar(files: Dict[str, bytes]) -> bytes:
    """Build a minimal asar (JSON pickle header + concatenated files)."""
    offset = 0
    tree: Dict[str, Any] = {"files": {}}
    blobs: List[bytes] = []
    for name, raw in files.items():
        parts = [p for p in name.replace("\\", "/").split("/") if p]
        node = tree["files"]
        for part in parts[:-1]:
            node = node.setdefault(part, {"files": {}})["files"]
        node[parts[-1]] = {"size": len(raw), "offset": str(offset)}
        blobs.append(raw)
        offset += len(raw)
    js = json.dumps(tree, separators=(",", ":")).encode("utf-8")
    pickle = struct.pack("<I", len(js)) + js
    header = struct.pack("<I", len(pickle)) + pickle
    pad = (4 - (len(header) % 4)) % 4
    header += b"\x00" * pad
    return header + b"".join(blobs)


def read_payload_bytes(path: Path | str, *, inner: Optional[str] = None) -> bytes:
    p = Path(path)
    data = p.read_bytes()
    if not inner:
        return data
    magic = sniff_magic(p, head=data[:64])
    if magic == "zip":
        zf = zipfile.ZipFile(io.BytesIO(data))
        return zf.read(inner)
    if magic == "asar":
        for ent in _asar_entries(data):
            if ent.get("inner") == inner:
                off = int(ent["offset"])
                size = int(ent["size"])
                return data[off : off + size]
    return data


def locate_in_bytes(data: bytes, query: str) -> Optional[Dict[str, Any]]:
    q = (query or "").strip()
    if len(q) < 3:
        return None
    needle = q.encode("utf-8", errors="replace")
    idx = data.find(needle)
    if idx < 0:
        idx = data.lower().find(needle.lower())
    if idx < 0:
        return None
    start = max(0, idx - 80)
    end = min(len(data), idx + len(needle) + 80)
    preview = data[idx : idx + min(96, len(needle) + 40)].decode("utf-8", errors="replace")
    return {
        "addr": idx,
        "kind": "utf8",
        "preview": preview.replace("\n", " ")[:96],
        "window": data[start:end],
        "window_start": start,
        "match_off": idx - start,
    }


def diagnose_text_module(
    path: Path | str,
    error_text: str,
    *,
    inner: Optional[str] = None,
) -> Dict[str, Any]:
    """C-like if/return near a string — same patch kinds, file offsets."""
    p = Path(path)
    data = read_payload_bytes(p, inner=inner)
    located = locate_in_bytes(data, error_text)
    diagnosis: Dict[str, Any] = {
        "ok": False,
        "symptom": error_text,
        "root_cause": "",
        "explanation": "",
        "corrective_patch": [],
        "ir": "text",
        "module": str(p.resolve()),
    }
    if inner:
        diagnosis["inner"] = inner
    if not located:
        diagnosis["explanation"] = f"string not in payload {p.name}"
        return diagnosis
    diagnosis["string_addr"] = hex(located["addr"])
    diagnosis["string_kind"] = "utf8"
    diagnosis["string_preview"] = located.get("preview")
    plan = _text_gates_near(data, located["addr"], p, inner=inner)
    diagnosis["corrective_patch"] = plan
    diagnosis["ok"] = bool(plan)
    if plan:
        diagnosis["root_cause"] = f"text predicate near {error_text[:40]!r} in {p.name}"
        diagnosis["explanation"] = (
            f"Payload string @ {hex(located['addr'])} in {p.name}. "
            "Apply corrective_patch (replace_string / force_branch on text IR)."
        )
    else:
        diagnosis["explanation"] = (
            f"Found {error_text[:40]!r} in payload {p.name} but no nearby if/return"
        )
    return diagnosis


def _text_gates_near(
    data: bytes,
    str_off: int,
    path: Path,
    *,
    inner: Optional[str] = None,
    window: int = 400,
) -> List[Dict[str, Any]]:
    lo = max(0, str_off - window)
    hi = min(len(data), str_off + window)
    chunk = data[lo:hi]
    plan: List[Dict[str, Any]] = []
    seen: set[int] = set()

    def add(kind: str, abs_off: int, old: bytes, new: bytes, why: str) -> None:
        if abs_off in seen:
            return
        if len(new) > len(old):
            return
        seen.add(abs_off)
        new_p = new + (b" " * (len(old) - len(new)))
        rec: Dict[str, Any] = {
            "kind": kind,
            "addr": hex(abs_off),
            "module": str(path.resolve()),
            "ir": "text",
            "old": old.decode("utf-8", errors="replace"),
            "new": new_p.decode("utf-8", errors="replace"),
            "why": why,
            "confidence": "medium",
        }
        if inner:
            rec["inner"] = inner
        if kind == "force_branch":
            rec["taken"] = True
        if kind == "ret_imm":
            rec["value"] = 1
        plan.append(rec)

    for m in _RETURN_BOOL_RX.finditer(chunk):
        tok = m.group(1).lower()
        if tok in (b"false", b"!1"):
            old = m.group(0)
            if tok == b"false":
                new = old.replace(b"false", b"true ")
            else:
                new = old.replace(b"!1", b"!0")
            add("ret_imm", lo + m.start(), old, new, "force return true near payload string")
    for m in _IF_RX.finditer(chunk):
        bang = m.group(1)
        name = m.group(2)
        old = m.group(0)
        if bang:
            new = b"if ( " + name + b" )"
            if len(new) != len(old):
                new = old.replace(b"if (!", b"if ( ", 1)
                if new == old:
                    continue
            add("force_branch", lo + m.start(), old, new, "invert if (!) near payload string")
        else:
            # if (ok) → if (1)
            if len(name) >= 1:
                new = b"if (" + (b"1" + b" " * (len(name) - 1)) + b")"
                if len(new) == len(old):
                    add("force_branch", lo + m.start(), old, new, "force if predicate true")
    for m in _TERNARY_RX.finditer(chunk):
        old = m.group(0)
        # keep same length: cond ? a : b → 1 ? a : b padded
        cond = m.group(1)
        rest = old[len(cond) :]
        new = b"1" + (b" " * (len(cond) - 1)) + rest if len(cond) >= 1 else old
        if new != old and len(new) == len(old):
            add("force_branch", lo + m.start(), old, new, "force ternary true")
    return plan[:6]


def apply_text_step(path: str, step: Dict[str, Any]) -> Tuple[bool, str]:
    """Same-length splice in a text file or archive blob. Rebuild if length changes."""
    p = Path(path)
    try:
        data = bytearray(p.read_bytes())
    except OSError as e:
        return False, str(e)
    old = (step.get("old") or "").encode("utf-8", errors="replace")
    new = (step.get("new") or "").encode("utf-8", errors="replace")
    inner = step.get("inner")
    addr = _parse_off(step.get("addr"))
    if inner:
        return _apply_inner(p, bytes(data), step)
    if old and new:
        if len(new) < len(old):
            new = new + b" " * (len(old) - len(new))
        if addr is not None and addr + len(old) <= len(data) and bytes(data[addr : addr + len(old)]) == old:
            if len(new) != len(old):
                data[addr : addr + len(old)] = new
            else:
                data[addr : addr + len(old)] = new
            p.write_bytes(bytes(data))
            return True, "text splice"
        idx = bytes(data).find(old)
        if idx < 0:
            return False, "old bytes not found"
        if len(new) != len(old):
            data[idx : idx + len(old)] = new
        else:
            data[idx : idx + len(old)] = new
        p.write_bytes(bytes(data))
        return True, "text splice"
    if addr is None:
        return False, "addr required"
    return False, "no old/new for text step"


def _apply_inner(path: Path, data: bytes, step: Dict[str, Any]) -> Tuple[bool, str]:
    inner = str(step.get("inner") or "")
    old = (step.get("old") or "").encode("utf-8", errors="replace")
    new = (step.get("new") or "").encode("utf-8", errors="replace")
    if len(new) < len(old):
        new = new + b" " * (len(old) - len(new))
    magic = sniff_magic(path, head=data[:64])
    if magic == "asar" and old and len(new) == len(old):
        blob = bytearray(data)
        idx = bytes(blob).find(old)
        if idx < 0:
            return False, "old bytes not in archive"
        blob[idx : idx + len(old)] = new
        path.write_bytes(bytes(blob))
        return True, "asar same-length splice"
    if magic == "zip":
        return _zip_replace_member(path, data, inner, old, new)
    if magic == "asar" and old and len(new) != len(old):
        return _asar_rebuild_replace(path, data, inner, old, new)
    if old and len(new) == len(old):
        blob = bytearray(data)
        idx = bytes(blob).find(old)
        if idx < 0:
            return False, "old bytes not in blob"
        blob[idx : idx + len(old)] = new
        path.write_bytes(bytes(blob))
        return True, "blob splice"
    return False, "archive replace failed"


def _zip_replace_member(
    path: Path, data: bytes, inner: str, old: bytes, new: bytes
) -> Tuple[bool, str]:
    try:
        zin = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile:
        return False, "bad zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for info in zin.infolist():
            payload = zin.read(info.filename)
            if inner and info.filename == inner and old:
                payload = payload.replace(old, new, 1)
            elif not inner and old and old in payload:
                payload = payload.replace(old, new, 1)
            zout.writestr(info, payload)
    path.write_bytes(buf.getvalue())
    return True, "zip member replace"


def _asar_rebuild_replace(
    path: Path, data: bytes, inner: str, old: bytes, new: bytes
) -> Tuple[bool, str]:
    entries = _asar_entries(data)
    files: Dict[str, bytes] = {}
    for ent in entries:
        name = str(ent.get("inner") or "")
        off = int(ent["offset"])
        size = int(ent["size"])
        chunk = data[off : off + size]
        if name == inner or (not inner and old in chunk):
            chunk = chunk.replace(old, new, 1)
        files[name] = chunk
    if not files:
        return False, "empty asar"
    path.write_bytes(pack_asar(files))
    return True, "asar rebuild"


def _parse_off(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    try:
        return int(str(raw), 0)
    except (TypeError, ValueError):
        return None


def scan_payload_strings(path: Path | str, query: str, *, limit: int = 20) -> List[Dict[str, Any]]:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError:
        return []
    q = (query or "").strip()
    if len(q) < 3:
        return []
    needle = q.encode("utf-8", errors="replace")
    hits: List[Dict[str, Any]] = []
    start = 0
    low = data.lower()
    nlow = needle.lower()
    magic = sniff_magic(p, head=data[:64])
    kind = "archive" if magic in ("asar", "zip") else "text"
    while len(hits) < limit:
        idx = low.find(nlow, start)
        if idx < 0:
            break
        end = idx
        while end < len(data) and 32 <= data[end] < 127 and end - idx < 120:
            end += 1
        preview = data[idx:end].decode("latin1", errors="replace")
        score = len(needle) * 10 + 40
        if looks_host_engine_string(preview):
            score -= 120
        hits.append(
            {
                "addr": hex(idx),
                "kind": "string",
                "preview": preview[:120],
                "needle": q,
                "score": score,
                "module": str(p.resolve()),
                "ir": kind,
                "nearby_fn": None,
            }
        )
        start = idx + max(len(needle), 1)
    inners = list_archive_entries(p) if kind == "archive" else []
    for ent in inners[:40]:
        inner = str(ent.get("inner") or "")
        if query.lower() not in inner.lower() and query.encode() not in data:
            continue
        off = int(ent.get("offset") or 0)
        size = int(ent.get("size") or 0)
        chunk = data[off : off + size]
        loc = locate_in_bytes(chunk, q)
        if not loc:
            continue
        abs_off = off + int(loc["addr"])
        if any(h.get("addr") == hex(abs_off) for h in hits):
            continue
        hits.append(
            {
                "addr": hex(abs_off),
                "kind": "string",
                "preview": loc.get("preview"),
                "needle": q,
                "score": 90,
                "module": str(p.resolve()),
                "ir": "archive",
                "inner": inner,
                "nearby_fn": None,
            }
        )
        if len(hits) >= limit:
            break
    hits.sort(key=lambda h: -int(h.get("score") or 0))
    return hits[:limit]


def gate_scan_payload(path: str, query: Optional[str], *, limit: int = 16) -> Dict[str, Any]:
    p = Path(path)
    q = (query or "").strip()
    hits = scan_payload_strings(p, q, limit=limit) if q else []
    plan: List[Dict[str, Any]] = []
    if hits:
        preview = str(hits[0].get("preview") or q)
        inner = hits[0].get("inner")
        diag = diagnose_text_module(p, preview, inner=inner)
        plan = list(diag.get("corrective_patch") or [])
    return {
        "ok": True,
        "summary": f"gate_scan payload={p.name} hits={len(hits)} plan={len(plan)}",
        "module": str(p.resolve()),
        "string_hits": hits[:24],
        "gate_candidates": plan[:limit],
        "patch_plan": plan[:5],
        "patch_site_previews": [],
        "next_hint": (
            f"payload IR {p.name}: diagnose_failure(error_text=hit) then apply_plan; "
            "do not patch the host ELF"
        ),
        "hints": {},
        "ir": classify_path(p).get("kind") or "text",
    }


def host_apply_refused(primary: str, steps: Sequence[Dict[str, Any]]) -> Optional[str]:
    """Refuse native ELF/PE patches on a host_runtime when steps are not payload IR."""
    brief = get_cached_brief(primary) or build_target_brief(primary)
    if brief.get("execution") != "host_runtime":
        return None
    payload_paths = {
        str(Path(x["path"]).resolve())
        for x in (brief.get("payloads") or [])
        if x.get("path")
    }
    host = str(Path(brief.get("path") or primary).resolve())
    native_on_host = False
    for s in steps:
        mod = str(Path(s.get("module") or primary).resolve())
        ir = str(s.get("ir") or "")
        kind = str(s.get("kind") or "")
        if ir in ("text", "archive") or kind == "replace_string":
            continue
        if mod == host or (mod not in payload_paths and sniff_magic(mod) in ("elf", "pe")):
            if kind in ("force_branch", "ret_imm", "nop_call", "nop_bytes", "force_flag"):
                native_on_host = True
                break
    if not native_on_host:
        return None
    names = [x.get("name") for x in (brief.get("payloads") or [])[:6]]
    return (
        "host_runtime: refuse native apply on the shell ELF/PE. "
        f"Search payload modules ({', '.join(str(n) for n in names) or 'sidecar archive/text'}) "
        "with find/atlas then diagnose_failure."
    )


def format_brief_text(brief: Dict[str, Any]) -> str:
    lines = [
        "TARGET BRIEF (facts from disk — read this before find/slice/apply):",
        f"  primary: {brief.get('path')}",
        f"  size: {brief.get('size')} bytes",
        f"  magic: {brief.get('magic')} arch={brief.get('arch') or '-'}",
        f"  execution: {brief.get('execution')}",
        f"  payload_ir: {brief.get('payload_ir')}",
    ]
    if brief.get("next_hint"):
        lines.append(f"  next: {brief.get('next_hint')}")
    inst = brief.get("install_dir")
    if inst:
        lines.append(f"  install: {inst}")
    sibs = brief.get("siblings") or []
    if sibs:
        lines.append("  siblings:")
        for s in sibs[:12]:
            lines.append(
                f"    - {s.get('name')}  {s.get('size')}  {s.get('kind')}/{s.get('magic')}"
            )
    hops = brief.get("payloads") or []
    if hops:
        lines.append("  payload modules:")
        for h in hops[:8]:
            lines.append(
                f"    - {h.get('name')}  kind={h.get('kind')} size={h.get('size')} score={h.get('score')}"
            )
    deps = brief.get("deps") or []
    if deps:
        lines.append("  deps: " + ", ".join(str(d) for d in deps[:12]))
    return "\n".join(lines)


def build_target_brief(
    primary: Path | str,
    *,
    install_dir: Optional[str] = None,
) -> Dict[str, Any]:
    p = Path(primary)
    if p.is_file():
        p = p.resolve()
    cls = classify_path(p)
    install = Path(install_dir) if install_dir else p.parent
    payloads = list_payload_modules(p) if p.is_file() else []
    if payloads and cls.get("execution") == "native":
        # sidecar present but layout not host-marked — still prefer payload if archives exist
        if any(x.get("kind") == "archive" for x in payloads) or _host_runtime_layout(p):
            cls["execution"] = "host_runtime"
            cls["payload_ir"] = (
                "archive" if any(x.get("kind") == "archive" for x in payloads) else "text"
            )
            cls["kind"] = "host"
    deps: List[str] = []
    if cls.get("magic") in ("elf", "pe"):
        try:
            from argus.discover import list_dependency_names

            deps = list_dependency_names(p)[:16]
        except Exception:
            deps = []
    payload_ir = cls.get("payload_ir") or "native"
    if cls.get("execution") == "host_runtime" and payloads:
        if any(x.get("kind") == "archive" for x in payloads):
            payload_ir = "archive"
        else:
            payload_ir = "text"
    next_hint = (
        "Use binary= primary for launch; gate logic may live in linked[] — slice then apply_plan"
    )
    if payload_ir != "native":
        next_hint = (
            "payload_ir is not native — argus_find/atlas on payload modules in this brief; "
            "do not slice or apply_plan on the host ELF/PE"
        )
    brief = {
        **cls,
        "payload_ir": payload_ir,
        "install_dir": str(install) if install.is_dir() else str(p.parent),
        "siblings": list_install_entries(install),
        "payloads": payloads,
        "deps": deps,
        "next_hint": next_hint,
    }
    return brief


def get_cached_brief(primary: Optional[str] = None) -> Optional[Dict[str, Any]]:
    try:
        from argus.llm.session import get_session

        brief = getattr(get_session(), "target_brief", None) or {}
        if not brief:
            return None
        if primary:
            bp = str(Path(brief.get("path") or "").resolve()) if brief.get("path") else ""
            want = str(Path(primary).resolve())
            if bp and bp != want and Path(primary).name != Path(brief.get("path") or "").name:
                # still ok: work copy vs original
                pass
        return brief
    except Exception:
        return None


def store_brief(brief: Dict[str, Any]) -> None:
    try:
        from argus.llm.session import get_session

        get_session().target_brief = dict(brief)
    except Exception:
        pass


def payload_ir_of(primary: Optional[str] = None) -> str:
    brief = get_cached_brief(primary)
    if brief:
        return str(brief.get("payload_ir") or "native")
    if primary and Path(primary).is_file():
        return str(classify_path(primary).get("payload_ir") or "native")
    return "native"
