"""Host vs payload brief, text diagnose, refuse native apply on shell."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from argus.apply_plan import apply_plan
from argus.discover import discover_targets
from argus.find import find_in_binary
from argus.flow import diagnose_target
from argus.llm.agent import _build_user_content
from argus.llm.session import add_verified_plan_steps, reset_session
from argus.llm.workspace import exec_workspace_dir
from argus.payload import (
    build_target_brief,
    classify_path,
    pack_asar,
    store_brief,
)

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
JS_SRC = (
    "function checkLicense(){\n"
    "  if (!ok) { throw 'trial expired'; }\n"
    "  return false;\n"
    "}\n"
)


def _host_tree(tmp_path: Path, *, asar: bool = False) -> Path:
    install = tmp_path / "app"
    install.mkdir()
    host = install / "hostbin"
    shutil.copy(SAMPLES / "fauxware", host)
    raw = bytearray(host.read_bytes())
    raw.extend(b"\x00OriginTrialsSampleAPIExpiryGracePeriod\x00")
    host.write_bytes(bytes(raw))
    (install / "chrome-sandbox").write_bytes(b"\x00" * 32)
    (install / "LICENSE.electron").write_text("Electron", encoding="utf-8")
    res = install / "resources"
    res.mkdir()
    (res / "app.js").write_text(JS_SRC, encoding="utf-8")
    if asar:
        (res / "app.asar").write_bytes(pack_asar({"app.js": JS_SRC.encode("utf-8")}))
    return host


def test_brief_classifies_host_runtime(tmp_path):
    host = _host_tree(tmp_path)
    brief = build_target_brief(host, install_dir=str(host.parent))
    assert brief["execution"] == "host_runtime"
    assert brief["payload_ir"] in ("text", "archive")
    names = [s["name"] for s in brief["siblings"]]
    assert any("app.js" in n or n.endswith("app.js") for n in names)
    assert any(p["kind"] in ("text", "archive") for p in brief["payloads"])
    assert "payload_ir is not native" in (brief.get("next_hint") or "")


def test_brief_asar_payload(tmp_path):
    host = _host_tree(tmp_path, asar=True)
    brief = build_target_brief(host, install_dir=str(host.parent))
    assert brief["payload_ir"] == "archive"
    assert any(p["name"] == "app.asar" for p in brief["payloads"])


def test_discover_linked_includes_payload(tmp_path):
    host = _host_tree(tmp_path)
    d = discover_targets("trial", root=str(host.parent), binary=str(host))
    assert d.get("brief", {}).get("execution") == "host_runtime"
    kinds = {m.get("kind") for m in d.get("linked") or []}
    assert "text" in kinds or any(
        Path(m["path"]).name == "app.js" for m in (d.get("linked") or [])
    )


def test_find_prefers_payload_not_engine(tmp_path):
    host = _host_tree(tmp_path)
    reset_session()
    store_brief(build_target_brief(host, install_dir=str(host.parent)))
    found = find_in_binary(str(host), "trial")
    hits = found.get("hits") or []
    previews = [str(h.get("preview") or "") for h in hits]
    assert any("trial expired" in p for p in previews)
    top = hits[0]["preview"] if hits else ""
    assert "OriginTrial" not in top


def test_find_accepts_asar_as_binary(tmp_path):
    host = _host_tree(tmp_path, asar=True)
    asar = host.parent / "resources" / "app.asar"
    found = find_in_binary(str(asar), "trial")
    assert found.get("ok") is not False
    previews = [str(h.get("preview") or "") for h in (found.get("hits") or [])]
    assert any("trial expired" in p for p in previews)
    assert (found.get("hits") or [])[0].get("inner") == "app.js"


def test_asar_find_skips_toc_and_node_modules(tmp_path):
    from argus.payload import pack_asar, scan_payload_strings

    blob = pack_asar(
        {
            "node_modules/foo/isPromise.js": b'{"ok":true}\nmodule.exports=function isPromise(){}',
            "node_modules/foo/LICENSE": b"Licensed under the MIT license. See LICENSE file in the project root.",
            "src/gate.js": (
                b"function checkLicense(){\n"
                b"  if (!isPro) { throw 'invalid license'; return false; }\n"
                b"  return true;\n"
                b"}\n"
            ),
        }
    )
    asar = tmp_path / "app.asar"
    asar.write_bytes(blob)
    hits = scan_payload_strings(asar, "isPro", limit=8)
    assert hits
    assert hits[0].get("inner") == "src/gate.js"
    assert "isPromise" not in str(hits[0].get("preview") or "")
    licensed = scan_payload_strings(asar, "license", limit=8)
    assert licensed
    assert "node_modules" not in str(licensed[0].get("inner") or "")
    found = find_in_binary(str(asar), "isPro")
    assert (found.get("hits") or [])[0].get("inner") == "src/gate.js"


def test_zip_find_python_not_site_packages(tmp_path):
    import zipfile

    zpath = tmp_path / "app.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr(
            "site-packages/pkg/license.py",
            "Licensed under the MIT license. See LICENSE file in the project root.\n",
        )
        zf.writestr(
            "app.py",
            "def check():\n    if not ok:\n        raise SystemExit('trial expired')\n        return False\n",
        )
    from argus.payload import scan_payload_strings

    hits = scan_payload_strings(zpath, "trial", limit=8)
    assert hits
    assert hits[0].get("inner") == "app.py"
    found = find_in_binary(str(zpath), "trial")
    assert (found.get("hits") or [])[0].get("inner") == "app.py"
    diag = diagnose_target(str(zpath), error_text="trial expired")
    assert diag.get("corrective_patch")
    assert all(s.get("inner") == "app.py" for s in diag["corrective_patch"])


def test_diagnose_payload_plan_and_host_zero_gates(tmp_path):
    host = _host_tree(tmp_path)
    reset_session()
    store_brief(build_target_brief(host, install_dir=str(host.parent)))
    diag = diagnose_target(str(host), error_text="trial expired")
    assert diag.get("corrective_patch")
    assert all(s.get("ir") == "text" for s in diag["corrective_patch"])
    engine = diagnose_target(str(host), error_text="This trial does not exist")
    # string only in Chromium-like ELF would be empty; this fixture has OriginTrial not that phrase
    assert not engine.get("corrective_patch")


def test_apply_refuses_host_elf(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_PATCH_MODE", "in_place")
    host = _host_tree(tmp_path)
    reset_session()
    store_brief(build_target_brief(host, install_dir=str(host.parent)))
    d = apply_plan(
        str(host),
        steps=[
            {
                "kind": "force_branch",
                "addr": "0x401000",
                "taken": True,
                "module": str(host),
            }
        ],
    )
    assert d.get("ok") is False
    assert "host_runtime" in (d.get("summary") or "")


def test_apply_text_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_PATCH_MODE", "in_place")
    monkeypatch.setenv("ARGUS_STRICT_PLAN", "0")
    host = _host_tree(tmp_path)
    js = host.parent / "resources" / "app.js"
    reset_session()
    store_brief(build_target_brief(host, install_dir=str(host.parent)))
    diag = diagnose_target(str(host), error_text="trial expired")
    plan = diag.get("corrective_patch") or []
    assert plan
    add_verified_plan_steps(plan, replace=True)
    d = apply_plan(str(host), steps=plan)
    assert d.get("ok") is True, d
    text = js.read_text(encoding="utf-8")
    assert "if (!ok)" not in text or "return false" not in text


def test_apply_asar_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_PATCH_MODE", "in_place")
    monkeypatch.setenv("ARGUS_STRICT_PLAN", "0")
    host = _host_tree(tmp_path, asar=True)
    asar = host.parent / "resources" / "app.asar"
    before = asar.read_bytes()
    reset_session()
    store_brief(build_target_brief(host, install_dir=str(host.parent)))
    diag = diagnose_target(str(host), error_text="trial expired")
    plan = diag.get("corrective_patch") or []
    assert plan
    add_verified_plan_steps(plan, replace=True)
    d = apply_plan(str(host), steps=plan)
    assert d.get("ok") is True, d
    assert asar.read_bytes() != before


def test_build_user_content_starts_with_brief(tmp_path):
    host = _host_tree(tmp_path)
    brief = build_target_brief(host, install_dir=str(host.parent))
    content = _build_user_content(
        "unlock trial",
        str(host),
        "TASKS:\n1. unlock",
        discover={"brief": brief, "linked": [{"path": str(host.parent / "libGLESv2.so"), "score": 26}]},
    )
    assert content.startswith("TARGET BRIEF")
    assert content.index("TARGET BRIEF") < content.index("unlock trial")
    assert "payload_ir" in content


def test_exec_workspace_not_install(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_WORK_DIR", str(tmp_path / "cache"))
    host = tmp_path / "usr" / "share" / "app" / "bin"
    host.parent.mkdir(parents=True)
    host.write_bytes(b"x" * 8)
    d = exec_workspace_dir(str(host))
    assert "usr/share" not in str(d)
    assert (tmp_path / "cache") in d.parents or str(tmp_path / "cache") in str(d)


def test_classify_plain_elf_stays_native(tmp_path):
    bin_path = tmp_path / "plain"
    shutil.copy(SAMPLES / "fauxware", bin_path)
    cls = classify_path(bin_path)
    assert cls["execution"] == "native"
    assert cls["payload_ir"] == "native"


def test_argus_discover_returns_brief(tmp_path):
    host = _host_tree(tmp_path)
    from argus.llm.session import reset_session
    from argus.llm.tools import dispatch_tool

    reset_session()
    out = json.loads(
        dispatch_tool(
            "argus_discover",
            {"prompt": "trial", "root": str(host.parent), "binary": str(host)},
        )
    )
    assert out.get("ok") is True
    assert (out.get("brief") or {}).get("execution") == "host_runtime"


def test_minified_js_diagnose_returns_window_not_if_parser(tmp_path):
    src = b're.getIsX=B=>"ok"===B.app.st;re.next=1;\n'
    asar = tmp_path / "app.asar"
    asar.write_bytes(pack_asar({"src/main.js": src}))
    diag = diagnose_target(str(asar), error_text='getIsX=B=>"ok"===')
    assert diag.get("window")
    assert "getIsX" in (diag.get("match") or "")
    assert (diag.get("window") or "").find("getIsX") < 80
    assert diag.get("inner") == "src/main.js"
    assert not diag.get("corrective_patch")
    assert "does not parse" in (diag.get("explanation") or "")


def test_replace_string_from_window_strict_plan(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_PATCH_MODE", "in_place")
    src = b're.getIsX=B=>"ok"===B.app.st;re.next=1;\n'
    asar = tmp_path / "app.asar"
    asar.write_bytes(pack_asar({"src/main.js": src}))
    from argus.llm.session import note_text_site
    from argus.payload import read_payload_bytes

    reset_session()
    diag = diagnose_target(str(asar), error_text='getIsX=B=>"ok"===')
    note_text_site(diag)
    old = '"ok"===B.app.st'
    new = "true" + " " * (len(old) - 4)
    assert old in (diag.get("window") or "")
    assert len(new) == len(old)
    d = apply_plan(str(asar), steps=[{"kind": "replace_string", "old": old, "new": new}])
    assert d.get("ok") is True, d
    assert b"true" in read_payload_bytes(asar, inner="src/main.js")

    asar.write_bytes(pack_asar({"src/main.js": src}))
    reset_session()
    note_text_site(diag)
    longer = old + "/*x*/"
    grew = apply_plan(
        str(asar),
        steps=[{"kind": "replace_string", "old": old, "new": longer}],
    )
    assert grew.get("ok") is True, grew
    assert b"/*x*/" in read_payload_bytes(asar, inner="src/main.js")

    asar.write_bytes(pack_asar({"src/main.js": src}))
    reset_session()
    note_text_site(diag)
    bad = apply_plan(
        str(asar),
        steps=[{"kind": "replace_string", "old": "not-in-the-window-zzzz", "new": "x"}],
    )
    assert bad.get("ok") is False


def test_find_and_diagnose_keep_inner_and_window(tmp_path):
    from argus.llm.tools import dispatch_tool

    src = b're.getIsX=B=>"ok"===B.app.st;re.next=1;\n'
    asar = tmp_path / "app.asar"
    asar.write_bytes(pack_asar({"src/main.js": src}))
    reset_session()
    found = json.loads(
        dispatch_tool("argus_find", {"binary": str(asar), "query": "getIsX", "for_task": 1})
    )
    hits = found.get("hits") or (found.get("evidence") or {}).get("hits") or []
    assert hits
    assert hits[0].get("inner") == "src/main.js"
    diag = json.loads(
        dispatch_tool(
            "argus_diagnose",
            {"binary": str(asar), "error_text": 'getIsX=B=>"ok"===', "for_task": 1},
        )
    )
    window = diag.get("window") or (diag.get("evidence") or {}).get("window") or ""
    assert "getIsX" in window
    assert diag.get("ok") is True
    peek = json.loads(
        dispatch_tool(
            "argus_peek",
            {"binary": str(asar), "addr": diag.get("string_addr") or hits[0]["addr"], "for_task": 1},
        )
    )
    assert peek.get("ok") is True
    assert "getIsX" in str(peek.get("window") or "")
