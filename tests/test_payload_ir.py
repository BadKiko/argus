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
