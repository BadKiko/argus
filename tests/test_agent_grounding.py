"""Grounding + find + patch tool smoke tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from argus.ask import Hint, PatchKind, Want, _pick_function, ask
from argus.find import find_in_binary
from argus.llm.tools import ARGUS_TOOLS, dispatch_tool
from argus.nl import parse_prompt

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_pick_function_never_largest():
    big = SimpleNamespace(name="huge_qt", addr=0x1000, size=999999, is_function=True, is_import=False)
    main = SimpleNamespace(name="main", addr=0x2000, size=32, is_function=True, is_import=False)
    img = SimpleNamespace(
        entry=0x2000,
        symbols={"huge_qt": big, "main": main},
    )
    assert _pick_function(img, None) == "main"
    assert _pick_function(img, "huge_qt") == "huge_qt"


def test_pick_function_entry_when_no_main():
    entry_fn = SimpleNamespace(name="_start", addr=0x400000, size=16, is_function=True, is_import=False)
    other = SimpleNamespace(name="blob", addr=0x500000, size=10_000, is_function=True, is_import=False)
    img = SimpleNamespace(entry=0x400000, symbols={"_start": entry_fn, "blob": other})
    assert _pick_function(img, None) == "_start"


def test_nl_remove_license_is_patch_not_lift():
    h = parse_prompt("убери проверку лицензии")
    assert h.want == Want.PATCH
    assert h.patch_kind in (PatchKind.SKIP_CHECK, PatchKind.ALWAYS_TRUE, PatchKind.RET_IMM)


def test_nl_how_license_still_lift():
    h = parse_prompt("как работает проверка лицензии?")
    assert h.want == Want.LIFT


def test_argus_find_on_fauxware():
    path = str(SAMPLES / "fauxware")
    data = find_in_binary(path, "password")
    assert data["ok"] is True
    assert data["hits"]
    kinds = {h["kind"] for h in data["hits"]}
    assert "string" in kinds or "symbol" in kinds


def test_gate_score_prefers_short_is_over_callback():
    from argus.find import _gate_score, _suggested_ret_value

    assert _gate_score("IsLicenseGenuine", True) > _gate_score("_Z15LicenseCallbackj", True)
    assert _gate_score("_Z15LicenseCallbackj", True) < 0  # UI callback demoted
    assert _suggested_ret_value("IsLicenseGenuine") == 0
    assert _suggested_ret_value("_ZN16LicenseActivator11isActivatedEv") == 1


def test_find_ui_query_does_not_prefer_unlock_stubs():
    from argus.find import _query_intent, find_in_binary

    assert _query_intent("Groot Pro") == "ui"
    assert _query_intent("заголовок и days left") == "ui"
    assert _query_intent("убери проверку лицензии") == "unlock"
    path = str(SAMPLES / "fauxware")
    data = find_in_binary(path, "Welcome title")
    assert "replace_string" in (data.get("next_hint") or "") or "UI/text" in (data.get("next_hint") or "")


def test_find_groot_suggested_stubs_if_present():
    from pathlib import Path

    groot = Path.home() / "Apps/craGroot190/bin/groot2"
    if not groot.is_file():
        return
    data = find_in_binary(str(groot), "license")
    stubs = data.get("suggested_stubs") or []
    assert stubs, "expected ranked gate stubs"
    names = [s["name"] for s in stubs]
    assert any(n.startswith("Is") and "License" in n for n in names)
    assert "LicenseCallback" not in "".join(names)
    assert "suggested_stubs" in (data.get("next_hint") or "") or "PREFERRED" in (data.get("next_hint") or "")


def test_dispatch_argus_find_envelope():
    path = str(SAMPLES / "fauxware")
    raw = dispatch_tool("argus_find", {"binary": path, "query": "password"})
    data = json.loads(raw)
    assert data.get("ok") is True
    assert "hits" in data
    assert "summary" in data


def test_dispatch_patch_always_true_writes_file(tmp_path):
    src = SAMPLES / "fauxware"
    out = tmp_path / "fauxware.patched"
    raw = dispatch_tool(
        "argus_patch",
        {
            "binary": str(src),
            "kind": "always_true",
            "function": "authenticate",
            "output": str(out),
        },
    )
    data = json.loads(raw)
    assert data.get("ok") is True
    assert data.get("patched_path") == str(out)
    assert out.exists()
    assert out.stat().st_size > 0


def test_tools_include_find_and_new_patch_kinds():
    names = {t["function"]["name"] for t in ARGUS_TOOLS}
    assert "argus_find" in names
    assert "argus_unlock_apply" in names
    assert "argus_slice" in names
    patch = next(t for t in ARGUS_TOOLS if t["function"]["name"] == "argus_patch")
    kinds = patch["function"]["parameters"]["properties"]["kind"]["enum"]
    assert "nop_bytes" in kinds and "ret_imm" in kinds and "force_branch" in kinds
    assert "unlock_license" not in kinds


def test_ask_ret_imm_and_default_patched_suffix(tmp_path):
    import shutil

    src = tmp_path / "fauxware"
    shutil.copy(SAMPLES / "fauxware", src)
    r = ask(
        str(src),
        Hint(want=Want.PATCH, patch_kind=PatchKind.RET_IMM, function="authenticate", ret_value=1),
    )
    assert r.ok
    assert r.patched_path == str(src) + ".patched"
    assert Path(r.patched_path).exists()


def test_refuse_stub_main():
    src = str(SAMPLES / "fauxware")
    r = ask(
        src,
        Hint(want=Want.PATCH, patch_kind=PatchKind.ALWAYS_TRUE, function="main", output="/tmp/argus_no_stub_main.bin"),
    )
    assert r.ok is False
    assert "refused" in (r.answer or "").lower() or any("refused" in n for n in r.notes)


def test_ret_imm_explicit_va_not_refused_as_main(tmp_path):
    """Default function label 'main' must not block ret_imm at an explicit non-entry VA."""
    import shutil

    src = tmp_path / "fauxware"
    shutil.copy(SAMPLES / "fauxware", src)
    from argus.binary import load_binary

    img = load_binary(str(src))
    auth = img.symbols["authenticate"].addr
    assert auth != img.entry
    out = tmp_path / "auth.patched"
    r = ask(
        str(src),
        Hint(
            want=Want.PATCH,
            patch_kind=PatchKind.RET_IMM,
            # no function= → _pick_function defaults to main; patch_addr is the real target
            patch_addr=auth,
            ret_value=1,
            output=str(out),
        ),
    )
    assert r.ok, r.answer or r.notes
    assert out.exists()


def test_skip_check_still_patches_authenticate(tmp_path):
    import shutil
    import subprocess

    src = tmp_path / "fauxware"
    shutil.copy(SAMPLES / "fauxware", src)
    out = tmp_path / "out.patched"
    r = ask(
        str(src),
        Hint(
            want=Want.PATCH,
            patch_kind=PatchKind.SKIP_CHECK,
            function="authenticate",
            output=str(out),
            note="убери проверку",
            find=b"Welcome",
        ),
    )
    assert r.ok and out.exists()
    p = subprocess.run([str(out)], input=b"x\ny\n", capture_output=True)
    assert b"Welcome" in p.stdout


def test_find_skips_zero_addr_symbols():
    from argus.find import find_in_binary

    data = find_in_binary(str(SAMPLES / "fauxware"), "password")
    assert all(h["addr"] != "0x0" for h in data["hits"])


def test_tools_include_xrefs():
    names = {t["function"]["name"] for t in ARGUS_TOOLS}
    assert "argus_xrefs" in names
    assert "argus_find" in names


def test_ret_imm_not_unlock_license_in_patch_kinds():
    patch = next(t for t in ARGUS_TOOLS if t["function"]["name"] == "argus_patch")
    kinds = patch["function"]["parameters"]["properties"]["kind"]["enum"]
    assert "ret_imm" in kinds
    assert "replace_string" in kinds
    assert "unlock_license" not in kinds
    assert not hasattr(PatchKind, "UNLOCK_LICENSE")


def test_nl_unlock_maps_to_ret_imm():
    h = parse_prompt("любой ключ сразу актив")
    assert h.want == Want.PATCH
    assert h.patch_kind == PatchKind.RET_IMM
    assert h.ret_value == 0


def test_safety_skips_smoke_on_heavy_text():
    from argus.binary import load_binary
    from argus.patch.safety import _looks_gui_or_heavy

    img = load_binary(str(SAMPLES / "fauxware"))
    assert _looks_gui_or_heavy(img) is False
    sublime = Path("/opt/sublime_merge/sublime_merge")
    if sublime.is_file():
        assert _looks_gui_or_heavy(load_binary(str(sublime))) is True


def test_safety_detects_early_ret_stub(tmp_path):
    import shutil

    from argus.ask import _encode_mov_eax_imm, _encode_ret
    from argus.binary import load_binary
    from argus.patch import Patcher
    from argus.patch.safety import assess_patched_binary, finalize_patch_safety

    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)
    img = load_binary(str(src))
    main = img.symbols["main"].addr
    out = tmp_path / "broken"
    p = Patcher.from_path(str(src))
    p.patch_bytes(main, _encode_mov_eax_imm(1) + _encode_ret(), note="kill main")
    p.save(str(out))
    a = assess_patched_binary(str(src), str(out))
    assert a["safe"] is False
    assert "early-ret" in a["reason"] or "entry" in a["reason"]
    ok, cert, notes = finalize_patch_safety(str(src), str(out), {}, remove_if_unsafe=True)
    assert ok is False
    assert not out.exists()


def test_safety_ok_on_authenticate_patch(tmp_path):
    import shutil

    src = tmp_path / "fw"
    out = tmp_path / "ok.patched"
    shutil.copy(SAMPLES / "fauxware", src)
    r = ask(
        str(src),
        Hint(want=Want.PATCH, patch_kind=PatchKind.ALWAYS_TRUE, function="authenticate", output=str(out)),
    )
    assert r.ok
    assert out.exists()
    assert (r.certificate or {}).get("safety", {}).get("safe") is True


def test_dispatch_missing_binary():
    raw = dispatch_tool("argus_analyze", {"binary": "/no/such/file/argus.bin"})
    data = json.loads(raw)
    assert data.get("ok") is False
    assert "нет файла" in data.get("summary", "")


def test_run_agent_missing_binary_no_llm():
    from argus.llm.agent import run_agent

    r = run_agent("дай пароль", binary="/tmp/does-not-exist-argus-xyz")
    assert r.ok is False
    assert "нет файла" in r.answer
    assert r.steps == 0


def test_retry_after_seconds_at_least_60():
    from argus.llm.gemini import RATE_LIMIT_WAIT_SEC, _retry_after_seconds

    body = 'Please retry in 20.592410637s.'
    assert _retry_after_seconds(body) >= RATE_LIMIT_WAIT_SEC
    assert _retry_after_seconds(body) == 60.0
    assert _retry_after_seconds('Please retry in 90s.') == 90.0
