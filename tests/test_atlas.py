"""argus_atlas: two-phase strings then from-string map (ELF/PE)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.atlas import build_atlas
from argus.llm.tools import dispatch_tool

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
BC = Path("/usr/lib/beyondcompare/BCompare")
FAUX = SAMPLES / "fauxware"
WIN64 = SAMPLES / "ollvm" / "CFF_win64.exe"


def test_atlas_elf_fauxware_two_phase():
    d = build_atlas(str(FAUX), "password")
    assert d.get("ok")
    assert d.get("phase") == "strings"
    assert d.get("jumps") == []
    strings = d.get("strings") or []
    assert strings, d.get("summary")
    addr = d.get("suggested_string_addr") or strings[0]["addr"]
    assert addr

    walked = build_atlas(str(FAUX), string_addr=addr)
    assert walked.get("ok"), walked.get("summary")
    assert walked.get("phase") == "map"
    names = [m.get("name") for m in walked.get("modules") or []]
    assert any("fauxware" in (n or "") for n in names)
    assert walked.get("modules")


@pytest.mark.skipif(not WIN64.is_file(), reason="PE sample missing")
def test_atlas_pe_sample_does_not_crash():
    d = build_atlas(str(WIN64), "invalid")
    assert "modules" in d
    assert d.get("phase") == "strings"
    kinds = {m.get("fmt") for m in d.get("modules") or [] if m.get("ok")}
    assert not kinds or "pe" in kinds or d.get("ok") is True


@pytest.mark.skipif(not BC.is_file(), reason="Beyond Compare not installed")
def test_atlas_bc_strings_then_error6_map():
    query = "That is not a valid version"
    d = build_atlas(str(BC), query)
    assert d.get("ok"), d.get("summary")
    assert d.get("phase") == "strings"
    assert not d.get("jumps")

    names = [m.get("name") for m in d.get("modules") or []]
    assert any(n == "BCompare" for n in names)
    hops = d.get("hops") or []
    assert any("cloudstorage" in (h.get("to") or "") for h in hops), hops

    strings = d.get("strings") or []
    assert strings, d.get("summary")
    # exact error text, not date/file "not a valid …" noise
    previews = " | ".join((s.get("preview") or "") for s in strings)
    assert "not a valid version" in previews.lower()
    assert "not a valid date" not in previews.lower()
    assert "not a valid time" not in previews.lower()

    err = next(
        (s for s in strings if "not a valid version" in (s.get("preview") or "").lower()),
        None,
    )
    assert err is not None, strings[:8]
    assert int(err.get("data_refs") or 0) >= 1
    addr = err["addr"]
    assert int(addr, 0) == 0x1DD29A0 or "not a valid version" in (err.get("preview") or "")

    walked = build_atlas(str(BC), query=query, string_addr=addr)
    assert walked.get("ok"), walked.get("summary")
    assert walked.get("phase") == "map"
    jumps = walked.get("jumps") or []
    assert jumps, f"no jumps: {walked.get('summary')} obs={walked.get('observations')}"
    exe_jumps = [j for j in jumps if j.get("module") == "BCompare"]
    assert exe_jumps, [(j.get("module"), j.get("op")) for j in jumps[:8]]
    with_regs = [j for j in exe_jumps if j.get("regs")]
    assert with_regs, "expected predicate registers on some jcc"

    addrs = [int(j["addr"], 0) for j in exe_jumps if j.get("addr")]
    # pointer-table xrefs land in the license-key formatter (f11e/e81a), not date-class parsers
    in_license = [a for a in addrs if 0xF11E00 <= a <= 0xF12200 or 0xE81A00 <= a <= 0xE81C80]
    assert in_license, f"license-window jumps missing; sample={[(hex(a), ) for a in addrs[:12]]} obs={walked.get('observations')}"
    date_noise = [a for a in addrs if 0xD0FB00 <= a <= 0xD0FD80]
    assert not date_noise, f"date-parser noise in map: {[hex(a) for a in date_noise]}"

    mods = walked.get("modules") or []
    assert any(m.get("pointer_sites") for m in mods), mods
    xrefs = []
    for m in mods:
        xrefs.extend(m.get("xrefs") or [])
    assert any(x.get("via") == "pointer_table" for x in xrefs), walked.get("observations")

    # sibling resource pack visible from the chosen string
    pack = " | ".join((s.get("preview") or "") for s in (walked.get("strings") or []))
    assert "bclock" in pack.lower() or "thanks for registering" in pack.lower() or "expired" in pack.lower()
    assert "Red Hat" not in pack
    assert not any(int(s.get("addr") or "0", 0) < 0x1000 for s in (walked.get("strings") or []))

    imms = []
    for m in mods:
        for fn in m.get("functions") or []:
            imms.extend(fn.get("imm_stores") or [])
    assert any(int(st.get("imm") or 0) == 6 for st in imms), imms[:12]

    f11 = [a for a in addrs if 0xF11E00 <= a <= 0xF12200]
    assert len(f11) >= 4, f"key-check jcc missing: {[hex(a) for a in addrs]}"

    # bidirectional: all e8 sites of related checks, not just the seed proc
    callers = walked.get("callers") or []
    assert callers, f"expected caller sets: {walked.get('observations')}"
    license_callers = []
    for c in callers:
        sites_c = [int(s, 0) for s in (c.get("sites") or [])]
        if any(0xD77000 <= a <= 0xD7E800 for a in sites_c) or (
            c.get("fn") and 0xD77000 <= int(c["fn"], 0) <= 0xD7E800
        ):
            license_callers.append(c)
    assert license_callers, callers[:8]
    assert max(int(c.get("count") or 0) for c in license_callers) >= 8, license_callers


@pytest.mark.skipif(not BC.is_file(), reason="Beyond Compare not installed")
def test_diagnose_bc_error6_uses_atlas_sink_callers():
    from argus.binary import load_binary
    from argus.flow import diagnose_failure

    img = load_binary(str(BC))
    d = diagnose_failure(img, error_text="That is not a valid version")
    assert d.get("ok"), d.get("explanation")
    plan = d.get("corrective_patch") or []
    assert plan, d.get("explanation")
    addrs = [int(s["addr"], 0) for s in plan if s.get("addr")]
    assert any(0xD77000 <= a <= 0xD7E800 for a in addrs), [hex(a) for a in addrs[:12]]
    kinds = {s.get("kind") for s in plan}
    assert kinds & {"force_branch", "nop_call", "force_flag", "ret_imm"}

    enter = build_atlas(str(BC), "Enter Key")
    top_enter = (enter.get("strings") or [None])[0]
    assert top_enter and "enter key" in (top_enter.get("preview") or "").lower(), enter.get("strings")[:5]

    raw = dispatch_tool("argus_atlas", {"binary": str(BC), "query": "BEGIN LICENSE KEY", "for_task": 1})
    payload = json.loads(raw)
    assert payload.get("ok")
    assert payload.get("phase") == "strings"
    assert payload.get("suggested_string_addr")
    hit = payload.get("strings") or []
    assert any("BEGIN LICENSE" in (s.get("preview") or "") for s in hit)

    raw2 = dispatch_tool(
        "argus_atlas",
        {"binary": str(BC), "string_addr": payload["suggested_string_addr"], "for_task": 1},
    )
    mapped = json.loads(raw2)
    assert mapped.get("ok"), mapped.get("summary")
    assert mapped.get("phase") == "map"
    assert mapped.get("jumps"), mapped.get("summary")
    begin_jumps = [int(j["addr"], 0) for j in mapped.get("jumps") or [] if j.get("addr")]
    # copies of this string lea into the key formatter (e81a) and/or the dialog (d7dc)
    near = [a for a in begin_jumps if 0xD7D700 <= a <= 0xD7E400 or 0xE81000 <= a <= 0xE82200 or 0xF11E00 <= a <= 0xF12200]
    assert near, f"license neighborhood missing: {[hex(a) for a in begin_jumps[:16]]} obs={mapped.get('observations')}"


def test_query_needles_include_utf32le():
    from argus.find import query_string_needles

    needles = query_string_needles("Trial version")
    kinds = {k for k, _ in needles}
    assert kinds >= {"utf8", "utf16le", "utf32le"}
    utf32 = next(b for k, b in needles if k == "utf32le" and b.startswith(b"T\x00\x00\x00r\x00\x00\x00"))
    assert utf32


RAR = Path("/home/kiko/Downloads/rarlinux-x64-723/rar/rar")


@pytest.mark.skipif(not RAR.is_file(), reason="rar sample not installed")
def test_atlas_utf32_trial_banner_maps_imm32():
    """CLI banners often live as char32_t[] with `mov edi, imm32` — not utf-8 lea."""
    d = build_atlas(str(RAR), "Trial version")
    assert d.get("ok"), d.get("summary")
    strings = d.get("strings") or []
    hit = next((s for s in strings if "Trial version" in (s.get("preview") or "")), None)
    assert hit is not None, strings[:8]
    assert hit.get("kind") == "utf32le"
    walked = build_atlas(str(RAR), string_addr=hit["addr"])
    assert walked.get("ok"), walked.get("summary")
    xrefs = []
    for m in walked.get("modules") or []:
        xrefs.extend(m.get("xrefs") or [])
    assert xrefs, walked.get("observations")
    addrs = [int(x["addr"], 0) for x in xrefs if x.get("addr")]
    assert any(0x446000 <= a <= 0x447000 for a in addrs), [hex(a) for a in addrs[:12]]


@pytest.mark.skipif(not RAR.is_file(), reason="rar sample not installed")
def test_diagnose_utf32_trial_banner():
    from argus.binary import load_binary
    from argus.flow import diagnose_failure

    img = load_binary(str(RAR))
    d = diagnose_failure(img, error_text="Trial version", use_atlas=True)
    assert d.get("ok") is True
    assert d.get("string_kind") == "utf32le"
    assert d.get("corrective_patch") or d.get("decision_flow")
