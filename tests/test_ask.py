"""Intent API tests — LLM hint → answer / lift / patch."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from argus.ask import Hint, PatchKind, Want, ask

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _need(*parts: str) -> Path:
    p = SAMPLES.joinpath(*parts)
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def test_ask_password_fauxware():
    r = ask(
        str(_need("fauxware")),
        Hint(want=Want.PASSWORD, note="crackme backdoor password", find=b"Welcome"),
    )
    assert r.ok and r.answer and "SOSNEAKY" in r.answer


def test_ask_password_fauxware_fla():
    r = ask(
        str(_need("fauxware_fla")),
        Hint(
            want=Want.PASSWORD,
            note="OLLVM flattened; need password",
            find=b"Welcome",
            function="authenticate",
        ),
    )
    assert r.ok and r.answer == "SOSNEAKY"


def test_ask_lift_authenticate():
    r = ask(
        str(_need("fauxware_fla")),
        Hint(want=Want.LIFT, function="authenticate", note="show cleaned CFG"),
    )
    assert r.ok and r.readable
    assert "authenticate" in r.readable
    assert "L_" in r.readable or "block_" in r.readable


def test_ask_patch_always_true(tmp_path):
    import shutil
    import sys

    src = str(_need("fauxware"))
    out = str(tmp_path / "argus_always_true.bin")
    r = ask(
        src,
        Hint(
            want=Want.PATCH,
            patch_kind=PatchKind.ALWAYS_TRUE,
            function="authenticate",
            output=out,
            note="bypass auth for test harness",
        ),
    )
    assert r.ok and r.patched_path
    # any password should welcome now (authenticate always returns 1)
    if sys.platform == "win32":
        has_wsl = False
        if shutil.which("wsl"):
            try:
                res = subprocess.run(["wsl", "--status"], capture_output=True, timeout=1.0)
                has_wsl = (res.returncode == 0)
            except Exception:
                pass
        if has_wsl:
            drive = out[0].lower()
            wsl_path = f"/mnt/{drive}/" + out[3:].replace("\\", "/")
            p = subprocess.run(["wsl", wsl_path], input=b"nope\nnope\n", capture_output=True)
            assert b"Welcome" in p.stdout
    else:
        p = subprocess.run([out], input=b"nope\nnope\n", capture_output=True)
        assert b"Welcome" in p.stdout


def test_ask_deobf(tmp_path):
    out = str(tmp_path / "argus_ask_deobf.bin")
    r = ask(
        str(_need("fauxware_fla")),
        Hint(want=Want.DEOBF, function="authenticate", output=out, note="unflatten"),
    )
    assert r.ok and Path(out).exists()
