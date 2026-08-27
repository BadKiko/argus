from pathlib import Path

from argus.mba import MBASimplifier, mba_x_plus_y, mba_x_xor_y
from argus.symbolic import solve_binary

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_solve_fauxware_password():
    res = solve_binary(str(SAMPLES / "fauxware"), find=b"Welcome")
    assert res.success, res.message
    assert res.stdin is not None
    # Password SOSNEAKY appears in the stdin stream (after username field)
    assert b"SOSNEAKY" in res.stdin


def test_mba_identities():
    s = MBASimplifier(32)
    r1 = s.simplify_binary_expr(mba_x_plus_y)
    assert r1.proved and r1.simplified == "x+y"
    r2 = s.simplify_binary_expr(mba_x_xor_y)
    assert r2.proved and r2.simplified == "x^y"
