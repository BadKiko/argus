from pathlib import Path

import pytest

from argus.binary import load_binary

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_load_fauxware_elf():
    img = load_binary(SAMPLES / "fauxware")
    assert img.fmt == "elf"
    assert img.arch == "x86_64"
    assert img.entry == 0x400580
    assert "main" in img.symbols
    assert "authenticate" in img.symbols
    assert any(n == "strcmp" for n in img.imports.values())


def test_load_pe_sample():
    pe_path = Path(__file__).resolve().parents[1] / "angr_test_sample.exe"
    if not pe_path.exists():
        pytest.skip("PE sample missing")
    img = load_binary(pe_path)
    assert img.fmt == "pe"
    assert img.arch == "x86_64"
    assert img.entry != 0
