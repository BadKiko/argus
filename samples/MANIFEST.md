# Sample corpus (research / CTF only)

Educational and research binaries for Argus tests. **Not malware droppers** — published crackmes and protector research samples.

| Path | Origin | Protection | Argus expectation (today) |
|------|--------|------------|---------------------------|
| `fauxware` / `ollvm/fauxware_plain` | angr | none | `solve` → `SOSNEAKY` |
| `fauxware_fla` / `ollvm/fauxware_fla` | OLLVM CFF | CFF | `deobf`/`certify` state recovery |
| `ollvm/CFF*.bin` | [ollvm-unflattener](https://github.com/cdong1012/ollvm-unflattener) | OLLVM CFF | load + CFG + CFF cases |
| `ollvm/CFF_win*.exe` | same | OLLVM CFF (PE) | load + entry CFG |
| `vmp/*.vmp.exe` | [VirtualizationObfuscatorAnalysis](https://github.com/mzakocs/VirtualizationObfuscatorAnalysis) | VMProtect 3 | load + entry CFG smoke |
| `vmp/sample*.vmp.bin` | [VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization) | VMProtect | load + entry CFG smoke |
| `vmp/ultrasec.vmp.exe` | [Ultrasec-VMP](https://github.com/voksireimagined/Ultrasec-VMP) | VMProtect crackme | load smoke |
| `pe/hello_world_themida_protected.exe` | VOA Themida | Themida | load smoke |
| `pe/angr_test_sample.exe` | angr | PE large | load + entry CFG |

Upstream clones (optional, large) live under `third_party/` and are gitignored.

## License / ethics

Use only for reverse-engineering research and tool evaluation. Do not redistribute as weaponized packs.
