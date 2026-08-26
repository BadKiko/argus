# Sample corpus (research / CTF only)

Educational and research binaries for Argus tests. **Not malware droppers**.

| Path | Origin | Protection | Argus 0.2.0 expectation |
|------|--------|------------|-------------------------|
| `fauxware` | angr | none | `ai "пароль"` → `SOSNEAKY` |
| `fauxware_fla` | OLLVM CFF | CFF | `ai "пароль"` → `SOSNEAKY`; unflatten+patch |
| `ollvm/CFF_full_linux64.bin` | ollvm-unflattener | CFF | lift/`case_map≥2` + unflatten certify |
| `ollvm/CFF*.bin` / `CFF_win*.exe` | same | CFF | load+CFG; PE unflatten when cases found |
| `vmp/sample1.vmp.bin` / `adder.vmp.exe` | Salwan / VOA | VMP | detect + partial lift/handlers |
| `vmp/ultrasec.vmp.exe` | UltraSec | VMP | load/detect smoke only |
| `pe/hello_world_themida_protected.exe` | VOA | Themida | detect smoke |

## Ground truth (password)

| Binary | Secret |
|--------|--------|
| `fauxware` | `SOSNEAKY` |
| `fauxware_fla` | `SOSNEAKY` |

## License / ethics

Research and tool evaluation only.
