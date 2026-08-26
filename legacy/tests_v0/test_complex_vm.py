import pytest
from argus.targets.complex_license_vm import ComplexLicenseValidatorVM, AdvancedVMOpcode

def test_complex_license_vm_execution():
    vm = ComplexLicenseValidatorVM(seed=123)
    program = vm.generate_complex_validation_suite()
    
    hwid = 0x12345678
    license_key = 0x87654321
    
    # Расчет Ground Truth ожидаемого токена
    hwid_part1 = (hwid ^ 0x5A5A5A5A) & 0xFFFFFFFF
    hwid_part2 = (((hwid & 0x0F0F0F0F) << 2) | ((hwid & 0x0F0F0F0F) >> 30)) & 0xFFFFFFFF
    hwid_hash = (hwid_part1 + hwid_part2) & 0xFFFFFFFF
    expected_token = (((license_key ^ hwid_hash) + 0x1337BEEF) ^ 0xCAFEBABE) & 0xFFFFFFFF

    registers, trace = vm.run_simulation(program, hwid=hwid, license_key=license_key)
    
    assert registers.get("AUTH_TOKEN") == expected_token
    assert registers.get("IS_VALID") == expected_token
    assert any("[DISPATCHER] Entering State 10" in line for line in trace)
    assert any("[DISPATCHER] Entering State 20" in line for line in trace)
    assert any("[DISPATCHER] Entering State 30" in line for line in trace)
    assert any("[DISPATCHER] Entering State 40" in line for line in trace)
