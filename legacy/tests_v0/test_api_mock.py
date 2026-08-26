# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.api_mock import APIMockRegistry

def test_api_mock_registry_stubs():
    registry = APIMockRegistry()

    # Verify standard WinAPI mocks
    is_mocked, ret_val = registry.invoke_mock("kernel32.dll!GetModuleHandleW", 0)
    assert is_mocked is True
    assert ret_val == 0x140000000

    is_mocked, ret_val = registry.invoke_mock("ntdll.dll!NtQueryInformationProcess", 0, 0, 0, 0, 0)
    assert is_mocked is True
    assert ret_val == 0 # STATUS_SUCCESS

    # Custom mock registration
    registry.register_mock("custom.dll!SpecialInit", lambda a, b: a + b)
    is_mocked, ret_val = registry.invoke_mock("custom.dll!SpecialInit", 10, 20)
    assert is_mocked is True
    assert ret_val == 30

    # Unregistered API
    is_mocked, _ = registry.invoke_mock("unknown.dll!MissingFunction")
    assert is_mocked is False
