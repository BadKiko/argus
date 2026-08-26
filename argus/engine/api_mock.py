# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
High-Level WinAPI & Subsystem Mock Registry.
Provides deterministic responses and synthetic handles for external system calls
(Kernel32, NtDll, DirectX, User32) to prevent emulator halts during deep logic traversal.
"""
from typing import Dict, Any, Callable, Optional, Tuple

class APIMockRegistry:
    def __init__(self):
        self.mock_table: Dict[str, Callable[..., int]] = {}
        self._register_default_mocks()

    def _register_default_mocks(self):
        # Default success stubs
        self.register_mock("kernel32.dll!GetModuleHandleW", lambda *args: 0x140000000) # Base addr
        self.register_mock("kernel32.dll!GetModuleHandleA", lambda *args: 0x140000000)
        self.register_mock("kernel32.dll!GetCurrentProcess", lambda *args: 0xFFFFFFFFFFFFFFFF) # Pseudo handle
        self.register_mock("kernel32.dll!GetCurrentThread", lambda *args: 0xFFFFFFFFFFFFFFFE)
        self.register_mock("kernel32.dll!QueryPerformanceCounter", lambda *args: 1) # Success BOOL
        self.register_mock("kernel32.dll!QueryPerformanceFrequency", lambda *args: 1)
        self.register_mock("kernel32.dll!VirtualProtect", lambda *args: 1)
        self.register_mock("kernel32.dll!VirtualAlloc", lambda *args: 0x20000000)
        self.register_mock("ntdll.dll!NtQueryInformationProcess", lambda *args: 0) # STATUS_SUCCESS
        self.register_mock("user32.dll!GetDesktopWindow", lambda *args: 0x10010)
        self.register_mock("d3d9.dll!Direct3DCreate9", lambda *args: 0x30000000)

    def register_mock(self, full_api_name: str, handler: Callable[..., int]):
        self.mock_table[full_api_name.lower()] = handler

    def invoke_mock(self, full_api_name: str, *args) -> Tuple[bool, int]:
        """
        Executes mock stub if registered. Returns (is_mocked, return_value).
        """
        key = full_api_name.lower()
        if key in self.mock_table:
            res = self.mock_table[key](*args)
            return True, res
        return False, 0
