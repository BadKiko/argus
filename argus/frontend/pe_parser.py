# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
PE/COFF Executable & Dynamic Link Library Parser.
Extracts code sections (.text), entry points, export/import directory tables using pefile.
"""
from typing import Dict, List, Optional, Tuple, Any
import os
import pefile

class PEParser:
    def __init__(self, file_path: str):
        self.file_path = file_path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Binary file not found: {file_path}")
        self.pe = pefile.PE(file_path)

    def get_basic_info(self) -> Dict[str, Any]:
        """
        Retrieves high-level metadata of the PE binary.
        """
        is_64bit = self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
        return {
            "file_name": os.path.basename(self.file_path),
            "is_64bit": is_64bit,
            "architecture": "x86_64" if is_64bit else "x86_32",
            "entry_point_rva": hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(self.pe.OPTIONAL_HEADER.ImageBase),
            "number_of_sections": len(self.pe.sections),
            "is_dll": self.pe.is_dll(),
            "is_exe": self.pe.is_exe(),
        }

    def get_sections(self) -> List[Dict[str, Any]]:
        """
        Lists all PE sections with their virtual addresses, raw sizes, and entropy.
        """
        sections = []
        for s in self.pe.sections:
            name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
            sections.append({
                "name": name,
                "virtual_address": hex(s.VirtualAddress),
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": s.get_entropy()
            })
        return sections

    def extract_text_section_bytes(self) -> Optional[bytes]:
        """
        Extracts raw binary executable bytes from the primary code section (.text).
        """
        for s in self.pe.sections:
            name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
            if name.lower() in [".text", "code", ".code"]:
                return s.get_data()
        # Fallback to first executable section
        for s in self.pe.sections:
            if s.IMAGE_SCN_MEM_EXECUTE:
                return s.get_data()
        return None

    def close(self):
        self.pe.close()
