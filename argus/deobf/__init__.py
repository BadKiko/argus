from argus.deobf.cff import CFFReport, cleaned_adjacency, find_dispatcher, recover_cff
from argus.deobf.detect import ProtectionReport, detect_protection
from argus.deobf.unflatten import UnflattenResult, apply_unflatten, deobf_and_patch, solve_after_deobf
from argus.deobf.vm import HandlerSynthesizer, VMReport, decode_toy_bytecode
from argus.deobf.vmp_layer import VMPLayerReport, analyze_vmp_layer
from argus.deobf.bogus import BogusCFReport, analyze_bogus_cf, prove_mba_catalog

__all__ = [
    "CFFReport",
    "recover_cff",
    "find_dispatcher",
    "cleaned_adjacency",
    "HandlerSynthesizer",
    "VMReport",
    "decode_toy_bytecode",
    "UnflattenResult",
    "apply_unflatten",
    "deobf_and_patch",
    "solve_after_deobf",
    "detect_protection",
    "ProtectionReport",
    "analyze_vmp_layer",
    "VMPLayerReport",
    "analyze_bogus_cf",
    "BogusCFReport",
    "prove_mba_catalog",
]
