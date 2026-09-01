from .patcher import PatchRecord, Patcher
from .intents import force_branch, force_flag, nop_bytes, nop_call, replace_string, ret_imm
from .packers import is_upx, maybe_upx_unpack
from .safety import assess_patched_binary, finalize_patch_safety, preflight_patch
from .deploy import (
    DeployResult,
    backup_path_for,
    deploy_patched_modules,
    ensure_original_backup,
    in_place_enabled,
    install_replace,
    original_dir_for,
    patch_mode,
    restore_from_original,
)

__all__ = [
    "Patcher",
    "PatchRecord",
    "force_branch",
    "force_flag",
    "nop_call",
    "nop_bytes",
    "ret_imm",
    "replace_string",
    "is_upx",
    "maybe_upx_unpack",
    "preflight_patch",
    "assess_patched_binary",
    "finalize_patch_safety",
    "DeployResult",
    "backup_path_for",
    "deploy_patched_modules",
    "ensure_original_backup",
    "in_place_enabled",
    "install_replace",
    "original_dir_for",
    "patch_mode",
    "restore_from_original",
]
