"""Launch environment for bundled Linux GUI apps (sibling .so)."""

from __future__ import annotations

import os
from pathlib import Path


def launch_env_for(binary: str | Path) -> tuple[str, dict[str, str]]:
    """Return cwd + env with LD_LIBRARY_PATH for install-dir siblings."""
    p = Path(binary).resolve()
    cwd = str(p.parent)
    ld_path = cwd
    try:
        from argus.llm.session import get_session

        sess = get_session()
        if sess.install_dir and Path(sess.install_dir).is_dir():
            cwd = sess.install_dir
            ld_path = sess.install_dir
        elif sess.original_binary:
            orig_parent = str(Path(sess.original_binary).resolve().parent)
            cwd = orig_parent
            ld_path = orig_parent
    except Exception:
        pass

    env = os.environ.copy()
    prev = env.get("LD_LIBRARY_PATH", "")
    parts = [ld_path] + ([prev] if prev else [])
    env["LD_LIBRARY_PATH"] = ":".join(dict.fromkeys(x for x in parts if x))
    return cwd, env
