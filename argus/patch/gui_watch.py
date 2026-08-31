"""Wait for a dialog (observe-only dev helper — no auto keyboard input).

Usage:
  python -m argus.patch.gui_watch --dialog "License"
"""

from __future__ import annotations

import argparse
import json
import time

from argus.patch.gui_oracle import _find_window_containing, list_top_windows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--dialog", default="", help="Dialog title substring to wait for")
    args = ap.parse_args()
    if not args.dialog:
        print("Pass --dialog <title substring>")
        return 2
    print(f"Waiting for dialog {args.dialog!r}…")
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        dlg = _find_window_containing(args.dialog, timeout=0.5)
        if dlg is not None:
            print(json.dumps({"ok": True, "detail": "dialog visible", "titles": list_top_windows()[:12]}, indent=2))
            return 0
        time.sleep(0.5)
    print("timeout; windows:", list_top_windows()[:8])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
