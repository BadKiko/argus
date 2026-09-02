#!/usr/bin/env python3
"""Drive Beyond Compare Register dialog so GDB can catch the Enter Key path.

  python3 scripts/bc_auto_key.py           # gdb spawn + paste dummy key + OK
  python3 scripts/bc_auto_key.py --no-gdb # UI only, already-running BC
  python3 scripts/bc_auto_key.py --key '--- BEGIN LICENSE KEY ---...'
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

INSTALL = Path("/usr/lib/beyondcompare")
EXE = INSTALL / "BCompare"
ROOT = Path(__file__).resolve().parents[1]
GDB_SCRIPT = ROOT / "scripts" / "bc_gdb_starti.gdb"
GDB_LOG = Path("/tmp/bc_gdb_license.log")
HIT_LOG = Path("/tmp/bc_gdb_hits.log")

DUMMY_KEY = """--- BEGIN LICENSE KEY ---
AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH
JJJJ-KKKK-MMMM-NNNN-PPPP-QQQQ-RRRR-STTT
VVVV-WWWW-XXXX-YYYY-ZZZZ-2345-6789-ABCD
--- END LICENSE KEY -----
"""

REGISTER = "Register Beyond Compare"
HOME = "Home - Beyond Compare"
EVAL_WIN = "Beyond Compare 30-day evaluation"
ERROR = "Error"


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def wmctrl_windows() -> list[tuple[str, str]]:
    """Return (wid, title) pairs."""
    if not shutil.which("wmctrl"):
        return []
    try:
        out = subprocess.check_output(["wmctrl", "-l"], text=True, timeout=3)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) >= 4:
            rows.append((parts[0], parts[3]))
        elif len(parts) == 3:
            rows.append((parts[0], ""))
    return rows


def titles() -> list[str]:
    return [t for _, t in wmctrl_windows()]


def find_wid(substr: str) -> str | None:
    for wid, title in wmctrl_windows():
        if substr.lower() in title.lower():
            return wid
    return None


def activate(wid: str) -> None:
    run(["wmctrl", "-i", "-a", wid])
    time.sleep(0.25)
    if shutil.which("xdotool"):
        run(["xdotool", "windowactivate", "--sync", wid])
        time.sleep(0.15)


def xdotool_click_window(wid: str, x: int, y: int) -> None:
    run(["xdotool", "mousemove", "--window", wid, str(x), str(y), "click", "1"])
    time.sleep(0.2)


def key_in_window(wid: str, *keys: str) -> None:
    run(["xdotool", "key", "--window", wid, "--clearmodifiers", *keys])
    time.sleep(0.15)


def paste_clipboard(wid: str, text: str) -> None:
    subprocess.run(["xclip", "-selection", "clipboard"], input=text, text=True, check=True)
    time.sleep(0.1)
    key_in_window(wid, "ctrl+v")
    time.sleep(0.3)


# --- AT-SPI ---------------------------------------------------------------

def _atspi():
    try:
        import gi

        gi.require_version("Atspi", "2.0")
        from gi.repository import Atspi

        return Atspi
    except Exception:
        return None


def _iter_acc(acc, depth=0, limit=400):
    stack = [(acc, 0)]
    n = 0
    while stack and n < limit:
        node, d = stack.pop()
        n += 1
        yield node, d
        try:
            count = node.get_child_count()
        except Exception:
            continue
        for i in range(count - 1, -1, -1):
            try:
                ch = node.get_child_at_index(i)
            except Exception:
                continue
            if ch is not None:
                stack.append((ch, d + 1))


def atspi_find(*, name_substr: str | None = None, role: str | None = None):
    Atspi = _atspi()
    if Atspi is None:
        return None
    desktop = Atspi.get_desktop(0)
    name_l = (name_substr or "").lower()
    for i in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(i)
        try:
            aname = (app.get_name() or "").lower()
        except Exception:
            aname = ""
        if "bcompare" not in aname and "beyond" not in aname and "scooter" not in aname:
            # still search — some apps report as the exe name
            pass
        for node, _ in _iter_acc(app):
            try:
                n = node.get_name() or ""
                r = node.get_role_name() or ""
            except Exception:
                continue
            if name_substr and name_l not in n.lower():
                continue
            if role and r.lower() != role.lower():
                continue
            return node
    return None


def atspi_do(node, action_substr: str = "") -> bool:
    Atspi = _atspi()
    if Atspi is None or node is None:
        return False
    try:
        n = node.get_n_actions()
    except Exception:
        n = 0
    if n <= 0:
        return False
    want = action_substr.lower()
    for i in range(n):
        try:
            nm = (node.get_action_name(i) or "").lower()
        except Exception:
            nm = ""
        if not want or want in nm:
            try:
                return bool(node.do_action(i))
            except Exception:
                return False
    try:
        return bool(node.do_action(0))
    except Exception:
        return False


def atspi_set_text(node, text: str) -> bool:
    Atspi = _atspi()
    if Atspi is None or node is None:
        return False
    try:
        Atspi.EditableText.set_text_contents(node, text)
        return True
    except Exception:
        pass
    try:
        Atspi.Text.set_text_contents(node, text)
        return True
    except Exception:
        return False


def atspi_dump_bc() -> list[str]:
    Atspi = _atspi()
    if Atspi is None:
        return ["atspi unavailable"]
    lines = []
    desktop = Atspi.get_desktop(0)
    for i in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(i)
        try:
            aname = app.get_name() or ""
        except Exception:
            continue
        if not any(s in aname.lower() for s in ("bcompare", "beyond", "scooter", "compare")):
            continue
        lines.append(f"APP {aname}")
        for node, d in _iter_acc(app, limit=250):
            try:
                n = node.get_name() or ""
                r = node.get_role_name() or ""
            except Exception:
                continue
            if n or r in ("push button", "text", "entry", "menu item", "frame"):
                lines.append(f"{'  '*d}{r}: {n!r}")
    return lines or ["no BC atspi app"]


# --- UI flow ---------------------------------------------------------------

def dismiss_error() -> None:
    wid = find_wid(ERROR)
    if not wid:
        return
    print("dismiss Error", flush=True)
    activate(wid)
    btn = atspi_find(name_substr="OK", role="push button")
    if btn:
        atspi_do(btn, "click")
    else:
        key_in_window(wid, "Return")
    time.sleep(0.4)


def open_register() -> str | None:
    wid = find_wid(REGISTER)
    if wid:
        return wid

    # Evaluation dialog often has Enter Key
    ev = find_wid("evaluation") or find_wid("trial")
    if ev:
        print("eval dialog — trying Enter Key button", flush=True)
        activate(ev)
        btn = atspi_find(name_substr="Enter Key", role="push button")
        if btn:
            atspi_do(btn, "click")
            time.sleep(1.0)
            return find_wid(REGISTER)

    home = find_wid(HOME)
    if not home:
        return None
    print("opening Help -> Enter Key", flush=True)
    activate(home)
    item = atspi_find(name_substr="Enter Key", role="menu item")
    if item:
        atspi_do(item, "click")
        time.sleep(1.0)
        return find_wid(REGISTER)

    key_in_window(home, "alt+h")
    time.sleep(0.4)
    key_in_window(home, "e")
    time.sleep(1.0)
    return find_wid(REGISTER)


def fill_and_ok(key: str) -> None:
    wid = open_register()
    if not wid:
        raise RuntimeError(f"Register window not found. titles={titles()!r}")
    print(f"Register wid={wid}", flush=True)
    activate(wid)

    text_node = (
        atspi_find(role="text")
        or atspi_find(role="entry")
        or atspi_find(role="terminal")
    )
    if text_node and atspi_set_text(text_node, key):
        print("AT-SPI set_text ok", flush=True)
    else:
        print("clipboard paste into Register", flush=True)
        geom = run(["xdotool", "getwindowgeometry", wid]).stdout
        # click into the big edit (upper-middle of 644x325 dialog)
        xdotool_click_window(wid, 320, 120)
        key_in_window(wid, "ctrl+a")
        time.sleep(0.1)
        paste_clipboard(wid, key)

    time.sleep(0.3)
    ok = atspi_find(name_substr="OK", role="push button")
    # prefer the Register dialog OK, not a leftover Error OK
    if ok:
        print("click OK (AT-SPI)", flush=True)
        atspi_do(ok, "click")
    else:
        print("click OK (xdotool Return / button)", flush=True)
        activate(wid)
        xdotool_click_window(wid, 590, 300)
    time.sleep(1.0)


def wait_gui(timeout: float) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        ts = titles()
        interesting = [t for t in ts if any(s in t for s in ("Beyond Compare", "BCompare", "Register", "Error"))]
        if interesting:
            print(f"windows: {interesting}", flush=True)
            if any(HOME in t or REGISTER in t or "evaluation" in t.lower() for t in ts):
                return
        time.sleep(0.5)
    raise TimeoutError(f"no BC windows after {timeout}s; titles={titles()!r}")


def stop_bc_and_our_gdb() -> None:
    """Kill only BCompare and gdb that loaded bc_gdb_starti.gdb. Never pkill gdb."""
    run(["pkill", "-x", "BCompare"])
    try:
        out = subprocess.check_output(["pgrep", "-a", "gdb"], text=True)
    except subprocess.CalledProcessError:
        out = ""
    for line in out.splitlines():
        if "bc_gdb_starti" in line:
            pid = line.split()[0]
            run(["kill", pid])
    time.sleep(0.8)


def start_gdb() -> subprocess.Popen:
    stop_bc_and_our_gdb()
    GDB_LOG.write_text("")
    HIT_LOG.write_text("")
    print(f"gdb -x {GDB_SCRIPT}", flush=True)
    proc = subprocess.Popen(
        ["gdb", "-q", "-x", str(GDB_SCRIPT)],
        stdout=GDB_LOG.open("a"),
        stderr=subprocess.STDOUT,
        cwd=str(INSTALL),
        env={**os.environ, "LD_LIBRARY_PATH": str(INSTALL)},
    )
    return proc


def hits_since(before: str) -> list[str]:
    cur = HIT_LOG.read_text() if HIT_LOG.is_file() else ""
    if cur.startswith(before):
        return [ln for ln in cur[len(before) :].splitlines() if ln.startswith("HIT ")]
    return [ln for ln in cur.splitlines() if ln.startswith("HIT ")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-gdb", action="store_true")
    ap.add_argument("--keep", action="store_true", help="do not kill/restart BC")
    ap.add_argument("--key", default=DUMMY_KEY)
    ap.add_argument("--wait", type=float, default=20.0)
    ap.add_argument("--dump-tree", action="store_true")
    args = ap.parse_args()

    if args.dump_tree:
        print("\n".join(atspi_dump_bc()))
        return 0

    gdb_proc = None
    if args.no_gdb:
        if not args.keep:
            run(["pkill", "-x", "BCompare"])
            time.sleep(0.5)
            env = {**os.environ, "LD_LIBRARY_PATH": str(INSTALL)}
            subprocess.Popen([str(EXE)], cwd=str(INSTALL), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_gui(args.wait)
    else:
        if not args.keep:
            gdb_proc = start_gdb()
        wait_gui(args.wait)

    dismiss_error()
    before = HIT_LOG.read_text() if HIT_LOG.is_file() else ""
    fill_and_ok(args.key)
    time.sleep(2.0)
    dismiss_error()

    new_hits = hits_since(before)
    print("--- windows after ---", flush=True)
    for t in titles():
        if any(s in t.lower() for s in ("beyond", "compare", "register", "error", "bcompare")):
            print(f"  {t}", flush=True)
    print("--- gdb HITs after OK ---", flush=True)
    if new_hits:
        print("\n".join(new_hits), flush=True)
    else:
        print("(none — check /tmp/bc_gdb_hits.log and /tmp/bc_gdb_license.log)", flush=True)
        if HIT_LOG.is_file():
            print(HIT_LOG.read_text()[-2000:], flush=True)

    print(f"gdb_log={GDB_LOG} hits={HIT_LOG}", flush=True)
    if gdb_proc is not None:
        print(f"gdb still running pid={gdb_proc.pid} — kill that pid only, not `pkill gdb`", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        print("titles:", titles(), file=sys.stderr)
        print("\n".join(atspi_dump_bc()), file=sys.stderr)
        sys.exit(1)
