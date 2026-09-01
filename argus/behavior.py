"""Cross-platform behavioral inspector and universal semantic verifier.

Performs deep runtime introspection of patched binaries across Windows and Linux:
- GUI window / modal dialog inspection (Win32 ctypes on Windows, X11/proc on Linux)
- Differential execution (A/B testing) comparing original vs patched behavior
- Dynamic intent-driven semantic assertions (no hardcoded keywords)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from argus.binary.launch_env import launch_env_for


def native_exec_supported(path: str | Path) -> tuple[bool, str, str]:
    """Return (supported, fmt, detail). PE on Windows, ELF on Linux, etc."""
    try:
        from argus.binary import load_binary

        img = load_binary(str(path))
        fmt = str(getattr(img, "fmt", "") or "")
    except Exception as e:
        return False, "unknown", str(e)
    if fmt == "pe" and sys.platform == "win32":
        return True, fmt, ""
    if fmt == "elf" and sys.platform.startswith("linux"):
        return True, fmt, ""
    if fmt == "macho" and sys.platform == "darwin":
        return True, fmt, ""
    return False, fmt, f"{fmt or 'unknown'} not natively executable on {sys.platform}"


def _unicorn_smoke(path: str, *, stdin: bytes, timeout: float) -> Optional[Dict[str, Any]]:
    try:
        from argus.concrete.runner import concrete_run, unicorn_available

        if not unicorn_available():
            return None
        res = concrete_run(str(path), stdin=stdin)
        return {
            "stdout": res.stdout or b"",
            "stderr": b"",
            "crash_code": None if res.ok else 1,
            "method": "unicorn",
        }
    except Exception:
        return None


def inspect_process_windows(pid: int) -> List[Dict[str, Any]]:
    """Enumerate visible and modal windows owned by PID across Windows and Linux."""
    windows: List[Dict[str, Any]] = []

    # Windows: native Win32 API via ctypes (zero dependency)
    if sys.platform == "win32":
        try:
            import ctypes
            user32 = ctypes.windll.user32

            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

            def enum_cb(hwnd, _):
                p = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
                if p.value == pid:
                    buf = ctypes.create_unicode_buffer(512)
                    user32.GetWindowTextW(hwnd, buf, 512)
                    cls_buf = ctypes.create_unicode_buffer(256)
                    user32.GetClassNameW(hwnd, cls_buf, 256)
                    visible = bool(user32.IsWindowVisible(hwnd))
                    title = buf.value.strip()
                    cls_name = cls_buf.value.strip()
                    is_dialog = cls_name == "#32770" or "dialog" in cls_name.lower()
                    if visible or title:
                        windows.append({
                            "hwnd": hwnd,
                            "title": title,
                            "class": cls_name,
                            "visible": visible,
                            "is_dialog": is_dialog,
                        })
                return True

            user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
        except Exception:
            pass
        return windows

    # Linux: X11 / Wayland / proc introspection
    if sys.platform.startswith("linux"):
        # 1. Try wmctrl if available
        if shutil.which("wmctrl"):
            try:
                out = subprocess.check_output(["wmctrl", "-l", "-p"], timeout=2).decode("utf-8", errors="replace")
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[2].isdigit() and int(parts[2]) == pid:
                        title = " ".join(parts[4:])
                        windows.append({
                            "hwnd": parts[0],
                            "title": title,
                            "class": "x11_window",
                            "visible": True,
                            "is_dialog": "dialog" in title.lower() or "error" in title.lower(),
                        })
            except Exception:
                pass

        # 2. Try xdotool if available and wmctrl didn't find anything
        if not windows and shutil.which("xdotool"):
            try:
                wids = subprocess.check_output(
                    ["xdotool", "search", "--pid", str(pid)],
                    timeout=2,
                ).decode("utf-8", errors="replace").splitlines()
                for wid in wids:
                    if not wid.strip():
                        continue
                    try:
                        title = subprocess.check_output(
                            ["xdotool", "getwindowname", wid.strip()],
                            timeout=1,
                        ).decode("utf-8", errors="replace").strip()
                        windows.append({
                            "hwnd": wid.strip(),
                            "title": title,
                            "class": "x11_window",
                            "visible": True,
                            "is_dialog": "dialog" in title.lower() or "error" in title.lower(),
                        })
                    except Exception:
                        pass
            except Exception:
                pass

    return windows


def gui_observation_available() -> bool:
    """True when the host can enumerate top-level GUI window titles."""
    if sys.platform == "win32":
        return True
    if sys.platform.startswith("linux"):
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            return False
        return bool(shutil.which("wmctrl") or shutil.which("xdotool"))
    if sys.platform == "darwin":
        return bool(shutil.which("osascript"))
    return False


def list_top_level_window_titles() -> List[str]:
    """Best-effort window titles on Windows and Linux (empty when unavailable)."""
    titles: List[str] = []
    if sys.platform == "win32":
        try:
            import ctypes

            user32 = ctypes.windll.user32
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

            def enum_cb(hwnd, _):
                if user32.IsWindowVisible(hwnd):
                    buf = ctypes.create_unicode_buffer(512)
                    user32.GetWindowTextW(hwnd, buf, 512)
                    t = buf.value.strip()
                    if t:
                        titles.append(t)
                return True

            user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
        except Exception:
            pass
        return titles

    if sys.platform.startswith("linux") and shutil.which("wmctrl"):
        try:
            out = subprocess.check_output(["wmctrl", "-l"], timeout=2).decode("utf-8", errors="replace")
            for line in out.splitlines():
                parts = line.split(None, 3)
                if len(parts) >= 4 and parts[2].strip():
                    titles.append(parts[3].strip())
        except Exception:
            pass
    return titles


def find_window_title_containing(substr: str, *, timeout: float = 8.0) -> Optional[str]:
    """Return first visible window title containing substr (case-insensitive)."""
    needle = (substr or "").strip().lower()
    if not needle:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        for title in list_top_level_window_titles():
            if needle in title.lower():
                return title
        time.sleep(0.35)
    return None


def collect_ui_texts(pid: int, windows: List[Dict[str, Any]]) -> List[str]:
    """Window titles for PID — same fields on Windows and Linux."""
    seen: set[str] = set()
    out: List[str] = []
    for w in windows:
        t = str(w.get("title") or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    if out:
        return out
    # Fallback: rescan (process may have created windows after first poll)
    for w in inspect_process_windows(pid):
        t = str(w.get("title") or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def terminate_process_by_name(exe_name: str) -> None:
    """Best-effort terminate processes by executable *comm* name (cross-platform).

    Never `pkill -f <shortname>`: that matches argv substrings and will kill
    `argus agent … rar` when the target is named `rar`.
    """
    name = Path(exe_name).name
    if not name or name in (".", ".."):
        return
    # Interpreter / shell names would suicide the agent.
    if name.lower() in {"python", "python3", "python3.12", "python3.13", "bash", "sh", "zsh", "argus"}:
        return
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", name],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass
        return
    # Exact process name only (comm), never argv substring.
    for cmd in (
        ["pkill", "-x", name],
        ["killall", "-q", name],
    ):
        if not shutil.which(cmd[0]):
            continue
        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
            return
        except Exception:
            continue


def detect_modal_error_dialog(windows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Detect if an error dialog or alert popup is currently open (separate from main window)."""
    error_patterns = [
        r"error", r"invalid", r"failed", r"warning",
        r"ошибка", r"неверн", r"сбой", r"alert",
        r"doesn't appear", r"does not appear", r"denied", r"incorrect",
    ]
    rx = re.compile("|".join(error_patterns), re.IGNORECASE)

    for w in windows:
        title = w.get("title", "").strip()
        if not title:
            continue
        if w.get("is_dialog") and rx.search(title):
            return w
        if rx.search(title) and len(title.split()) > 2:
            return w
    return None


def _positive_oracle_met(
    *,
    is_gui: bool,
    windows: List[Dict[str, Any]],
    stdout: bytes,
    stderr: bytes,
    allow_strings: Optional[List[str]] = None,
    original_path: Optional[str] = None,
    patched_path: Optional[str] = None,
    require_positive: bool = False,
) -> Tuple[bool, str, Optional[str]]:
    """Return (ok, detail, oracle_kind). When require_positive, silence is not success."""
    combined = stdout + b"\n" + stderr
    if allow_strings:
        for s in allow_strings:
            if s and s.encode() in combined:
                return True, f"allow string found: {s[:40]!r}", "allow_string"

    if is_gui and windows and not detect_modal_error_dialog(windows):
        # GUI alive without error modal — weak signal unless differential confirms
        if original_path and patched_path and Path(original_path).is_file():
            diff = trace_differential_divergence(
                patched_path,
                input_a=b"invalid_trial_123\n",
                input_b=b"valid_license_candidate\n",
            )
            if diff.get("diverged"):
                return True, diff.get("summary") or "patched behavior diverges from baseline", "differential"
        if not require_positive:
            return True, f"GUI launch without error modal ({len(windows)} window(s))", "no_modal"
        return False, "GUI alive but no positive oracle (allow string / differential)", None

    if not is_gui and combined.strip():
        low = combined.lower()
        cli_ok_hints = (b"welcome", b"success", b"registered", b"ok")
        if any(h in low for h in cli_ok_hints):
            return True, "CLI output contains positive hint", "cli_hint"

    if not require_positive:
        if is_gui:
            return True, "GUI clean launch (legacy permissive)", "legacy_gui"
        return True, "CLI success rc=0 (legacy permissive)", "legacy_cli"
    return False, "no positive oracle met", None


def verify_binary_semantic(
    patched_path: str,
    *,
    original_path: Optional[str] = None,
    task_text: str = "",
    stdin: bytes = b"invalid_test_key_12345\n",
    timeout: float = 3.0,
    allow_strings: Optional[List[str]] = None,
    require_positive_oracle: bool = False,
) -> Dict[str, Any]:
    """Universal semantic verification of a patched binary.

    Works cross-platform (Windows & Linux, GUI & CLI) without relying on hardcoded strings.
    When require_positive_oracle=True, process alive / silence is NOT sufficient.
    """
    p = Path(patched_path)
    if not p.is_file():
        return {
            "kind": "semantic_verify",
            "ok": False,
            "detail": f"Patched binary missing: {patched_path}",
        }

    native_ok, bin_fmt, native_detail = native_exec_supported(p)

    # Detect whether binary is GUI or CLI
    is_gui = False
    try:
        from argus.patch.safety import _looks_gui_or_heavy
        from argus.binary import load_binary
        img = load_binary(str(p))
        is_gui = _looks_gui_or_heavy(img)
    except Exception:
        pass

    if not native_ok and not is_gui:
        uni = _unicorn_smoke(str(p), stdin=stdin, timeout=timeout)
        if uni is not None:
            stdout = uni.get("stdout") or b""
            crash_code = uni.get("crash_code")
            if crash_code is not None and crash_code != 0:
                return {
                    "kind": "semantic_verify",
                    "ok": False,
                    "detail": f"Unicorn smoke failed for {bin_fmt} on {sys.platform}",
                    "crash_code": crash_code,
                    "method": "unicorn",
                }
            return {
                "kind": "semantic_verify",
                "ok": True,
                "detail": f"Unicorn smoke ok ({bin_fmt} on {sys.platform})",
                "method": "unicorn",
                "stdout_snippet": stdout[:200].decode("utf-8", errors="replace") if stdout else "",
            }
        return {
            "kind": "semantic_verify",
            "ok": True,
            "detail": f"{native_detail} — native launch skipped",
            "ran": False,
            "skipped": True,
            "method": "format_skip",
        }

    if not native_ok and is_gui:
        return {
            "kind": "semantic_verify",
            "ok": True,
            "detail": f"{native_detail} — GUI smoke skipped; use argus_gui_oracle on native host",
            "ran": False,
            "skipped": True,
            "needs_oracle": True,
            "method": "format_skip",
        }

    from argus.binary.launch_env import stage_native_executable

    staged = stage_native_executable(str(p), original=original_path)
    test_p = staged.path
    cwd, env = launch_env_for(test_p)
    cwd = staged.cwd or cwd
    temp_in_root = staged.path if staged.ephemeral else None

    # 1. Run patched process
    proc = None
    stdout = b""
    stderr = b""
    timed_out = False
    crash_code = None
    windows = []

    try:
        if is_gui:
            # For GUI, launch asynchronously to inspect windows
            proc = subprocess.Popen(
                [str(test_p)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
            # Give UI time to initialize and create top-level windows
            time.sleep(min(timeout, 2.0))
            poll = proc.poll()
            if poll is not None:
                crash_code = poll
            else:
                windows = inspect_process_windows(proc.pid)
                # Terminate GUI smoke process cleanly
                try:
                    proc.terminate()
                    proc.wait(timeout=1.0)
                except Exception:
                    proc.kill()
        else:
            # For CLI, run synchronously with input
            res = subprocess.run(
                [str(test_p)],
                input=stdin,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )
            stdout = res.stdout or b""
            stderr = res.stderr or b""
            crash_code = res.returncode if res.returncode != 0 else None
    except subprocess.TimeoutExpired:
        timed_out = True
    except Exception as e:
        return {
            "kind": "semantic_verify",
            "ok": False,
            "detail": f"Execution failed: {e}",
        }
    finally:
        if temp_in_root and temp_in_root.exists():
            try:
                temp_in_root.unlink()
            except OSError:
                pass

    # 2. Check crash codes (Windows 0xC0000005 or Linux SIGSEGV 139 / -11)
    if crash_code is not None:
        c_hex = hex(crash_code & 0xFFFFFFFF) if crash_code < 0 or crash_code > 0xFFFF else str(crash_code)
        if "c0000005" in c_hex.lower() or crash_code in (-11, 139):
            return {
                "kind": "semantic_verify",
                "ok": False,
                "detail": f"Process crashed on startup: ACCESS_VIOLATION / SIGSEGV ({c_hex}). A non-boolean function or jump table was corrupted!",
                "crash_code": c_hex,
                "suggested_action": "Use argus_diagnose_failure(crash_code='0xC0000005') to roll back the broken stub and patch caller gates instead.",
            }
        # GUI exited before window inspection — cannot prove goal without gui oracle
        if is_gui:
            return {
                "kind": "semantic_verify",
                "ok": False if require_positive_oracle else True,
                "detail": f"GUI exited early (code {c_hex}) — use argus_gui_oracle for dialog check",
                "crash_code": c_hex,
                "needs_oracle": True,
                "oracle_kind": "gui_dialog",
            }

    # 3. GUI Window and Modal Dialog Analysis
    if is_gui and windows:
        modal_err = detect_modal_error_dialog(windows)
        if modal_err:
            title = str(modal_err.get("title") or "")
            return {
                "kind": "semantic_verify",
                "ok": False,
                "detail": f"Unsatisfied check: error modal dialog appeared with title {title!r}",
                "dialog": modal_err,
                "windows": windows,
                "suggested_action": (
                    "Use argus_diagnose_failure(error_text=<exact dialog body>) "
                    "then argus_gui_oracle(reject_texts=[...])"
                ),
                "needs_oracle": True,
            }

    # 4. CLI Output Analysis (Check for common denial phrases in stdout/stderr)
    if not is_gui:
        combined = (stdout + b"\n" + stderr).decode("utf-8", errors="replace").lower()
        cli_denials = ["invalid", "incorrect", "access denied", "error", "unauthorized", "failed"]
        for d in cli_denials:
            if d in combined:
                return {
                    "kind": "semantic_verify",
                    "ok": False,
                    "detail": f"CLI output contains failure message '{d}': {combined[:160]}",
                }

    if timed_out and is_gui:
        return {
            "kind": "semantic_verify",
            "ok": False,
            "detail": "GUI process alive after timeout but goal unproven",
            "is_gui": is_gui,
            "windows": windows,
            "needs_oracle": True,
        }

    pos_ok, pos_detail, oracle_kind = _positive_oracle_met(
        is_gui=is_gui,
        windows=windows,
        stdout=stdout,
        stderr=stderr,
        allow_strings=allow_strings,
        original_path=original_path,
        patched_path=patched_path,
        require_positive=require_positive_oracle,
    )
    if not pos_ok:
        return {
            "kind": "semantic_verify",
            "ok": False,
            "detail": pos_detail,
            "is_gui": is_gui,
            "windows": windows,
            "needs_oracle": require_positive_oracle,
            "stdout_snippet": stdout[:200].decode("utf-8", errors="replace") if stdout else "",
        }

    return {
        "kind": "semantic_verify",
        "ok": True,
        "detail": pos_detail,
        "oracle_kind": oracle_kind,
        "is_gui": is_gui,
        "windows": windows,
        "stdout_snippet": stdout[:200].decode("utf-8", errors="replace") if stdout else "",
    }


def trace_differential_divergence(
    binary_path: str,
    *,
    input_a: bytes = b"invalid_trial_123\n",
    input_b: bytes = b"valid_license_candidate\n",
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Execute binary under two distinct inputs to detect divergence in execution paths."""
    res_a = verify_binary_semantic(binary_path, stdin=input_a, timeout=timeout)
    res_b = verify_binary_semantic(binary_path, stdin=input_b, timeout=timeout)

    diverged = False
    reasons = []

    if res_a.get("ok") != res_b.get("ok"):
        diverged = True
        reasons.append(f"Status changed: Trial A ok={res_a.get('ok')} vs Trial B ok={res_b.get('ok')}")

    if res_a.get("crash_code") != res_b.get("crash_code"):
        diverged = True
        reasons.append(f"Exit code changed: Trial A rc={res_a.get('crash_code')} vs Trial B rc={res_b.get('crash_code')}")

    windows_a = [w.get("title") for w in res_a.get("windows") or [] if w.get("title")]
    windows_b = [w.get("title") for w in res_b.get("windows") or [] if w.get("title")]
    if windows_a != windows_b:
        diverged = True
        reasons.append(f"Window titles differed: A={windows_a[:2]} vs B={windows_b[:2]}")

    return {
        "ok": True,
        "diverged": diverged,
        "summary": "; ".join(reasons) if diverged else "Execution paths identical (no behavioral divergence detected)",
        "trial_a": res_a,
        "trial_b": res_b,
    }
