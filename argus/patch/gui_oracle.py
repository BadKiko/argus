"""Desktop GUI launch oracle — observe only, no keyboard input.



Cross-platform (Windows + Linux): staged launch from install dir, crash check,

optional window/modal/reject_text observation when the host supports GUI introspection.

Does NOT type license keys — user confirms key acceptance manually.

"""



from __future__ import annotations



import re

import subprocess

import sys

import time

from pathlib import Path

from typing import Any, Dict, List, Optional



from argus.behavior import (

    collect_ui_texts,

    detect_modal_error_dialog,

    find_window_title_containing,

    gui_observation_available,

    inspect_process_windows,

    list_top_level_window_titles,

    terminate_process_by_name,

)

from argus.binary.file_io import release_binary_lock



_ERROR_BODY_RX = re.compile(

    r"(error loading|unable to find|failed to|could not load|fatal error|"

    r"exception|access violation)",

    re.IGNORECASE,

)



_SIGSEGV_CODES = frozenset({-11, 139, -1073741819, 3221225477, 0xC0000005})





def close_process(exe_path: str | Path) -> None:

    """Terminate process by executable file name."""

    terminate_process_by_name(str(exe_path))





def list_top_windows() -> List[str]:

    """Legacy helper — cross-platform window title list."""

    return list_top_level_window_titles()





def _find_window_containing(substr: str, *, timeout: float = 8.0):

    """Legacy compat for gui_watch — returns title string or None."""

    return find_window_title_containing(substr, timeout=timeout)





_DEFAULT_REJECT_UI = (
    "30-day",
    "evaluation period",
    "trial expired",
    "purchase a license",
    "not registered",
    "invalid license",
    "unregistered",
)


def _merged_reject_texts(reject_texts: Optional[List[str]]) -> List[str]:
    merged: List[str] = []
    seen: set[str] = set()
    for raw in list(reject_texts or []) + list(_DEFAULT_REJECT_UI):
        needle = (raw or "").strip()
        low = needle.lower()
        if len(needle) < 4 or low in seen:
            continue
        seen.add(low)
        merged.append(needle)
    return merged


def _match_reject(texts: List[str], reject_texts: List[str]) -> List[str]:
    hits: List[str] = []
    if not reject_texts:
        return hits
    blob = "\n".join(texts).lower()
    for raw in reject_texts:
        needle = (raw or "").strip()
        if len(needle) < 4:
            continue
        if needle.lower() in blob:
            hits.append(needle[:120])
    return hits





def _match_error_body(texts: List[str]) -> Optional[str]:

    for t in texts:

        if _ERROR_BODY_RX.search(t):

            return t[:160]

    return None





def _is_crash_code(code: Optional[int]) -> bool:

    if code is None:

        return False

    if code == 0:

        return False

    if code in _SIGSEGV_CODES:

        return True

    if code < 0:

        return True

    return code != 0





def observe_gui_launch(

    exe_path: str,

    *,

    original: Optional[str] = None,

    cwd: Optional[str] = None,

    main_window_hint: Optional[str] = None,

    reject_texts: Optional[List[str]] = None,

    settle_s: float = 3.0,

    launch_timeout: float = 14.0,

) -> Dict[str, Any]:

    """Launch from install dir, observe windows — no keyboard input."""

    exe = Path(exe_path)

    if not exe.is_file():

        return {

            "ok": False,

            "kind": "gui_launch_oracle",

            "detail": f"missing {exe_path}",

            "ran": False,

            "no_keyboard_input": True,

        }



    orig = original

    if not orig:

        try:

            from argus.llm.session import get_session



            orig = get_session().original_binary or None

        except Exception:

            orig = None



    from argus.binary.launch_env import launch_env_for, stage_native_executable



    close_process(exe)

    time.sleep(0.4)

    staged = stage_native_executable(exe, original=orig)

    launch_exe = staged.path

    launch_cwd, launch_env = launch_env_for(launch_exe)

    workdir = cwd or staged.cwd or launch_cwd

    hint = (main_window_hint or launch_exe.stem or exe.stem).strip()

    obs_available = gui_observation_available()



    proc = subprocess.Popen(

        [str(launch_exe)],

        cwd=workdir,

        env=launch_env,

        stdout=subprocess.DEVNULL,

        stderr=subprocess.DEVNULL,

    )

    pid = proc.pid

    windows: List[Dict[str, Any]] = []

    crash_code: Optional[int] = None



    try:

        deadline = time.time() + launch_timeout

        while time.time() < deadline:

            poll = proc.poll()

            if poll is not None:

                crash_code = int(poll)

                break

            if obs_available:

                windows = inspect_process_windows(pid)

                if windows and any(w.get("visible") for w in windows):

                    break

            time.sleep(0.35)



        if crash_code is None:

            time.sleep(settle_s)

            poll = proc.poll()

            if poll is not None:

                crash_code = int(poll)

            elif obs_available:

                windows = inspect_process_windows(pid)



        ui_texts = collect_ui_texts(pid, windows) if obs_available else []

        modal_err = detect_modal_error_dialog(windows) if obs_available else None

        body_err = _match_error_body(ui_texts) if ui_texts else None

        reject_hits = _match_reject(ui_texts, _merged_reject_texts(reject_texts))



        ok = True

        detail_parts: List[str] = []



        if _is_crash_code(crash_code):

            ok = False

            detail_parts.append(f"process exited code={crash_code}")



        still_alive = proc.poll() is None



        if not windows and ok:

            if still_alive and not obs_available:

                detail_parts.append(

                    "process alive; GUI titles unavailable (headless or install wmctrl/xdotool)"

                )

            elif still_alive and obs_available:

                detail_parts.append("process alive but no windows detected")

            else:

                ok = False

                detail_parts.append("no windows for process")



        if modal_err and ok:

            ok = False

            detail_parts.append(

                f"error modal: {modal_err.get('title') or modal_err!r}"

            )



        if body_err and ok:

            ok = False

            detail_parts.append(f"error text visible: {body_err!r}")



        if reject_hits and ok:

            ok = False

            detail_parts.append(f"reject_text visible: {reject_hits[0]!r}")



        if ok:

            main_seen = any(hint.lower() in (w.get("title") or "").lower() for w in windows)

            if not main_seen and hint and obs_available:

                main_seen = find_window_title_containing(hint, timeout=2.0) is not None

            if obs_available and windows:

                detail_parts.append(

                    f"GUI launch ok from install cwd ({len(windows)} window(s))"

                    + ("" if main_seen or not hint else f"; hint {hint!r} not matched")

                )

            elif still_alive:

                detail_parts.append(f"launch ok from install cwd (pid={pid})")



        detail = "; ".join(detail_parts) or "gui launch oracle"

        level = "EXECUTION_VERIFIED" if ok else "UNKNOWN"



        return {

            "ok": ok,

            "kind": "gui_launch_oracle",

            "level": level,

            "detail": detail,

            "ran": True,

            "no_keyboard_input": True,

            "platform": sys.platform,

            "gui_observation": obs_available,

            "crash_code": crash_code,

            "windows": windows[:12],

            "ui_texts": ui_texts[:20],

            "reject_hits": reject_hits,

            "error_modal": modal_err,

            "install_cwd": workdir,

            "staged_exe": str(launch_exe),

            "staged_from": str(exe),

            "pid": pid,

            "manual_note": (

                "Launch oracle observes idle UI only — validation input path is not exercised."

            ),

        }

    finally:

        try:

            proc.terminate()

            proc.wait(timeout=2.0)

        except Exception:

            try:

                proc.kill()

            except Exception:

                pass

        close_process(launch_exe)
        release_binary_lock(launch_exe)
        time.sleep(0.3)





def verify_gui_oracle(

    exe_path: str,

    *,

    cwd: Optional[str] = None,

    main_window_hint: Optional[str] = None,

    dialog_hint: Optional[str] = None,

    junk_input: str = "hkj",

    reject_texts: Optional[List[str]] = None,

    settle_s: float = 2.5,

) -> Dict[str, Any]:

    """Launch staged exe and observe — no dialog typing."""

    _ = dialog_hint, junk_input

    return observe_gui_launch(

        exe_path,

        cwd=cwd,

        main_window_hint=main_window_hint,

        reject_texts=reject_texts,

        settle_s=settle_s,

    )





# Legacy aliases (deprecated)

def close_sublime_merge() -> None:

    close_process("sublime_merge.exe")


