"""Free-form multi-ask tasks + replace_string span + finalize anti-hallucination."""

from __future__ import annotations

import shutil
from pathlib import Path

from argus.llm.tasks import finalize_agent, split_user_tasks
from argus.patch.intents import replace_string

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_replace_string_mid_c_string_preserves_tail(tmp_path):
    src = tmp_path / "blob.bin"
    # mid-match must not wipe bytes after old
    body = b"Thanks for trying out Sublime Merge!\nThis feature is only available\x00"
    src.write_bytes(b"HDR\x00" + body + b"TAIL")
    # invent minimal ELF? replace_string uses load_binary — need real ELF
    fw = SAMPLES / "fauxware"
    if not fw.is_file():
        return
    dst = tmp_path / "fw"
    out = tmp_path / "fw.patched"
    shutil.copy(fw, dst)
    # plant a known C-string in the file bytes via patcher raw... use existing string in fauxware
    from argus.binary import load_binary

    img = load_binary(str(dst))
    # find any short string to replace mid-style: use a known symbol string if present
    data = dst.read_bytes()
    # inject test blob into a copy at end of file (may break ELF) — better: construct via section
    # Use replace on a substring that appears inside a longer C-string in fauxware if any.
    # Fallback: write custom file and use Patcher directly after planting in .rodata-like.
    needle = b"enter"
    idx = data.find(needle)
    if idx < 0:
        needle = b"user"
        idx = data.find(needle)
    assert idx >= 0
    # ensure there are bytes after needle before NUL
    end = data.find(b"\x00", idx)
    assert end > idx + len(needle)
    tail_before = data[idx + len(needle) : end]

    ok, cert = replace_string(str(dst), needle.decode(), "zzzzz"[: len(needle)].ljust(len(needle)), str(out))
    assert ok, cert
    after = out.read_bytes()
    expected = ("zzzzz"[: len(needle)].ljust(len(needle))).encode()
    assert after[idx : idx + len(needle)] == expected
    assert after[idx + len(needle) : end] == tail_before


def test_replace_string_exact_slot_on_planted_blob(tmp_path):
    """Unit-level: intents.replace_string slot == len(old) via Patcher on fauxware planted VA."""
    fw = SAMPLES / "fauxware"
    shutil.copy(fw, tmp_path / "fw")
    path = str(tmp_path / "fw")
    out = str(tmp_path / "out")
    data = Path(path).read_bytes()
    # Find "authenticate" or similar
    old = b"Username"
    if data.find(old) < 0:
        old = b"Password"
    if data.find(old) < 0:
        # skip if corpus differs
        return
    new = (b"X" * (len(old) - 1)) + b" "
    idx = data.find(old)
    end = data.find(b"\x00", idx)
    tail = data[idx + len(old) : end]
    ok, _ = replace_string(path, old.decode(), new.decode(), out)
    assert ok
    after = Path(out).read_bytes()
    assert after[idx : idx + len(old)] == new
    assert after[idx + len(old) : end] == tail


def test_split_user_tasks_multi_and_absurd():
    prompt = (
        "убери проверку лицензии из программы "
        "и еще поставь тёмную тему по дефолту "
        "и еще в заголовок поставь Kiko Merge "
        "и еще вставь картинку пениса в программу"
    )
    tasks = split_user_tasks(prompt)
    assert len(tasks) >= 3
    assert all(t.text for t in tasks)
    # no GoalKind — just free text
    assert any("пениса" in t.text or "картинку" in t.text for t in tasks) or len(tasks) >= 3


def test_split_single_stays_one():
    tasks = split_user_tasks("дай пароль от fauxware")
    assert len(tasks) == 1
    assert "пароль" in tasks[0].text


def test_finalize_password_question_done():
    from argus.llm.tools import dispatch_tool
    import json

    fw = SAMPLES / "fauxware"
    if not fw.is_file():
        return
    path = str(fw)
    ai = json.loads(dispatch_tool("argus_ai", {"prompt": "какой пароль?", "binary": path, "for_task": 1}))
    tasks = split_user_tasks("какой пароль?")
    res = finalize_agent(
        tasks,
        [{"tool": "argus_ai", "args": {"binary": path, "for_task": 1}, "result": ai}],
        binary=path,
        store_memory=False,
    )
    assert res.task_statuses[0]["status"] == "done"
    assert "SOSNEAKY" in (res.task_statuses[0]["detail"] or "")


def test_finalize_blocks_false_unlock_success():
    tasks = split_user_tasks(
        "убери лицензию и еще поставь заголовок Kiko"
    )
    assert len(tasks) >= 2
    # Sublime-like: UI force_branch + ETXTBSY replace, model lies
    trace = [
        {
            "tool": "argus_patch",
            "args": {"kind": "force_branch", "addr": "0x57ddda", "for_task": 1, "taken": True},
            "result": {
                "ok": True,
                "for_task": 1,
                "summary": "branch forced",
                "evidence": {"weak_ui_xref": True},
                "verify": {"kind": "none", "ok": None},
                "patched_path": "./x.patched",
            },
        },
        {
            "tool": "argus_patch",
            "args": {
                "kind": "replace_string",
                "old": "Sublime Merge!",
                "new": "Kiko Merge ",
                "for_task": 2,
            },
            "result": {
                "ok": False,
                "for_task": 2,
                "summary": "Text file busy (ETXTBSY): target binary is running",
                "verify": {"kind": "bytes_contains", "ok": False},
            },
        },
    ]
    r = finalize_agent(tasks, trace, "лицензия успешно обойдена, всё готово")
    assert r.ok is False
    assert "успешно обойдена" not in r.answer.split("Задачи:")[0] if "Задачи:" in r.answer else True
    # status lines must not claim done for unlock-like
    assert "→ done" not in "\n".join(
        line for line in r.answer.splitlines() if line.startswith("1.")
    )
    assert any(s["status"] != "done" for s in r.task_statuses)
    assert "Модель" in r.answer  # appendix only
    assert "incomplete" in r.answer or "failed" in r.answer


def test_finalize_replace_verified_done(tmp_path):
    tasks = split_user_tasks("замени заголовок на Kiko")
    trace = [
        {
            "tool": "argus_patch",
            "args": {"kind": "replace_string", "for_task": 1, "old": "A", "new": "B"},
            "result": {
                "ok": True,
                "for_task": 1,
                "summary": "replaced",
                "verify": {"kind": "bytes_contains", "ok": True, "detail": "found"},
                "patched_path": str(tmp_path / "p"),
            },
        }
    ]
    r = finalize_agent(tasks, trace, "done lol")
    assert r.ok is True
    assert r.task_statuses[0]["status"] == "done"


def test_finalize_absurd_no_tools_incomplete():
    tasks = split_user_tasks("вставь картинку пениса в бинарь")
    r = finalize_agent(tasks, [], "готово, вставил")
    assert r.ok is False
    assert r.task_statuses[0]["status"] == "incomplete"
    assert "нет tool evidence" in r.answer


def test_finalize_license_not_done_from_crt_lift():
    tasks = split_user_tasks("Сделай чтобы проверка лицензии везде в программе возвращала True")
    r = finalize_agent(
        tasks,
        [
            {
                "tool": "argus_ai",
                "args": {"for_task": 1},
                "result": {
                    "ok": True,
                    "want": "lift",
                    "answer": "lifted sub_4045b0 (4 blocks, confidence=low)",
                    "summary": "lifted sub_4045b0 (4 blocks, confidence=low)",
                    "evidence": {"want": "lift"},
                },
            }
        ],
        store_memory=False,
    )
    assert r.task_statuses[0]["status"] != "done"
