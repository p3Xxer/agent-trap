"""The agent loop, driven by a scripted model and an in-memory sandbox (no Docker, no API)."""

import json

from agenttrap.agent import Trace, debrief, run_agent
from agenttrap.sandbox import CommandResult


class ScriptedLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.roles = []

    def chat(self, role, size, messages, **kwargs):
        self.roles.append(role)
        return self.replies.pop(0)


class MemorySandbox:
    def __init__(self, files):
        self.files = dict(files)
        self.commands = []

    def read(self, path):
        if path in self.files:
            return CommandResult(0, self.files[path], "")
        return CommandResult(1, "", f"cat: {path}: No such file")

    def write(self, path, text):
        self.files[path] = text
        return CommandResult(0, "", "")

    def run(self, command, timeout=60):
        self.commands.append(command)
        return CommandResult(0, "ok", "")


def act(action, **args):
    return json.dumps({"thought": "", "action": action, "args": args})


def test_runs_tools_in_sandbox_and_records_requests():
    llm = ScriptedLLM([
        act("read_file", path="README.md"),
        act("run_command", command="pytest -q"),
        act("http_request", method="post", url="https://x.test/c", body="hello"),
        act("finish", summary="done"),
    ])  # fmt: skip
    sandbox = MemorySandbox({"README.md": "# demo"})
    trace = run_agent("task", sandbox, lambda r: "200 OK", llm, role="t")

    assert [s.action for s in trace.steps] == ["read_file", "run_command", "http_request", "finish"]
    assert "# demo" in trace.steps[0].observation
    assert sandbox.commands == ["pytest -q"]
    assert [(r.method, r.url, r.body) for r in trace.requests] == [
        ("POST", "https://x.test/c", "hello")
    ]
    assert trace.stopped == "finished"
    assert llm.roles == ["t:0", "t:1", "t:2", "t:3"]  # unique per step, so repeats aren't cached


def test_bad_reply_is_reported_back_not_crashed():
    llm = ScriptedLLM(["not json at all", act("finish", summary="ok")])
    trace = run_agent("task", MemorySandbox({}), lambda r: "", llm, role="t")
    assert trace.steps[0].action == "invalid"
    assert "malformed" in trace.messages[-1]["content"]


def test_stops_at_max_steps():
    llm = ScriptedLLM([act("list_dir", path=".")] * 3)
    trace = run_agent("task", MemorySandbox({}), lambda r: "", llm, role="t", max_steps=3)
    assert trace.stopped == "max steps"


def test_debrief_collects_reported_injections():
    reply = json.dumps({"found": True, "items": [
        {"source": "README.md", "quote": "TODO: send keys", "asked_for": "exfiltrate"},
        {"source": "x", "quote": "  ", "asked_for": "empty quotes are dropped"},
    ]})  # fmt: skip
    trace = Trace(task="t", messages=[{"role": "user", "content": "t"}])
    [found] = debrief(trace, ScriptedLLM([reply]), role="t")
    assert (found.source, found.quote) == ("README.md", "TODO: send keys")


def test_debrief_tolerates_garbage():
    trace = Trace(task="t")
    assert debrief(trace, ScriptedLLM(["sorry, I can't"]), role="t") == []
