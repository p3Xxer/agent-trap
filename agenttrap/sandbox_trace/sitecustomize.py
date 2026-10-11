"""Notes which of the project's files Python ran, so the culprit search can start with them.

Python imports this file by itself at start-up when its folder is on PYTHONPATH, in every Python
process the sandbox runs, including the ones pip and setup.py start. Each file under the project
root that is executed is appended once to a log. This is only a hint for narrowing the search: it
never touches the verdict, and nothing it does may break the program being observed.
"""

import atexit
import os
import sys

ROOT = os.path.abspath(os.environ.get("AGENTTRAP_TRACE_ROOT", "/work"))
LOG = os.environ.get("AGENTTRAP_TRACE_LOG", "/tmp/agenttrap-loaded.txt")
_seen = set()


def _note(path):
    try:
        relative = os.path.relpath(os.path.abspath(path), ROOT)
        if relative in _seen or relative.startswith("..") or "\n" in relative:
            return
        _seen.add(relative)
        if os.path.isfile(os.path.join(ROOT, relative)):
            with open(LOG, "a") as log:
                log.write(relative + "\n")
    except Exception:  # noqa: BLE001 - tracing must never break the program
        pass


def _on_event(event, args):
    # Every import, and every `exec(compile(source, path, ...))` such as the one that runs a
    # setup.py for pip, ends up executing a code object that remembers its file.
    if event == "exec":
        _note(args[0].co_filename)


def _note_main_script():
    _note(getattr(sys.modules.get("__main__"), "__file__", None) or sys.argv[0])


try:
    sys.addaudithook(_on_event)
    atexit.register(_note_main_script)
except Exception:  # noqa: BLE001
    pass
