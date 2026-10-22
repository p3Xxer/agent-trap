# False alarms on real projects

20 well-known open-source Python projects, none of them malicious, scanned as a stand-in for ordinary code. 2 runs per task plus the install-and-test run. Run on 2026-10-11.

| Measure | Result |
| --- | --- |
| Scanned without error | 20/20 (100%) |
| Installed in the sandbox (so their own build code really ran) | 16/20 (80%) |
| Tests really ran (at least one passed or failed) | 8/20 (40%) |
| Wrongly flagged (any warning) | 0/20 (0%) |
| Wrongly called MALICIOUS | 0/20 (0%) |
| Mean time per scan | 60s |

How much code really ran matters for reading these numbers. The sandbox has no internet, so dependencies are not installed and many test suites cannot run; a project that did not install or run tests gave Agent Trap little to observe, and its SAFE means less.

| Project | Result | Installed | Tests | Why flagged |
| --- | --- | --- | --- | --- |
| `pallets/click` | SAFE | yes | 24 failed, 2238 passed, 24 skipped, 31000 deselected, 1 xfailed | - |
| `pallets/itsdangerous` | SAFE | yes | 2 errors | - |
| `pallets-eco/blinker` | SAFE | yes | - | - |
| `python-attrs/attrs` | SAFE | no | - | - |
| `pypa/packaging` | SAFE | yes | 20 errors | - |
| `kjd/idna` | SAFE | yes | 1 error | - |
| `more-itertools/more-itertools` | SAFE | yes | 768 passed | - |
| `pytest-dev/pluggy` | SAFE | no | 68 failed, 151 passed | - |
| `mahmoud/boltons` | SAFE | yes | 525 passed | - |
| `tqdm/tqdm` | SAFE | no | - | - |
| `Delgan/loguru` | SAFE | yes | - | - |
| `jmespath/jmespath.py` | SAFE | yes | 1 error | - |
| `tkem/cachetools` | SAFE | yes | 338 passed | - |
| `pytoolz/toolz` | SAFE | yes | 1 failed, 191 passed, 1 skipped | - |
| `bottlepy/bottle` | SAFE | yes | 364 passed | - |
| `tartley/colorama` | SAFE | yes | 38 passed, 14 skipped | - |
| `micheles/decorator` | SAFE | yes | - | - |
| `pyparsing/pyparsing` | SAFE | yes | 1 error | - |
| `Python-Markdown/markdown` | SAFE | yes | 2 errors | - |
| `hynek/structlog` | SAFE | no | - | - |
