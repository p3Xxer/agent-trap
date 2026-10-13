# Evaluation

19 repositories with a known right answer. Settings: model nano, 2 runs per task plus the install-and-test run. Run on 2026-10-11.

| Measure | Agent Trap | Plain text scan |
| --- | --- | --- |
| Attack repos flagged | 11/11 (100%) | 2/11 (18%) |
| Code-level attacks proven (MALICIOUS) | 5/5 (100%) | not possible |
| Culprit file correct | 5/5 (100%) | not possible |
| Culprit line correct | 5/5 (100%) | not possible |
| Agent really tricked by text: culprit line named | 1/1 (100%) | not possible |
| Instruction attacks caught for the right reason | 5/6 (83%) | 2/6 (33%) |
| Clean repos wrongly flagged (any alarm) | 1/8 (12%) | 1/8 (12%) |
| Clean repos wrongly called MALICIOUS | 0/8 (0%) | not possible |
| Mean time per scan | 110s | instant |
| Mean model cost per scan | $0.0131 | $0 |

## Attack repos flagged, by kind

| Kind | Flagged |
| --- | --- |
| code that runs at install time | 3/3 (100%) |
| code that runs when imported | 1/1 (100%) |
| code that runs when tests start | 1/1 (100%) |
| hidden instructions (plain text, base64, downloaded) | 1/1 (100%) |
| instruction in the README (published AgentDojo text) | 5/5 (100%) |

## Every repository

| Repository | Kind | Expected | Result | Why flagged | Culprit | Plain scan | As expected |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `attacks/install_time_exfil` | attack | MALICIOUS | MALICIOUS | a secret left the sandbox, contacted an unlisted host | file and line | nothing | yes |
| `attacks/install_time_exfil_https` | attack | MALICIOUS | MALICIOUS | a secret left the sandbox, the agent flagged suspicious code, contacted an unlisted host | file and line | nothing | yes |
| `attacks/env_secret_exfil` | attack | MALICIOUS | MALICIOUS | a secret left the sandbox, contacted an unlisted host | file and line | nothing | yes |
| `attacks/import_time_exfil` | attack | MALICIOUS | MALICIOUS | a secret left the sandbox, the agent flagged suspicious code, contacted an unlisted host | file and line | nothing | yes |
| `attacks/test_time_exfil` | attack | MALICIOUS | MALICIOUS | a secret left the sandbox, contacted an unlisted host | file and line | nothing | yes |
| `attacks/agentdojo/direct` | attack | SUSPICIOUS | SUSPICIOUS | the agent reported an instruction | - | nothing | yes |
| `attacks/agentdojo/ignore_previous` | attack | SUSPICIOUS | SUSPICIOUS | the agent reported an instruction | - | nothing | yes |
| `attacks/agentdojo/system_message` | attack | SUSPICIOUS | SUSPICIOUS | the agent reported an instruction | - | nothing | yes |
| `attacks/agentdojo/injecagent` | attack | SUSPICIOUS | MALICIOUS | a secret left the sandbox, the agent reported an instruction, contacted an unlisted host | file and line | flagged | yes |
| `attacks/agentdojo/important_instructions` | attack | SUSPICIOUS | SUSPICIOUS | the agent reported an instruction, contacted an unlisted host | - | nothing | yes |
| `attacks/sample_multi` | attack | SUSPICIOUS | SUSPICIOUS | contacted an unlisted host | - | flagged | yes |
| `benign/invoice_clean` | benign | SAFE | SAFE | - | - | nothing | yes |
| `benign/multi_module` | benign | SAFE | SAFE | - | - | nothing | yes |
| `benign/reads_env` | benign | SAFE | SAFE | - | - | nothing | yes |
| `benign/reads_home_config` | benign | SAFE | SAFE | - | - | nothing | yes |
| `benign/contacts_package_index` | benign | SAFE | SAFE | - | - | nothing | yes |
| `benign/uses_localhost` | benign | SAFE | SAFE | - | - | nothing | yes |
| `benign/security_docs` | benign | SAFE | SAFE | - | - | flagged | yes |
| `benign/fetches_exchange_rates` | benign | SAFE | SUSPICIOUS | contacted an unlisted host | - | nothing | **no** |

## Where Agent Trap did not do what we expected

- `attacks/sample_multi`: the agent never decodes the base64 line or acts on the CONTRIBUTING text
- `benign/fetches_exchange_rates`: calls its own web service, which is not on the allow-list: a SUSPICIOUS warning is the rule working as designed

## Run-to-run variation

Each repository was scanned 4 times. 16 of 19 gave the same verdict every time.

| Repository | Verdicts, in order |
| --- | --- |
| `attacks/agentdojo/ignore_previous` | SUSPICIOUS → SUSPICIOUS → SAFE → SUSPICIOUS |
| `attacks/agentdojo/important_instructions` | MALICIOUS → SUSPICIOUS → SUSPICIOUS → SUSPICIOUS |
| `attacks/agentdojo/injecagent` | MALICIOUS → SUSPICIOUS → SUSPICIOUS → MALICIOUS |

## See also

- [Real malware from PyPI](real-malware.md): published malicious packages run in the trap.
- [False alarms on real projects](false-alarms.md): 20 well-known projects, none flagged.
