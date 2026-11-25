\# Results Table



| Technique | Test | Telemetry | Sigma Rule | Splunk | Sentinel | Detected | Notes |

|---|---|---|---|---|---|---|---|

| T1082 | systeminfo, hostname, whoami | Sysmon EventCode 1 | T1082-system-discovery-utilities.yml | Tested | Untested | Yes (3 of 3) | 4 older whoami runs from powershell.exe also matched (manual lab checks) |

