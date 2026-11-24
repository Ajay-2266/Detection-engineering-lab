\# T1082 - System Information Discovery



\*\*Tactic:\*\* Discovery

\*\*Platform:\*\* Windows 11 (Win11-Victim)

\*\*Date run:\*\* 2026-11-24

\*\*Run as:\*\* labuser (standard user, no admin)



\## What I ran

&#x20;   systeminfo

&#x20;   hostname

&#x20;   whoami



\## Expected telemetry

Sysmon EventCode 1 (process creation) for each binary.



\## Observed

| Time | Image | CommandLine | ParentImage |

|---|---|---|---|

| 13:22:22 | C:\\Windows\\System32\\systeminfo.exe | systeminfo | cmd.exe |

| 13:22:40 | C:\\Windows\\System32\\HOSTNAME.EXE | hostname | cmd.exe |

| 13:22:44 | C:\\Windows\\System32\\whoami.exe | whoami | cmd.exe |



\## Detection notes

Each command alone is common admin activity. The signal is several

discovery commands from the same parent within a short window.



\## Splunk search used

&#x20;   index=sysmon EventCode=1 (Image="\*\\\\systeminfo.exe" OR Image="\*\\\\hostname.exe" OR Image="\*\\\\whoami.exe") | table \_time Image CommandLine ParentImage User

