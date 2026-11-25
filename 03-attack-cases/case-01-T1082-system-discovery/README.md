\# Case 01: System Information Discovery (T1082)



\*\*MITRE ATT\&CK:\*\* Discovery, T1082 System Information Discovery

\*\*NIST SP 800-61 phase:\*\* Detection and Analysis

\*\*Verdict:\*\* False positive in this lab (benign admin activity). Low severity, needs context to judge.



\## Situation

I ran this test on a Windows 11 VM (WIN11-VICTIM) as a standard user (`labuser`). Sysmon was installed and logs were forwarded to Splunk.



\## Task

Detect when someone runs built-in Windows commands that reveal information about the machine and the user. Attackers run these right after getting access to learn where they are.



\## Action

1\. Ran `systeminfo`, `hostname` and `whoami` from `cmd.exe` on 2026-11-24.

2\. Found all three in Splunk as Sysmon EventCode 1 (process creation).

3\. Wrote a Sigma rule matching these three program names, then converted it into a Splunk search.

4\. Ran the Splunk search against all data to test the rule.



Files: \[attack](2-attack.md), \[Sigma rule](1-detection-sigma.yml), \[Splunk search](1-detection-splunk.spl)



\## Result

The rule caught all 3 of my test commands (parent `cmd.exe`, user `labuser`). It also returned 4 older `whoami` runs from 2026-11-07, 11-13 and 11-19, all started by `powershell.exe` as `labuser`. These look like my own checks while setting up the lab.



The rule only looks at program names, so it can't tell me from an attacker. A real analyst would check the parent process, the user, the time, and whether several discovery commands run close together.



\## Lessons

\- One discovery command alone is normal admin activity. Several in a short window from the same parent is more suspicious.

\- This rule is a low-severity hunting rule, not an alert to escalate.

\- Next improvement: alert on 3 or more of these commands within a few minutes from the same host.

