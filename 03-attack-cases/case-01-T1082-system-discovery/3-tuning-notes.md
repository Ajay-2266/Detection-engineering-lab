&#x20;Tuning Notes: net user detection (T1087.001)



Date: 2026-11-27 | Host: WIN11-VICTIM | User: labuser



&#x20;First rule

Match Sysmon process creation events where the program is net.exe and the

command line contains the word "user" or "localgroup administrators". The

goal was to catch local account discovery.



&#x20;What went wrong

I tested the rule by trying to break it, and found two problems:

\- Missed: I ran net1 user directly. That starts net1.exe without net.exe,

&#x20; so a rule that only watches net.exe never sees it.

\- False positive: the rule matched net localgroup "Remote Desktop Users"

&#x20; because the word "Users" is in the group name. That command lists a group,

&#x20; not accounts, so it shouldn't count as account discovery.



I also noticed that every net command creates two events: net.exe, then

net1.exe about 30 to 60 milliseconds later. Matching both programs would

raise two alerts for one command.



&#x20;What I changed

1\. Watch both net.exe and net1.exe, so the direct net1 bypass is caught.

2\. Skip net1.exe events whose parent is net.exe, so one command gives one alert.

3\. Require the command line to end with "user", so Remote Desktop Users no

&#x20;  longer matches. The localgroup administrators pattern stayed as it was.



The tuned search is in 1-detection-net-user.spl.



&#x20;Result

| | First rule | Tuned rule |

|---|---|---|

| Real activity caught | 2 of 3 | 3 of 3 |

| Missed | net1 user (direct) | none |

| False positives | 1 (Remote Desktop Users) | 0 |



&#x20;Limits

\- The tuned rule is narrower. It misses net user with an account name after

&#x20; it (for example, net user labuser), which is also account discovery.

\- I tested only a handful of commands in a lab, not a real network, so these

&#x20; numbers show the method, not real-world accuracy.

\- An attacker could rename the program or use PowerShell instead of net.

\- ParentImage showed "-" on 3 of the 4 net commands run from one cmd.exe

&#x20; window. Each had ParentProcessId 8664, which matched that cmd.exe, so the

&#x20; parent existed and was logged. I don't know why Sysmon left the fields

&#x20; empty. When ParentImage is "-", I fall back to ParentProcessId.

\- The duplicate-skipping part of the rule depends on ParentImage being filled

&#x20; in for net1.exe. It was in all my tests, but if it came back empty, one

&#x20; command would raise two alerts.

\- The Splunk forwarder starts cmd.exe repeatedly in the background, so any

&#x20; future cmd.exe rule needs to exclude it.

