---
id: DET-003
title: Cursor extension host spawning systemsetup, launchctl or pgrep -f on macOS
platform: Microsoft Defender XDR
data_source: DeviceProcessEvents
attack: [T1059.004, T1543.001]
status: experimental
date: 2026-11-03
linkedin:
---

# DET-003 · Cursor extension host spawning systemsetup, launchctl or pgrep -f on macOS

## The idea

Detection engineering takeaway: alert when Cursor's extension host starts systemsetup, launchctl
or pgrep -f on a Mac.

Detects the Cursor extension host process (Cursor Helper (Plugin)) starting systemsetup,
launchctl or pgrep with -f. The trojanized anthropic.claude-code 2.1.312 and 2.1.313 extensions
served in the Cursor marketplace used this process lineage to check Remote Login, load a
LaunchAgent and check for its running SSH tunnel. An editor extension host rarely needs to query
system settings or manage launch agents.

Source: [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/) (2026-10-30).

## Detection logic

| | |
|---|---|
| **Data source** | `DeviceProcessEvents` (Microsoft Defender XDR) |
| **Severity** | **High** as written |
| **Schedule** | Run every 1h, lookback 1h (or as a custom detection in Defender XDR) |

Files:

- [`sentinel.kql`](sentinel.kql): Defender XDR / Sentinel query generated from the Sigma rule
- [`rule.yml`](rule.yml): Sigma version

## MITRE ATT&CK

- [T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [T1543.001 Launch Agent](https://attack.mitre.org/techniques/T1543/001/)

## False positives and tuning

- Extensions that legitimately load their own launch agents through launchctl, or check for running processes with pgrep -f.
- Run it as a 30-day hunt first, list the extension folders active at the time of each hit, and allowlist by exact child command line rather than by child image.
- If your fleet also runs VS Code, add its extension host parent after baselining.

## How to test

On a lab machine with Defender for Endpoint, reproduce the behaviour described above and run
`sentinel.kql`. Expect one `DeviceProcessEvents` row per matching event.

## References

- [Inside a malicious Claude Code-branded extension and its persistent SSH backdoor | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/)
- [Fake Claude Code extension in Cursor: How to find the backdoor](https://expel.com/blog/blog-fake-claude-code-extension-cursor-ssh-backdoor/)
