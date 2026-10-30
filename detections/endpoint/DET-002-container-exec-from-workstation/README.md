---
id: DET-002
title: Container exec from a workstation via kubectl, oc, docker or podman
platform: Microsoft Defender XDR
data_source: DeviceProcessEvents
attack: [T1609]
status: experimental
date: 2026-10-30
linkedin: https://lnkd.in/p/dVbKx7B9
---

# DET-002 · Container exec from a workstation via kubectl, oc, docker or podman

## The idea

In the October 2026 Binance theft, Binance's initial investigation points to a compromised
DevOps engineer's laptop. From there the attacker reached a service container that submitted
unauthorized withdrawals. No wallet private key had to leak: the attacker got Binance's own
systems to sign the transactions.

The step defenders can see on the endpoint is the jump from the laptop into the container.
`kubectl exec`, `oc exec`, `docker exec` and `podman exec` give an interactive or one-shot
command inside a running container. From a workstation into production, that is the same as an
interactive logon to a production server, and it deserves the same scrutiny.

## Detection logic

| | |
|---|---|
| **Data source** | `DeviceProcessEvents` (Microsoft Defender for Endpoint) |
| **Trigger** | `kubectl.exe`, `oc.exe`, `docker.exe` or `podman.exe` (by path or original file name) with ` exec ` in the command line |
| **Severity** | **Medium** as written. Raise a copy to **High** for your production contexts and signing or withdrawal namespaces |
| **Schedule** | Run every 1h, lookback 1h (or as a custom detection in Defender XDR) |
| **Entities** | Device = `DeviceName`, Account = `AccountUpn`, Process = `ProcessCommandLine` |

Files:

- [`sentinel.kql`](sentinel.kql): Defender XDR / Sentinel query generated from the Sigma rule, with a production-scope variant
- [`rule.yml`](rule.yml): Sigma version

## MITRE ATT&CK

- [T1609 Container Administration Command](https://attack.mitre.org/techniques/T1609/)

## False positives and tuning

- **On-call engineers debugging containers**, especially in development clusters. Expect most
  hits to be legitimate at first.
- **Scope it.** Production context names and namespaces are environment-specific. Put yours in
  `prodScopes` in the second query in `sentinel.kql` and route those matches as incidents.
- **Break-glass accounts** that are approved to exec into production: suppress them by
  `AccountUpn`, and review the suppression list regularly.

## How to test

On a lab workstation with Defender for Endpoint and a test cluster or local container:

```bash
kubectl exec -it <pod> -n <namespace> -- sh
docker exec <container> whoami
```

Expect one `DeviceProcessEvents` row per command, matched by the query.

## References

- [BleepingComputer: Binance links $6.3 billion crypto theft to compromised DevOps laptop](https://www.bleepingcomputer.com/news/security/binance-links-63-billion-crypto-theft-to-compromised-devops-laptop/)
- [The Hacker News: Binance suffers security breach affecting $6.3 billion in assets](https://thehackernews.com/2026/10/binance-suffers-security-breach.html)
- [Kubernetes docs: kubectl exec](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_exec/)
