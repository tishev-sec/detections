---
id: DET-001
title: Unexpected Azure OpenAI / AI Foundry API key access
platform: Microsoft Sentinel
data_source: AzureActivity
attack: [T1552, T1496]
status: experimental
date: 2026-10-12
linkedin:
---

# DET-001 · Unexpected Azure OpenAI / AI Foundry API key access

## The idea

Azure AI Services accounts (Azure OpenAI, AI Foundry, Speech, etc.) come with two API keys
(`key1` / `key2`) from the moment the account exists. Nobody "creates" a key, so alerting on
creation finds nothing.

The event that matters is an identity **reading** (`ListKeys`) or **regenerating** those keys.
That is the moment a static, identity-less credential leaves Azure. From there it works from any
machine, bypasses Conditional Access and MFA, and is exactly what LLMjacking crews look for:
free access to someone else's paid model capacity.

## Detection logic

| | |
|---|---|
| **Data source** | `AzureActivity` (Azure Activity connector, Microsoft Sentinel) |
| **Operations** | `MICROSOFT.COGNITIVESERVICES/ACCOUNTS/LISTKEYS/ACTION`, `.../REGENERATEKEY/ACTION` |
| **Trigger** | A caller lists or regenerates keys on an AI account where that **caller + account pair has not been seen in the last 14 days** |
| **Severity** | **High** if any call came from outside the known first-party portals (scripts, SDKs, replayed tokens), otherwise **Medium** |
| **Schedule** | Run every 1h, lookback 14d |
| **Entities** | Account = `Caller`, IP = `CallerIpAddress`, Azure Resource = `AccountResourceId` |

Files:

- [`sentinel.kql`](sentinel.kql): full analytics rule with the 14-day baseline, plus a companion hunt for keys being switched back on (`disableLocalAuth` reversed)
- [`rule.yml`](rule.yml): portable Sigma version (single event, no baseline)

## MITRE ATT&CK

- [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [T1496 Resource Hijacking](https://attack.mitre.org/techniques/T1496/)

## False positives and tuning

- **Engineers copying keys** from the portal or AI Foundry when wiring up an app. The baseline
  stops repeat alerts, but expect a few during onboarding.
- **Pipelines and rotation jobs** that read keys into Key Vault. Add them to `allowedCallers`, or
  swap it for a Sentinel watchlist: `_GetWatchlist('AIKeyAllowlist')`.
- **Portal app IDs**: check each one under *Entra ID → Enterprise applications* in your own tenant
  before relying on the Medium/High split.

The best fix is upstream: set `disableLocalAuth = true` on AI accounts and use Entra ID auth.
After that, any successful `ListKeys` is worth looking at, and the companion hunt in
`sentinel.kql` catches someone re-enabling keys.

## How to test

With an account you own in a lab subscription:

```bash
az cognitiveservices account keys list --name <ai-account> --resource-group <rg>
```

Run it from the CLI (not the portal) with an identity that has never read keys on that account.
Expect a **High** result within the next run.

## Credits

The portal app ID list and the "keys enabled then listed" hunt are based on the logic of Datadog's
public detection rules for Azure AI key access.
