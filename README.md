# Tishev · Detections

[![validate](https://github.com/tishev-sec/detections/actions/workflows/validate.yml/badge.svg)](https://github.com/tishev-sec/detections/actions/workflows/validate.yml)
[![site](https://img.shields.io/badge/browse-tishev--sec.github.io%2Fdetections-blue)](https://tishev-sec.github.io/detections/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Detection engineering ideas, shared as working **KQL** and **Sigma** rules.

Each detection starts as a post on LinkedIn. This repo holds the rules behind the post: the
idea, the query, how it maps to MITRE ATT&CK, the false positives I expect, and how to test it.

**Browse the readable version:** https://tishev-sec.github.io/detections/

## Detections

<!-- INDEX:START -->
| ID | Detection | Category | Platform | ATT&CK | Formats | Status |
|---|---|---|---|---|---|---|
| DET-001 | [Unexpected Azure OpenAI / AI Foundry API key access](detections/cloud/DET-001-azure-ai-api-key-access/) | cloud | Microsoft Sentinel | [T1552](https://attack.mitre.org/techniques/T1552/), [T1496](https://attack.mitre.org/techniques/T1496/) | KQL · Sigma | experimental |
<!-- INDEX:END -->

## What's in each detection

Every detection lives in its own folder, `detections/<category>/DET-XXX-short-name/`:

| File | What it is |
|---|---|
| `README.md` | The idea, detection logic, ATT&CK mapping, false positives, tuning and how to test |
| `sentinel.kql` | Microsoft Sentinel / Defender XDR query, ready to paste |
| `rule.yml` | [Sigma](https://sigmahq.io/) version, convertible to Splunk, Elastic and others with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) |

Categories: `cloud`, `identity`, `endpoint`, `network`, `ai`.

## Using these rules

All rules are marked `experimental` until they have run in a real environment. Test them in your
own tenant, tune the allowlists to your environment, and check the false positives section first.

Convert a Sigma rule to another SIEM:

```bash
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p splunk_windows detections/<category>/<folder>/rule.yml
```

## Feedback

Found a false positive, a bypass, or a better way to write a query? Open an
[issue](https://github.com/tishev-sec/detections/issues) or comment on the LinkedIn post.
Pull requests are welcome.

## License

[MIT](LICENSE). Use the rules freely; a credit back is appreciated.
