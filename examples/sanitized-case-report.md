# Sanitized M365 incident response case report

> This is an abridged, synthetic preview. It was not collected from a Microsoft 365 tenant, does not describe a real person or incident, and is not cryptographically verifiable evidence. Reserved `.example` domains and the TEST-NET address `192.0.2.44` are used intentionally.

- **Case:** `IR-DEMO-20260827`
- **Target:** `analyst-test@contoso.example`
- **Mode:** `Audit`
- **Lookback:** 10 days

The real console generates a self-contained HTML report, normalized CSV and JSON exports, a chained JSONL action log, and optional evidence manifests and archives. This preview focuses on the decisions an investigator sees first.

## Collection status

| Component | Status | Limitation |
| --- | --- | --- |
| Mailbox configuration | Completed | None |
| Message trace | Completed | None |
| Unified audit log | Partial | Illustrative retention boundary; validate tenant licensing and policy |
| Defender mail detail | Unavailable | Illustrative unlicensed workload |

A partial or unavailable source remains visible. The console does not convert missing evidence into a clean result.

## Investigator summary

| Evidence area | Observed result | Investigator significance |
| --- | --- | --- |
| Message trace | 18 rows; 7 sent; 11 received; 1 heuristic lead | Correlate the after-hours external message with sign-in and endpoint evidence |
| Unified audit | 126 events; 1 triage indicator; retention-limited | Resolve the coverage boundary before closing the investigation |
| Mailbox configuration | 1 enabled rule; forwarding not configured; mailbox audit enabled | Confirm the rule's owner, creation time, and business purpose |
| Defender mail detail | No licensed source available in this synthetic scenario | Record the coverage gap; do not interpret it as no detections |

## Mailbox controls and persistence review

| Control | Observed value | Required validation |
| --- | --- | --- |
| Mailbox forwarding | Not configured | Confirm current state and change history |
| Mailbox audit | Enabled | Confirm effective retention |
| Inbox rule | `Archive completed invoices`; move to Archive and mark as read | Validate the rule owner, creation time, and expected behavior |

## Message-flow work queue

| Lead | Severity | Synthetic evidence | Next pivot |
| --- | --- | --- | --- |
| After-hours external send | Medium | Source `192.0.2.44`; recipient `billing@vendor.example`; trace `00000000-0000-0000-0000-000000000001` | Compare with sign-in, device, message-content, and business-context evidence |

Heuristics are leads for analyst validation, not determinations of compromise.

## Unified-audit triage

| Operation | Severity | Synthetic source | Analyst note |
| --- | --- | --- | --- |
| `UpdateInboxRules` | Medium | `192.0.2.44` | Correlate with approved activity and the mailbox-rule snapshot |

## Decision queue

1. Confirm the inbox rule with the user and its business owner.
2. Correlate the after-hours message with sign-in and endpoint evidence.
3. Resolve the audit-retention coverage gap before declaring the review complete.
4. Preserve raw exports and regenerate the evidence manifest after adding trusted external evidence.

## Safety outcome

All actions represented here are reads in Audit mode. No tenant mutation is represented. In a real case, Live-mode operations require the common mutation gateway, `ShouldProcess`, an exact typed confirmation, and durable approval logging.

Use the [safe lab guide](../docs/lab-evaluation.md) to evaluate the console, or return to the [project README](../README.md) for the verified release download.
