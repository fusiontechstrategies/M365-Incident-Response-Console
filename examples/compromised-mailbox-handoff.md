# Compromised-mailbox investigation handoff

> Synthetic example only. This worksheet contains no tenant or customer data and is not incident evidence.

Use this one-page structure when an investigator hands a mailbox case to containment, legal, an MSP escalation team, or the next shift. Attach the console's raw exports, chained action log, evidence manifest, and generated case report separately; do not paste secrets or unredacted message content into the worksheet.

## Case decision

| Field | Synthetic example |
| --- | --- |
| Case | `IR-DEMO-20260827` |
| Target | `analyst-test@contoso.example` |
| Collection mode | Audit; no tenant mutation |
| Lookback | 10 days |
| Current disposition | Investigation incomplete; containment authorization pending |
| Decision owner | Assign a named incident commander |

## What the collection established

- Mailbox configuration and message trace collectors completed.
- A synthetic after-hours external send and an inbox-rule change share the example source address `192.0.2.44`.
- The inbox rule moves completed invoices to Archive and marks them read; ownership and business purpose are not yet established.
- The unified audit result is partial because the fixture models a retention boundary.
- Defender mail detail is unavailable in the fixture's modeled license state.

## What it did not establish

- It did not attribute activity to a person, device, session, or threat actor.
- It did not establish that the inbox rule or external send is malicious.
- It did not prove full audit, message, endpoint, or identity coverage.
- It did not perform containment, revoke sessions, reset credentials, remove a rule, or change a tenant setting.

## Decisions required before containment

- [ ] Confirm the mailbox rule with the user and business owner.
- [ ] Correlate the external send with Entra sign-in and endpoint evidence.
- [ ] Record the audit-retention and Defender coverage gaps in the case disposition.
- [ ] Identify the exact Live-mode operations being authorized.
- [ ] Record the approver, scope, time window, rollback owner, and required confirmation phrases.
- [ ] Preserve the pre-change evidence manifest before any approved mutation.

## Evidence handoff

| Artifact | Required check |
| --- | --- |
| Generated case report | Coverage limitations remain visible |
| Raw collector exports | Stored in the private case directory |
| Chained JSONL action log | Hash chain validates |
| SHA-256 evidence manifest | Regenerated after the final evidence addition |
| Protected archive | Created only under the organization's evidence-handling policy |
| External evidence | Source, acquisition time, and trust boundary documented |

## Next-shift acceptance

- [ ] Receiving investigator reviewed unavailable and partial collectors.
- [ ] Receiving investigator can reproduce the current case disposition from the attached evidence.
- [ ] Open decisions have an owner and deadline.
- [ ] Any production change remains behind the console's Live-mode, `ShouldProcess`, exact-confirmation, and durable-logging gates.

The paired [sanitized case summary](sanitized-case-summary.json) and [sanitized case report](sanitized-case-report.md) show the synthetic source material behind this handoff.
