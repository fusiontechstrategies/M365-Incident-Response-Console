# Portable case export and verification

An analyst can use PowerShell 7.6 to export a sealed console case and check its evidence on an offline workstation. The recipient needs [Test-PortableCase.ps1](../scripts/Test-PortableCase.ps1) from a trusted checkout. The verifier reads data files and returns a timeline, handoff history, and collection coverage.

## Try a synthetic case

```powershell
pwsh -NoProfile -File ./examples/New-SyntheticPortableCase.ps1 -Destination ./synthetic-case
$case = & ./scripts/Test-PortableCase.ps1 -Path ./synthetic-case
$case.Coverage | Format-Table Source, Status, Note
$case.Timeline | Format-Table TimestampUtc, Event, Status
$case.HandoffHistory | Format-Table TimestampUtc, Event, Investigator, Recipient
```

The generator produces the same file bytes each time. The fixture contains invented identities and case evidence.

## Export a sealed case

Generate the SHA-256 evidence manifest in the console after the final collection and report. Choose a new destination outside the source case in a private parent directory. Pause changes to the source case while exporting.

```powershell
pwsh -NoProfile -File ./scripts/New-PortableCase.ps1 -CasePath ./cases/IR-example -Destination ./handoff-snapshot
pwsh -NoProfile -File ./scripts/Test-PortableCase.ps1 -Path ./handoff-snapshot
```

The exporter creates a directory limited to the current OS identity and verifies the snapshot before promoting it to the destination. When present, it includes a copy of the handoff history from the original case root's `.handoffs/<case-id>/events.json`. The snapshot contains potentially sensitive evidence. Share it through your organization's approved evidence transfer process.

Optionally pass `-CoveragePath` with a JSON array of objects. Each object has a source, a status, the package paths that support it, and an optional note.

```json
[
  {
    "Source": "Mailbox configuration",
    "Status": "Partial",
    "Evidence": ["case/Exports/mailbox-configuration.json"],
    "Note": "Folder permissions were unavailable."
  }
]
```

Use `Completed`, `Partial`, `Unavailable`, `Failed`, `NotRun`, or `Unknown`. Leave evidence arrays empty for sources with no artifact. Without a coverage file, the exporter records the original collection status as `Unknown`.

## Version 1 format

| Path | Contents |
| --- | --- |
| `portable-case.json` | Schema `m365-ir-portable-case/v1`, case ID, export UTC, synthetic marker, artifact inventory, coverage and handoff anchor |
| `case/` | Original evidence files, case metadata, action log, and SHA-256 manifest |
| `handoff/events.json` | Optional original handoff journal |
| `portable-case.sig` | Optional binary RSA-PSS SHA-256 signature over the exact portable manifest bytes |

Each inventory row includes `Path`, `Length` in bytes, and lowercase hexadecimal `SHA256` over the original file bytes. Paths are relative to the snapshot with forward slashes and NFC text. The verifier rejects unsafe Windows names, links, case collisions, and unlisted files. It also checks that the native artifact inventory and the action journal count and terminal digest match. Handoff verification checks the transition history, the case metadata binding, and the portable handoff anchor.

The console's v1 journal digests use PowerShell's ordered, compressed JSON. The native handoff case binding hashes decoded metadata text re-encoded as UTF-8. The separate artifact digest hashes the exact metadata file bytes.

The verifier accepts an extracted directory of up to 8,192 entries. Manifest and handoff journal reads are limited to 4 MiB apiece, and the action journal to 32 MiB. Verify a stable copy in a directory that only authorized users can write.

## Interpreting verification

`InternallyConsistent` means the files and journal chains match the manifest. For author authentication, obtain the signer's RSA public key from a trusted channel separately from the case and supply it with `-TrustedPublicKey`. The key must be at least 2048 bits in PEM format.

```powershell
pwsh -NoProfile -File ./scripts/Test-PortableCase.ps1 -Path ./handoff-snapshot -TrustedPublicKey ./trusted-signer.pem
```

`VerifiedWithSuppliedKey` binds the manifest to that key. Handoff identities remain operator-entered, timestamps are source data, and reported collection coverage governs the interpretation of missing evidence. An unsigned package can be internally consistent even if someone rewrote all its files and hashes.
