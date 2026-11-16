[CmdletBinding()]
param(
    [string]$FixturePath = (Join-Path -Path $PSScriptRoot -ChildPath '..\examples\sanitized-case-summary.json')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$resolvedFixturePath = (Resolve-Path -LiteralPath $FixturePath -ErrorAction Stop).Path
$fixture = Get-Content -LiteralPath $resolvedFixturePath -Raw -Encoding utf8 |
    ConvertFrom-Json -Depth 20 -DateKind String

if ($fixture.schema -cne 'm365-ir-console/sanitized-demo/v1') {
    throw "Unsupported sanitized fixture schema: $($fixture.schema)"
}
if (($fixture.synthetic -isnot [bool]) -or ($fixture.synthetic -ne $true)) {
    throw 'The fixture is not explicitly marked synthetic. Refusing to display it as a demo.'
}
if ($fixture.case.mode -cne 'Audit') {
    throw "The sanitized demo must remain in Audit mode. Found: $($fixture.case.mode)"
}

@(
    'M365 Incident Response Console | Five-minute offline demo'
    'SYNTHETIC DATA ONLY | No tenant connection | No tenant mutation'
    ''
    "Case: $($fixture.case.id)"
    "Target: $($fixture.case.target)"
    "Mode: $($fixture.case.mode)"
    "Lookback: $($fixture.case.lookbackDays) days"
    ''
    'Collection coverage'
    '-------------------'
) | Write-Output

foreach ($row in $fixture.collectionStatus) {
    $limitation = if ([string]::IsNullOrWhiteSpace([string]$row.limitation)) {
        'none reported'
    }
    else {
        [string]$row.limitation
    }
    '{0,-34} {1,-12} {2}' -f $row.component, $row.status, $limitation | Write-Output
}

@(
    ''
    'Investigator decision queue'
    '---------------------------'
) | Write-Output

for ($index = 0; $index -lt $fixture.decisionQueue.Count; $index++) {
    '{0}. {1}' -f ($index + 1), $fixture.decisionQueue[$index] | Write-Output
}

@(
    ''
    'Evidence boundary'
    '-----------------'
    'Provides: reviewable synthetic output that demonstrates coverage and decision handling.'
    'Does not provide: tenant evidence, a trusted timestamp, a digital signature, or chain of custody.'
    ''
    "Fixture: $resolvedFixturePath"
) | Write-Output
