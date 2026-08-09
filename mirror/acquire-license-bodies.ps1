<#
.SYNOPSIS
Anvil A.4 — deliberate acquisition of the publisher licence texts the licence
gate reads as evidence. Windows counterpart of acquire-license-bodies.sh.

.DESCRIPTION
NOTHING RUNS THIS FOR YOU. It is not wired into any build, test or CI job, and
internal/ingest/license imports no HTTP client at all. An operator runs it once,
on purpose, and then READS what it fetched.

Two invariants, both taken from eval/tools/opengrep/anvil_opengrep/acquire.py:

  1. ONLY WHAT THE MANIFEST PINS. Every URL comes verbatim out of
     LICENSE-MANIFEST.toml. No "latest", no version resolution, no URL derived
     from anything else.
  2. CHECKSUM OR NOTHING. A pinned entry whose download does not match its
     sha256 deletes the download and fails. Never retried, never ignored.

An UNPINNED entry (sha256 = "") cannot be verified, so this script fetches it,
prints the digest, and stops short of blessing it. Recording that digest is a
human act: you are certifying that the document you just read is the operative
licence for that feed. See mirror/README.md.

.EXAMPLE
pwsh -File mirror/acquire-license-bodies.ps1
pwsh -File mirror/acquire-license-bodies.ps1 -VerifyOnly
pwsh -File mirror/acquire-license-bodies.ps1 -Feed ghsa,cwe
#>
[CmdletBinding()]
param(
    [switch] $VerifyOnly,
    [string[]] $Feed = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifestPath = Join-Path $here 'LICENSE-MANIFEST.toml'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    Write-Error "FATAL: $manifestPath not found"
}

# --- manifest reader: the same tiny grammar internal/ingest/license parses ---
function Read-PinnedBodies {
    param([string] $Path)

    $entries = @()
    $current = $null
    foreach ($raw in (Get-Content -LiteralPath $Path -Encoding UTF8)) {
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        if ($line -eq '[[body]]') {
            if ($null -ne $current) { $entries += $current }
            $current = [ordered]@{ feed_id = ''; tier = ''; dir = ''; sha256 = ''; text_url = '' }
            continue
        }
        if ($null -eq $current) { continue }
        if ($line -match '^(feed_id|dir|sha256|text_url)\s*=\s*"(.*)"\s*(#.*)?$') {
            $current[$Matches[1]] = $Matches[2]
        }
        elseif ($line -match '^tier\s*=\s*(\d+)\s*(#.*)?$') {
            $current['tier'] = $Matches[1]
        }
    }
    if ($null -ne $current) { $entries += $current }
    return $entries
}

function Get-Sha256 {
    param([string] $Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$bodies = Read-PinnedBodies -Path $manifestPath
if ($bodies.Count -eq 0) {
    Write-Error "FATAL: $manifestPath pins no licence bodies"
}

Write-Host "manifest : $manifestPath"
Write-Host ''

$verified = 0
$unpinned = 0
$failed = 0

foreach ($b in $bodies) {
    if ($Feed.Count -gt 0 -and $Feed -notcontains $b.feed_id) { continue }

    $destDir = Join-Path (Join-Path $here ("tier" + $b.tier)) $b.dir
    $dest = Join-Path $destDir 'LICENSE.full.txt'

    if (-not (Test-Path -LiteralPath $dest)) {
        if ($VerifyOnly) {
            Write-Host ("{0,-20} MISSING   {1}" -f $b.feed_id, $dest)
            Write-Host ("{0,-20}           fetch it: drop -VerifyOnly" -f '')
            $failed++
            continue
        }
        if (-not $b.text_url.StartsWith('https://')) {
            Write-Host ("{0,-20} REFUSED   text_url is not https: {1}" -f $b.feed_id, $b.text_url)
            $failed++
            continue
        }
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        $tmp = "$dest.partial"
        try {
            Invoke-WebRequest -Uri $b.text_url -OutFile $tmp -UseBasicParsing -MaximumRedirection 5
            Move-Item -LiteralPath $tmp -Destination $dest -Force
        }
        catch {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
            Write-Host ("{0,-20} FETCH FAILED  {1}" -f $b.feed_id, $b.text_url)
            Write-Host ("{0,-20}           {1}" -f '', $_.Exception.Message)
            $failed++
            continue
        }
    }

    $actual = Get-Sha256 -Path $dest

    if ([string]::IsNullOrWhiteSpace($b.sha256)) {
        Write-Host ("{0,-20} UNPINNED  {1}" -f $b.feed_id, $dest)
        Write-Host ("{0,-20}           from {1}" -f '', $b.text_url)
        Write-Host ("{0,-20}           sha256 = `"{1}`"" -f '', $actual)
        Write-Host ("{0,-20}           READ THIS FILE, then record that digest in LICENSE-MANIFEST.toml." -f '')
        $unpinned++
    }
    elseif ($actual -ne $b.sha256) {
        Write-Host ("{0,-20} MISMATCH  {1}" -f $b.feed_id, $dest)
        Write-Host ("{0,-20}           pinned  {1}" -f '', $b.sha256)
        Write-Host ("{0,-20}           actual  {1}" -f '', $actual)
        Write-Host ("{0,-20}           Supply-chain or upstream-terms change. NOT retried. Investigate." -f '')
        Remove-Item -LiteralPath $dest -Force
        $failed++
    }
    else {
        Write-Host ("{0,-20} verified  {1}" -f $b.feed_id, $dest)
        $verified++
    }
}

Write-Host ''
Write-Host "verified: $verified   unpinned: $unpinned   failed: $failed"
if ($unpinned -gt 0 -or $failed -gt 0) {
    Write-Host 'The licence gate refuses every feed that is not "verified" above. That is the design.'
    exit 1
}
exit 0
