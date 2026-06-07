# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Bin = $env:LANDSTRIP_BIN
if (-not $Bin) {
    $Bin = Join-Path $RepoRoot "target\debug\landstrip.exe"
}
if (-not (Test-Path -LiteralPath $Bin -PathType Leaf)) {
    Write-Error "missing landstrip binary: $Bin"
}

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("landstrip-test-" + [Guid]::NewGuid().ToString("N"))
$Allowed = Join-Path $Tmp "allowed"
$Denied = Join-Path $Tmp "denied"
$Cmd = Join-Path $Tmp "cmd.exe"
$PassCount = 0
$FailCount = 0
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Pass([string] $Name) {
    $script:PassCount += 1
    Write-Host "PASS $Name"
}

function Fail([string] $Name, [string] $Message) {
    $script:FailCount += 1
    Write-Host "FAIL $Name -- $Message"
}

function Write-Policy([string] $Path, [hashtable] $Policy) {
    $json = $Policy | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($Path, $json, $script:Utf8NoBom)
}

function Invoke-Landstrip([string] $Policy, [string[]] $CommandArgs) {
    $output = (& $script:Bin -p $Policy @CommandArgs 2>&1) | Out-String
    $status = $LASTEXITCODE
    [pscustomobject]@{
        Status = $status
        Output = $output.Trim()
    }
}

function Expect-Success([string] $Name, [string] $Policy, [string[]] $CommandArgs) {
    $result = Invoke-Landstrip $Policy $CommandArgs
    if ($result.Status -eq 0) {
        Pass $Name
    } else {
        Fail $Name "status=$($result.Status) output=$($result.Output)"
    }
}

function Expect-Failure([string] $Name, [string] $Policy, [string[]] $CommandArgs) {
    $result = Invoke-Landstrip $Policy $CommandArgs
    if ($result.Status -ne 0) {
        Pass $Name
    } else {
        Fail $Name "unexpected success output=$($result.Output)"
    }
}

function Expect-FailureText([string] $Name, [string] $Policy, [string[]] $CommandArgs, [string] $Text) {
    $result = Invoke-Landstrip $Policy $CommandArgs
    if (($result.Status -ne 0) -and ($result.Output -like "*$Text*")) {
        Pass $Name
    } else {
        Fail $Name "status=$($result.Status) output=$($result.Output)"
    }
}

try {
    New-Item -ItemType Directory -Path $Allowed, $Denied | Out-Null
    Copy-Item -LiteralPath $env:ComSpec -Destination $Cmd

    $PolicyFs = Join-Path $Tmp "policy-fs.json"
    Write-Policy $PolicyFs @{
        filesystem = @{
            allowWrite = @($Allowed)
            denyRead = @("/")
            allowRead = @($Tmp, $RepoRoot)
        }
    }
    $AllowedFile = Join-Path $Allowed "ok.txt"
    $DeniedFile = Join-Path $Denied "nope.txt"
    Expect-Success "explicit read/write policy permits configured root" $PolicyFs @($Cmd, "/C", "echo", "ok>", $AllowedFile)
    Expect-Failure "explicit read/write policy denies other root" $PolicyFs @($Cmd, "/C", "echo", "nope>", $DeniedFile)

    $PolicyRead = Join-Path $Tmp "policy-read.json"
    Write-Policy $PolicyRead @{
        filesystem = @{
            allowWrite = @($Allowed)
        }
    }
    Expect-FailureText "unrestricted read policy is rejected" $PolicyRead @($Cmd, "/C", "exit 0") "read access must use explicit allow roots"

    $PolicyAllowNetwork = Join-Path $Tmp "policy-allow-network.json"
    Write-Policy $PolicyAllowNetwork @{
        network = @{
            allowNetwork = $true
        }
        filesystem = @{
            denyRead = @("/")
            allowRead = @($Tmp, $RepoRoot)
        }
    }
    Expect-FailureText "unrestricted network policy is rejected" $PolicyAllowNetwork @($Cmd, "/C", "exit 0") "unrestricted network is not supported yet"

    $PolicyLocalBinding = Join-Path $Tmp "policy-local-binding.json"
    Write-Policy $PolicyLocalBinding @{
        network = @{
            allowLocalBinding = $true
        }
        filesystem = @{
            denyRead = @("/")
            allowRead = @($Tmp, $RepoRoot)
        }
    }
    Expect-FailureText "TCP local binding policy is rejected" $PolicyLocalBinding @($Cmd, "/C", "exit 0") "TCP policies are not supported yet"

    Write-Host "SUMMARY pass=$PassCount fail=$FailCount tmp=$Tmp"
    if ($FailCount -ne 0) {
        exit 1
    }
} finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
