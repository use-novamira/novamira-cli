# SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
# SPDX-License-Identifier: AGPL-3.0-or-later

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$package = "@novamira/cli"
$skillsPackage = "skills@1.5.18"

function Fail([string] $Message) {
  throw "novamira installer: $Message"
}

function Resolve-Application([string] $Name) {
  $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($null -eq $command) {
    Fail "$Name is required but was not found in PATH"
  }
  return $command.Source
}

function Invoke-Checked([string] $Command, [string[]] $Arguments) {
  & $Command @Arguments
  if ($LASTEXITCODE -ne 0) {
    Fail "$Command failed with exit code $LASTEXITCODE"
  }
}

$node = Resolve-Application "node"
$npm = Resolve-Application "npm"
$npx = Resolve-Application "npx"

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  Fail "the PowerShell installer supports Windows only; use install.sh on macOS or Linux"
}

$nodeVersion = & $node --version
if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^v(\d+)' -or [int] $Matches[1] -lt 22) {
  Fail "Node.js 22 or newer is required (found $nodeVersion)"
}

Write-Output "Installing $package with npm..."
Invoke-Checked $npm @("install", "--global", "--ignore-scripts", $package)

$npmPrefix = & $npm prefix --global
if ($LASTEXITCODE -ne 0) {
  Fail "npm prefix --global failed with exit code $LASTEXITCODE"
}
$npmPrefix = ([string] $npmPrefix).Trim()
$novamiraBin = Join-Path $npmPrefix "novamira.cmd"
if (-not (Test-Path -LiteralPath $novamiraBin -PathType Leaf)) {
  Fail "npm installed Novamira, but novamira is not available in PATH (npm prefix: $npmPrefix)"
}

Invoke-Checked $novamiraBin @("--version")
Invoke-Checked $novamiraBin @("doctor", "--offline")

$npmRoot = & $npm root --global
if ($LASTEXITCODE -ne 0) {
  Fail "npm root --global failed with exit code $LASTEXITCODE"
}
$npmRoot = ([string] $npmRoot).Trim()
$skillSource = Join-Path $npmRoot "@novamira/cli"
$skillFile = Join-Path $skillSource "skills/novamira/SKILL.md"
if (-not (Test-Path -LiteralPath $skillFile -PathType Leaf)) {
  Fail "the installed npm package does not contain the Novamira agent skill"
}

$skipSkill = [Environment]::GetEnvironmentVariable("NOVAMIRA_SKIP_SKILL")
if ($skipSkill -eq "1") {
  Write-Output "`nSkipping Novamira agent skill installation."
} else {
  Write-Output "`nInstalling the Novamira agent skill globally..."
  $agent = [Environment]::GetEnvironmentVariable("NOVAMIRA_AGENT")
  $oldDisableTelemetry = [Environment]::GetEnvironmentVariable("DISABLE_TELEMETRY")
  $oldIgnoreScripts = [Environment]::GetEnvironmentVariable("npm_config_ignore_scripts")
  try {
    [Environment]::SetEnvironmentVariable("DISABLE_TELEMETRY", "1")
    [Environment]::SetEnvironmentVariable("npm_config_ignore_scripts", "true")
    $skillArguments = @("--yes", $skillsPackage, "add", $skillSource, "--skill", "novamira", "--global")
    if (-not [string]::IsNullOrWhiteSpace($agent)) {
      $skillArguments += @("--agent", $agent, "--yes")
    } elseif ([Console]::IsInputRedirected) {
      Fail "set NOVAMIRA_AGENT for unattended skill installation, or NOVAMIRA_SKIP_SKILL=1"
    }
    Invoke-Checked $npx $skillArguments
  } finally {
    [Environment]::SetEnvironmentVariable("DISABLE_TELEMETRY", $oldDisableTelemetry)
    [Environment]::SetEnvironmentVariable("npm_config_ignore_scripts", $oldIgnoreScripts)
  }
}

Write-Output "`nNovamira CLI installation completed successfully."
