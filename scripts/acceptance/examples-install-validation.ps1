# 示例包安装闭环验证（Consumer 侧）
# 目标：3 个 Skill + 2 个 MCP + 1 个 Plugin 的 published 夹具包，
#       在隔离 HOME 中真实完成 tah install → tah verify → tah uninstall；
#       另验证 Grade E 风险包被拦截。
# 前置：docker compose 三服务运行（api/db/web），API 健康。
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$codeWorktree = "D:\Github\Documents\GitHub\trusted-agent-hub"
$cliEntry = Join-Path $codeWorktree "apps\cli\dist\apps\cli\src\cli.js"
$composeFile = Join-Path $codeWorktree "docker-compose.yml"
$api = "http://127.0.0.1:8000"

$originalLocation = (Get-Location).Path
$originalHome = $env:HOME
$originalUserProfile = $env:USERPROFILE
$originalApiUrl = $env:TRUSTED_AGENT_HUB_API_URL
$originalToken = $env:TRUSTED_AGENT_HUB_TOKEN
$originalNodeExtraCaCerts = $env:NODE_EXTRA_CA_CERTS

$runId = [guid]::NewGuid().ToString("N").Substring(0, 10)
$fixtureRoot = Join-Path $env:TEMP "tah-examples-validation-$runId"
$isolatedHome = Join-Path $env:TEMP "tah-examples-home-$runId"
$artifactProcess = $null
$artifactProcessStartTime = $null
$artifactPort = $null
$certificatePath = $null
$testToken = $null
$testUserId = $null

# ── 待验证包定义 ──
$packages = @(
    @{ Name = "val-demo-code-review";   SourceDir = "examples\skills\demo-code-review";        Grade = "A" },
    @{ Name = "val-demo-summarization"; SourceDir = "examples\skills\demo-summarization";      Grade = "A" },
    @{ Name = "val-demo-test-generation"; SourceDir = "examples\skills\demo-test-generation";  Grade = "A" },
    @{ Name = "val-demo-filesystem";    SourceDir = "examples\mcp-servers\demo-filesystem";     Grade = "A" },
    @{ Name = "val-demo-sql-explorer";  SourceDir = "examples\mcp-servers\demo-sql-explorer";   Grade = "A" },
    @{ Name = "val-demo-dev-toolkit";   SourceDir = "examples\plugins\demo-dev-toolkit";        Grade = "A" },
    @{ Name = "val-risky-executor";     SourceDir = "examples\risky-packages\risky-executor";   Grade = "E" }
)

function Invoke-NodeCli([string[]]$Arguments) {
    $previousEap = $ErrorActionPreference
    $output = @()
    $exitCode = -1
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& node $cliEntry @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEap
    }
    [pscustomobject]@{ ExitCode = $exitCode; Text = ($output -join "`n") }
}

Write-Host "=== 1. 构建 HTTPS 制品（每个示例包一个 zip） ==="
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$gitExe = (Get-Command git -ErrorAction Stop).Source
$gitInstallRoot = Split-Path (Split-Path $gitExe -Parent) -Parent
$openssl = @(
    (Join-Path $gitInstallRoot "usr\bin\openssl.exe"),
    (Join-Path $gitInstallRoot "mingw64\bin\openssl.exe")
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($openssl)) { throw "OpenSSL not found" }
$certificatePath = Join-Path $fixtureRoot "localhost-cert.pem"
$privateKeyPath = Join-Path $fixtureRoot "localhost-key.pem"
$previousEap = $ErrorActionPreference
$opensslExit = 0
try {
    $ErrorActionPreference = "Continue"
    & $openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 `
        -keyout $privateKeyPath -out $certificatePath `
        -subj "/CN=127.0.0.1" `
        -addext "subjectAltName=IP:127.0.0.1" `
        -addext "basicConstraints=critical,CA:TRUE" 2>&1 | Out-Null
    $opensslExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousEap
}
if ($opensslExit -ne 0) { throw "openssl failed (exit $opensslExit)" }

foreach ($pkg in $packages) {
    $sourcePath = Join-Path $codeWorktree $pkg.SourceDir
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
        throw "Example source missing: $sourcePath"
    }
    $zipPath = Join-Path $fixtureRoot ($pkg.Name + ".zip")
    Compress-Archive -LiteralPath $sourcePath -DestinationPath $zipPath -Force
    $pkg.Sha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $pkg.Size = (Get-Item -LiteralPath $zipPath).Length
    $pkg.ZipName = $pkg.Name + ".zip"
    $pkg.RootName = Split-Path $sourcePath -Leaf
    Write-Host "  + $($pkg.Name) sha256=$($pkg.Sha256.Substring(0,12))… size=$($pkg.Size) root=$($pkg.RootName)"
}

$portProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$portProbe.Start()
$artifactPort = ([System.Net.IPEndPoint]$portProbe.LocalEndpoint).Port
$portProbe.Stop()

$serverScriptPath = Join-Path $fixtureRoot "https-server.js"
$serverScript = @'
const https = require('https');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname);
const port = Number(process.argv[2]);
const names = process.argv.slice(3);
const server = https.createServer(
  { cert: fs.readFileSync(path.join(root, 'localhost-cert.pem')), key: fs.readFileSync(path.join(root, 'localhost-key.pem')) },
  (req, res) => {
    const pathname = new URL(req.url, 'https://127.0.0.1').pathname.slice(1);
    if (req.method !== 'GET' || !names.includes(pathname)) { res.writeHead(404); res.end('not found'); return; }
    const archive = path.join(root, pathname);
    const stat = fs.statSync(archive);
    res.writeHead(200, { 'content-type': 'application/zip', 'content-length': stat.size });
    fs.createReadStream(archive).pipe(res);
  }
);
server.listen(port, '127.0.0.1');
'@
[System.IO.File]::WriteAllText($serverScriptPath, $serverScript, $utf8NoBom)
$nodeExe = (Get-Command node -ErrorAction Stop).Source
$args = @($serverScriptPath, [string]$artifactPort)
foreach ($pkg in $packages) { $args += $pkg.ZipName }
$artifactProcess = Start-Process -FilePath $nodeExe -ArgumentList $args -WindowStyle Hidden -PassThru
$artifactProcessStartTime = $artifactProcess.StartTime
$env:NODE_EXTRA_CA_CERTS = $certificatePath

$artifactReady = $false
1..20 | ForEach-Object {
    if (-not $artifactReady) {
        $previousEap = $ErrorActionPreference
        $probe = @()
        try {
            $ErrorActionPreference = "Continue"
            $probe = @(& node -e "fetch(process.argv[1]).then(r=>r.arrayBuffer()).then(b=>console.log(b.byteLength)).catch(e=>process.exit(1))" "https://127.0.0.1:$artifactPort/$($packages[0].ZipName)" 2>&1)
            $artifactReady = $LASTEXITCODE -eq 0 -and [long](($probe -join "").Trim()) -eq $packages[0].Size
        } finally {
            $ErrorActionPreference = $previousEap
        }
        if (-not $artifactReady) { Start-Sleep -Milliseconds 500 }
    }
}
if (-not $artifactReady) { throw "HTTPS artifact server not ready" }
Write-Host "Artifact server ready on port $artifactPort"

Write-Host "=== 2. 写入 published 夹具（A 级 x6 + E 级 x1） ==="
foreach ($pkg in $packages) {
    $packageId = "pkg-" + $pkg.Name.Replace("-", "")
    $versionId = "ver-" + $pkg.Name.Replace("-", "")
    $copyDestination = "~/.claude/skills/$($pkg.Name)/"
    $grade = $pkg.Grade
    $level = if ($grade -eq "E") { "untrusted" } else { "low" }
    $rec = if ($grade -eq "E") { "blocked" } else { "safe" }
    $sql = @"
BEGIN;
DELETE FROM install_records WHERE version_id = '$versionId';
DELETE FROM trust_levels WHERE version_id = '$versionId';
DELETE FROM scan_reports WHERE version_id = '$versionId';
DELETE FROM review_records WHERE version_id = '$versionId';
DELETE FROM audit_logs WHERE target_id = '$versionId' AND target_type = 'version';
DELETE FROM package_versions WHERE id = '$versionId';
DELETE FROM packages WHERE id = '$packageId';
INSERT INTO packages (id, name, status, latest_version, data)
VALUES (
  '$packageId', '$($pkg.Name)', 'published', '1.0.0',
  jsonb_build_object('id', '$packageId', 'name', '$($pkg.Name)', 'description', 'Example package install validation', 'type', 'skill', 'latest_version', '1.0.0', 'status', 'published', 'keywords', jsonb_build_array('validation'), 'compatibility', jsonb_build_array('claude-code'), 'install_count', 0)::json
);
INSERT INTO package_versions (id, package_id, version, status, data)
VALUES (
  '$versionId', '$packageId', '1.0.0', 'published',
  jsonb_build_object(
    'id', '$versionId', 'package_id', '$packageId', 'version', '1.0.0', 'status', 'published',
    'source', jsonb_build_object('type', 'local_upload', 'repository_url', 'https://127.0.0.1:$artifactPort/', 'download_url', 'https://127.0.0.1:$artifactPort/$($pkg.ZipName)', 'ref', 'v1.0.0', 'commit_hash', '0000000000000000000000000000000000000000', 'verified_owner', true),
    'integrity', jsonb_build_object('sha256', '$($pkg.Sha256)', 'download_size_bytes', $($pkg.Size)),
    'compatibility', jsonb_build_array('claude-code'),
    'permissions', jsonb_build_object('filesystem', jsonb_build_object('read', jsonb_build_array(), 'write', jsonb_build_array(), 'delete', false), 'shell', jsonb_build_object('allowed', false, 'commands', jsonb_build_array()), 'network', jsonb_build_object('allowed', false, 'domains', jsonb_build_array())),
    'installation', jsonb_build_object('method', 'copy_directory', 'target_client', 'claude-code', 'steps', jsonb_build_array(
      jsonb_build_object('action', 'download', 'url', 'https://127.0.0.1:$artifactPort/$($pkg.ZipName)'),
      jsonb_build_object('action', 'verify', 'algorithm', 'sha256', 'checksum', '$($pkg.Sha256)'),
      jsonb_build_object('action', 'extract', 'archive', '$($pkg.ZipName)'),
      jsonb_build_object('action', 'copy', 'source', '$($pkg.RootName)/', 'destination', '$copyDestination')
    )),
    'trust_score', jsonb_build_object('model_version', 'validation-v1', 'score', $(if ($grade -eq "E") { 10 } else { 95 }), 'risk_summary', jsonb_build_object('level', '$level', 'grade', '$grade', 'top_risks', jsonb_build_array(), 'install_recommendation', '$rec'))
  )::json
);
COMMIT;
"@
    $previousEap = $ErrorActionPreference
    $psqlExit = 0
    try {
        $ErrorActionPreference = "Continue"
        $sql | & docker compose -f $composeFile exec -T db `
            psql -U postgres -d trusted_agent_hub -v "ON_ERROR_STOP=1" 2>&1 | Out-Null
        $psqlExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEap
    }
    if ($psqlExit -ne 0) { throw "Fixture insert failed for $($pkg.Name) (exit $psqlExit)" }
    Write-Host "  + fixture $($pkg.Name) ($grade)"
}

Write-Host "=== 3. 注册临时用户 ==="
$username = "examples-e2e-$runId"
$password = "ExamplesPw_$runId"
$registerBody = @{
    username = $username
    password = $password
    email = "$username@example.com"
    display_name = "Examples validation"
} | ConvertTo-Json
$tokens = Invoke-RestMethod -Method Post -Uri "$api/api/v0/auth/register" `
    -ContentType "application/json" -Body $registerBody -TimeoutSec 10
$testUserId = [string]$tokens.user.id
$testToken = [string]$tokens.access_token
$env:TRUSTED_AGENT_HUB_TOKEN = $testToken
Write-Host "Registered $username"

Write-Host "=== 4. 隔离 HOME 中逐个 install / verify / uninstall ==="
New-Item -ItemType Directory -Path $isolatedHome | Out-Null
$env:HOME = $isolatedHome
$env:USERPROFILE = $isolatedHome
$env:TRUSTED_AGENT_HUB_API_URL = $api
$nodeHome = (& node -e "console.log(require('os').homedir())").Trim()
if ($nodeHome -ne $isolatedHome) { throw "HOME mismatch" }

$summary = @()
foreach ($pkg in $packages) {
    $installPath = Join-Path $isolatedHome ".claude\skills\$($pkg.Name)"
    if ($pkg.Grade -eq "E") {
        $result = Invoke-NodeCli -Arguments @("install", $pkg.Name, "--client", "claude-code", "--yes", "--force", "--accept-high-risk")
        $blocked = $result.ExitCode -ne 0 -and $result.Text -match "blocked|unavailable"
        $summary += [pscustomobject]@{ Package = $pkg.Name; Grade = "E"; Install = if ($blocked) { "BLOCKED-OK" } else { "UNEXPECTED" }; Verify = "-"; Uninstall = "-" }
        Write-Host "  $($pkg.Name): exit=$($result.ExitCode) blocked=$blocked"
        continue
    }
    $install = Invoke-NodeCli -Arguments @("install", $pkg.Name, "--client", "claude-code", "--yes")
    $installed = $install.ExitCode -eq 0 -and (Test-Path -LiteralPath $installPath -PathType Container)
    $verify = Invoke-NodeCli -Arguments @("verify", $pkg.Name, "--client", "claude-code")
    $verified = $verify.ExitCode -eq 0 -and $verify.Text -match "\[valid\]"
    $uninstall = Invoke-NodeCli -Arguments @("uninstall", $pkg.Name, "--client", "claude-code", "--yes")
    $uninstalled = $uninstall.ExitCode -eq 0 -and $uninstall.Text -match "\[uninstalled\]"
    $summary += [pscustomobject]@{
        Package = $pkg.Name
        Grade = $pkg.Grade
        Install = if ($installed) { "OK" } else { "FAIL" }
        Verify = if ($verified) { "OK" } else { "FAIL" }
        Uninstall = if ($uninstalled) { "OK" } else { "FAIL" }
    }
    Write-Host "  $($pkg.Name): install=$installed verify=$verified uninstall=$uninstalled"
}

$summary | Format-Table -AutoSize
$failed = @($summary | Where-Object { $_.Install -ne "OK" -and $_.Install -ne "BLOCKED-OK" -or $_.Verify -eq "FAIL" -or $_.Uninstall -eq "FAIL" })
if ($failed.Count -gt 0) {
    throw "Validation failed for: $($failed.Package -join ', ')"
}
Write-Host "`n=== EXAMPLES INSTALL VALIDATION ALL PASSED ==="

# ── 恢复与清理 ──
$env:HOME = $originalHome
$env:USERPROFILE = $originalUserProfile
$env:TRUSTED_AGENT_HUB_API_URL = $originalApiUrl
$env:TRUSTED_AGENT_HUB_TOKEN = $originalToken
$env:NODE_EXTRA_CA_CERTS = $originalNodeExtraCaCerts
Set-Location $originalLocation

if ($null -ne $artifactProcess) {
    $running = Get-Process -Id $artifactProcess.Id -ErrorAction SilentlyContinue
    if ($null -ne $running -and $running.ProcessName -eq "node" -and $running.StartTime -eq $artifactProcessStartTime) {
        Stop-Process -Id $running.Id
    }
}

$cleanupSql = @"
BEGIN;
$(foreach ($pkg in $packages) {
    $packageId = "pkg-" + $pkg.Name.Replace("-", "")
    $versionId = "ver-" + $pkg.Name.Replace("-", "")
    "DELETE FROM install_records WHERE version_id = '$versionId';"
    "DELETE FROM package_versions WHERE id = '$versionId' AND package_id = '$packageId';"
    "DELETE FROM packages WHERE id = '$packageId' AND name = '$($pkg.Name)';"
})
COMMIT;
"@
$previousEap = $ErrorActionPreference
try {
    $ErrorActionPreference = "Continue"
    $cleanupSql | & docker compose -f $composeFile exec -T db `
        psql -U postgres -d trusted_agent_hub -v "ON_ERROR_STOP=1" 2>&1 | Out-Null
    $cleanupExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousEap
}
if ($cleanupExit -ne 0) { Write-Warning "Fixture cleanup failed (exit $cleanupExit)" }
if (-not [string]::IsNullOrWhiteSpace($testUserId)) {
    $userSql = "DELETE FROM users WHERE id = '$testUserId' AND email = '$username@example.com';"
    $previousEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $userSql | & docker compose -f $composeFile exec -T db psql -U postgres -d trusted_agent_hub -v "ON_ERROR_STOP=1" 2>&1 | Out-Null
        $userExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEap
    }
    if ($userExit -ne 0) { Write-Warning "User cleanup failed (exit $userExit)" }
}

function Remove-VerifiedTempPath([string]$Candidate, [string]$Prefix) {
    if ([string]::IsNullOrWhiteSpace($Candidate) -or -not (Test-Path -LiteralPath $Candidate)) { return }
    $resolved = [System.IO.Path]::GetFullPath($Candidate)
    $tempPrefix = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd([char]92) + [char]92
    $leaf = Split-Path $resolved -Leaf
    if ($resolved.StartsWith($tempPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and $leaf.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse
    }
}
Remove-VerifiedTempPath $isolatedHome "tah-examples-home-"
Remove-VerifiedTempPath $fixtureRoot "tah-examples-validation-"
Write-Host "Restored Node HOME: $(& node -e "console.log(require('os').homedir())")"
