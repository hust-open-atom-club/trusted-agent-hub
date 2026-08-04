# CLI Uninstall 真实环境验收脚本（适配当前仓库）
# 依据 docs/cli-uninstall-real-environment-acceptance.md 改造：
#   - worktree 路径改为当前仓库 D:\Github\Documents\GitHub\trusted-agent-hub（main@80e1183，已含 consumer 合并）
#   - 注册环节由交互式 Get-Credential 改为自动生成密码（验收记录中已注明）
#   - 跳过 npm ci/build（已在验收前单独执行并通过）
# 前提：docker compose 三服务已启动（api/db/web），API 健康。
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$codeWorktree = "D:\Github\Documents\GitHub\trusted-agent-hub"
$cliRoot = Join-Path $codeWorktree "apps\cli"
$cliEntry = Join-Path $cliRoot "dist\apps\cli\src\cli.js"
$composeFile = Join-Path $codeWorktree "docker-compose.yml"
$healthyApiUrl = "http://127.0.0.1:8000"
$offlineApiUrl = "http://127.0.0.1:65534"

$originalLocation = (Get-Location).Path
$originalHome = $env:HOME
$originalUserProfile = $env:USERPROFILE
$originalApiUrl = $env:TRUSTED_AGENT_HUB_API_URL
$originalToken = $env:TRUSTED_AGENT_HUB_TOKEN
$originalNodeExtraCaCerts = $env:NODE_EXTRA_CA_CERTS

$runId = [guid]::NewGuid().ToString("N").Substring(0, 12)
$packageName = "cli-uninstall-e2e-$runId"
$packageId = "pkg-cli-uninstall-$runId"
$versionId = "ver-cli-uninstall-$runId"
$temporaryUsername = "cli-uninstall-e2e-$runId"
$temporaryEmail = "$temporaryUsername@example.com"
$testUserId = $null
$testToken = $null

$fixtureRoot = Join-Path $env:TEMP "tah-uninstall-fixture-$runId"
$isolatedHome = Join-Path $env:TEMP "tah-uninstall-home-$runId"
$artifactProcess = $null
$artifactProcessStartTime = $null
$artifactPort = $null
$artifactUrl = $null
$artifactSha256 = $null
$artifactSize = $null
$certificatePath = $null
$privateKeyPath = $null
$dockerStartedByAcceptance = $false

$installPath = Join-Path $isolatedHome ".claude\skills\$packageName"
$recordPath = Join-Path $isolatedHome ".trusted-agent-hub\installs.json"
$clientRoot = Join-Path $isolatedHome ".claude\skills"

function Read-LocalRecords {
    if (-not (Test-Path -LiteralPath $recordPath)) { return @() }
    $parsed = ConvertFrom-Json -InputObject (
        Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8
    )
    if ($null -eq $parsed) { return @() }
    @($parsed)
}

function Write-LocalRecords([object[]]$Records) {
    $json = ConvertTo-Json -InputObject @($Records) -Depth 20
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($recordPath, $json + "`n", $utf8NoBom)
}

function Get-MatchingRecords {
    @(Read-LocalRecords | Where-Object {
        $_.package_name -eq $packageName -and $_.client -eq "claude-code"
    })
}

function Assert-MatchingRecordRemoved {
    $matchingRecords = @(Get-MatchingRecords)
    if ($matchingRecords.Count -ne 0) {
        throw "Matching local install record still exists"
    }
}

function Get-ServerInstallRecordCount {
    $raw = & docker compose -f $composeFile exec -T db `
        psql -U postgres -d trusted_agent_hub -tAc `
        "SELECT COUNT(*) FROM install_records WHERE version_id = '$versionId';"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to query server install_records"
    }
    [int](($raw -join "").Trim())
}

function Assert-ServerCountUnchanged([int]$Before) {
    $after = Get-ServerInstallRecordCount
    if ($after -ne $Before) {
        throw "Uninstall changed server install_records: $Before -> $after"
    }
    Write-Host "Server install_records unchanged: $Before"
}

function Assert-NoTransactionLeftovers {
    if (-not (Test-Path -LiteralPath $clientRoot)) { return }
    $leftovers = @(Get-ChildItem -LiteralPath $clientRoot -Force | Where-Object {
        $_.Name -like ".uninstall-*" -or
        $_.Name -like ".tmp-*" -or
        $_.Name -like ".staging-*" -or
        $_.Name -like ".backup-*"
    })
    if ($leftovers.Count -ne 0) {
        throw "Transaction leftovers found: $($leftovers.FullName -join ', ')"
    }
}

function Invoke-NodeCli([string[]]$Arguments) {
    $previousErrorActionPreference = $ErrorActionPreference
    $output = @()
    $exitCode = -1
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& node $cliEntry @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    [pscustomobject]@{
        ExitCode = $exitCode
        Text = @($output | ForEach-Object { $_.ToString() }) -join "`n"
    }
}

function Invoke-Uninstall([string[]]$Arguments, [int]$ExpectedExitCode, [string]$ExpectedStatus) {
    $result = Invoke-NodeCli -Arguments $Arguments
    $result.Text
    if ($result.ExitCode -ne $ExpectedExitCode) {
        throw "Unexpected uninstall exit code: expected $ExpectedExitCode, got $($result.ExitCode)"
    }
    if ($result.Text -notmatch ("\[" + [regex]::Escape($ExpectedStatus) + "\]")) {
        throw "Expected uninstall status [$ExpectedStatus], got: $($result.Text)"
    }
}

function Install-TestPackage {
    $env:TRUSTED_AGENT_HUB_API_URL = $healthyApiUrl
    $result = Invoke-NodeCli -Arguments @(
        "install", $packageName,
        "--client", "claude-code",
        "--version", "1.0.0",
        "--yes", "--force", "--accept-high-risk"
    )
    $result.Text
    if ($result.ExitCode -ne 0) {
        throw "Real CLI install failed with exit code $($result.ExitCode): $($result.Text)"
    }
    if (-not (Test-Path -LiteralPath $installPath -PathType Container)) {
        throw "Install directory missing: $installPath"
    }
    $matchingRecords = @(Get-MatchingRecords)
    if ($matchingRecords.Count -ne 1) {
        throw "Expected exactly one matching local install record"
    }
    Assert-NoTransactionLeftovers
}

Write-Host "=== 5. Docker 服务与 API 健康检查 ==="
$expectedServices = @("api", "db", "web")
$runningServices = @(
    & docker compose -f $composeFile ps --services --status running |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() }
)
if ($LASTEXITCODE -ne 0) { throw "docker compose ps failed" }
if ($runningServices.Count -eq 0) {
    & docker compose -f $composeFile up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
    $dockerStartedByAcceptance = $true
} elseif (@($expectedServices | Where-Object { $_ -notin $runningServices }).Count -ne 0) {
    throw "Docker stack is partially running: $($runningServices -join ', ')"
}
$apiReady = $false
1..30 | ForEach-Object {
    if (-not $apiReady) {
        try {
            $health = Invoke-RestMethod -Uri "$healthyApiUrl/api/v0/health" -TimeoutSec 3
            $apiReady = $health.status -eq "ok"
        } catch {
            $apiReady = $false
        }
        if (-not $apiReady) { Start-Sleep -Seconds 2 }
    }
}
if (-not $apiReady) { throw "API health check failed" }
Write-Host "Docker services running: $($runningServices -join ', ')"
Write-Host "API health status: $($health.status)"

Write-Host "=== 6. 本地 HTTPS 测试制品 ==="
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$packageSource = Join-Path $fixtureRoot "package"
New-Item -ItemType Directory -Path $packageSource | Out-Null
$skillText = @"
---
name: $packageName
description: Temporary package for CLI uninstall acceptance.
---

# CLI Uninstall Acceptance Fixture

run_id: $runId
"@
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    (Join-Path $packageSource "SKILL.md"), $skillText, $utf8NoBom
)
$archivePath = Join-Path $fixtureRoot "package.zip"
Compress-Archive -LiteralPath $packageSource -DestinationPath $archivePath
$artifactSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$artifactSize = (Get-Item -LiteralPath $archivePath).Length

$gitExe = (Get-Command git -ErrorAction Stop).Source
$gitInstallRoot = Split-Path (Split-Path $gitExe -Parent) -Parent
$opensslCandidates = @(
    (Join-Path $gitInstallRoot "usr\bin\openssl.exe"),
    (Join-Path $gitInstallRoot "mingw64\bin\openssl.exe")
)
$opensslCommand = Get-Command openssl -ErrorAction SilentlyContinue
if ($null -ne $opensslCommand) {
    $opensslCandidates += $opensslCommand.Source
}
$openssl = $opensslCandidates | Where-Object {
    Test-Path -LiteralPath $_ -PathType Leaf
} | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($openssl)) {
    throw "OpenSSL was not found in the Git installation"
}

$certificatePath = Join-Path $fixtureRoot "localhost-cert.pem"
$privateKeyPath = Join-Path $fixtureRoot "localhost-key.pem"
& $openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 `
    -keyout $privateKeyPath -out $certificatePath `
    -subj "/CN=127.0.0.1" `
    -addext "subjectAltName=IP:127.0.0.1" `
    -addext "basicConstraints=critical,CA:TRUE"
if ($LASTEXITCODE -ne 0) { throw "Failed to create temporary TLS certificate" }

$portProbe = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Loopback, 0
)
$portProbe.Start()
$artifactPort = ([System.Net.IPEndPoint]$portProbe.LocalEndpoint).Port
$portProbe.Stop()
$artifactUrl = "https://127.0.0.1:$artifactPort/package.zip"

$serverScriptPath = Join-Path $fixtureRoot "https-server.js"
$serverScript = @'
const https = require('https');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname);
const cert = path.join(root, 'localhost-cert.pem');
const key = path.join(root, 'localhost-key.pem');
const port = Number(process.argv[2]);
const archive = path.join(root, 'package.zip');
const server = https.createServer(
  { cert: fs.readFileSync(cert), key: fs.readFileSync(key) },
  (req, res) => {
    const pathname = new URL(req.url, 'https://127.0.0.1').pathname;
    if (req.method !== 'GET' || pathname !== '/package.zip') {
      res.writeHead(404); res.end('not found'); return;
    }
    const stat = fs.statSync(archive);
    res.writeHead(200, {
      'content-type': 'application/zip',
      'content-length': stat.size
    });
    fs.createReadStream(archive).pipe(res);
  }
);
server.listen(port, '127.0.0.1');
'@
[System.IO.File]::WriteAllText($serverScriptPath, $serverScript, $utf8NoBom)

$nodeExe = (Get-Command node -ErrorAction Stop).Source
$artifactProcess = Start-Process -FilePath $nodeExe `
    -ArgumentList @($serverScriptPath, [string]$artifactPort) `
    -WindowStyle Hidden -PassThru
$artifactProcessStartTime = $artifactProcess.StartTime
$env:NODE_EXTRA_CA_CERTS = $certificatePath

$artifactReady = $false
1..20 | ForEach-Object {
    if (-not $artifactReady) {
        $previousErrorActionPreference = $ErrorActionPreference
        $probeOutput = @()
        $probeExit = -1
        try {
            $ErrorActionPreference = "Continue"
            $probeOutput = @(& node -e `
                "fetch(process.argv[1]).then(r=>{if(!r.ok)throw Error(String(r.status));return r.arrayBuffer()}).then(b=>console.log(b.byteLength)).catch(e=>{console.error(e.message);process.exit(1)})" `
                $artifactUrl 2>&1)
            $probeExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $artifactReady = $probeExit -eq 0 -and `
            [long](($probeOutput -join "").Trim()) -eq $artifactSize
        if (-not $artifactReady) { Start-Sleep -Milliseconds 500 }
    }
}
if (-not $artifactReady) { throw "Local HTTPS artifact server is not ready" }
Write-Host "Artifact ready: $artifactUrl sha256=$artifactSha256 size=$artifactSize"

Write-Host "=== 7. 写入并验证 published 数据库夹具 ==="
$copyDestination = "~/.claude/skills/$packageName/"
$commitHash = "0" * 40
$fixtureSql = @'
BEGIN;

INSERT INTO packages (id, name, status, latest_version, data)
VALUES (
  :'package_id', :'package_name', 'published', '1.0.0',
  jsonb_build_object(
    'id', :'package_id',
    'name', :'package_name',
    'description', 'Temporary CLI uninstall acceptance package',
    'type', 'skill',
    'latest_version', '1.0.0',
    'status', 'published',
    'keywords', jsonb_build_array('acceptance'),
    'compatibility', jsonb_build_array('claude-code'),
    'install_count', 0
  )::json
);

INSERT INTO package_versions (id, package_id, version, status, data)
VALUES (
  :'version_id', :'package_id', '1.0.0', 'published',
  jsonb_build_object(
    'id', :'version_id',
    'package_id', :'package_id',
    'version', '1.0.0',
    'status', 'published',
    'source', jsonb_build_object(
      'type', 'local_upload',
      'repository_url', :'repository_url',
      'download_url', :'artifact_url',
      'ref', 'v1.0.0',
      'commit_hash', :'commit_hash',
      'verified_owner', true
    ),
    'integrity', jsonb_build_object(
      'sha256', :'artifact_sha256',
      'download_size_bytes', :'artifact_size'::bigint
    ),
    'compatibility', jsonb_build_array('claude-code'),
    'permissions', jsonb_build_object(
      'filesystem', jsonb_build_object(
        'read', jsonb_build_array(),
        'write', jsonb_build_array(),
        'delete', false
      ),
      'shell', jsonb_build_object('allowed', false, 'commands', jsonb_build_array()),
      'network', jsonb_build_object('allowed', false, 'domains', jsonb_build_array())
    ),
    'installation', jsonb_build_object(
      'method', 'copy_directory',
      'target_client', 'claude-code',
      'steps', jsonb_build_array(
        jsonb_build_object('action', 'download', 'url', :'artifact_url'),
        jsonb_build_object(
          'action', 'verify', 'algorithm', 'sha256',
          'checksum', :'artifact_sha256'
        ),
        jsonb_build_object('action', 'extract', 'archive', 'package.zip'),
        jsonb_build_object(
          'action', 'copy', 'source', 'package/',
          'destination', :'copy_destination'
        )
      )
    ),
    'trust_score', jsonb_build_object(
      'model_version', 'acceptance-fixture-v1',
      'risk_summary', jsonb_build_object(
        'level', 'low',
        'grade', 'A',
        'top_risks', jsonb_build_array(),
        'install_recommendation', 'safe'
      )
    )
  )::json
);

COMMIT;
'@

$fixtureSql | & docker compose -f $composeFile exec -T db `
    psql -U postgres -d trusted_agent_hub `
    -v "ON_ERROR_STOP=1" `
    -v "package_id=$packageId" `
    -v "package_name=$packageName" `
    -v "version_id=$versionId" `
    -v "repository_url=https://127.0.0.1:$artifactPort/" `
    -v "artifact_url=$artifactUrl" `
    -v "commit_hash=$commitHash" `
    -v "artifact_sha256=$artifactSha256" `
    -v "artifact_size=$artifactSize" `
    -v "copy_destination=$copyDestination"
if ($LASTEXITCODE -ne 0) { throw "Failed to create database fixture" }

$verifySql = @'
SELECT p.name, p.status AS package_status, p.latest_version,
       pv.version, pv.status AS version_status,
       pv.data::jsonb #>> '{installation,target_client}' AS target_client,
       pv.data::jsonb #>> '{installation,steps,3,destination}' AS destination
FROM package_versions pv
JOIN packages p ON p.id = pv.package_id
WHERE pv.id = :'version_id' AND pv.package_id = :'package_id';
'@
$fixtureRow = $verifySql | & docker compose -f $composeFile exec -T db `
    psql -U postgres -d trusted_agent_hub `
    -v "ON_ERROR_STOP=1" -v "package_id=$packageId" -v "version_id=$versionId" `
    -AtF "|"
if ($LASTEXITCODE -ne 0) { throw "Failed to verify database fixture" }
$expectedRow = "$packageName|published|1.0.0|1.0.0|published|claude-code|$copyDestination"
if (($fixtureRow -join "").Trim() -ne $expectedRow) {
    throw "Database fixture mismatch: $($fixtureRow -join '')"
}
Write-Host "Published fixture verified: $packageName@1.0.0"

Write-Host "=== 8. 验证真实 Manifest API ==="
$manifestUrl = "$healthyApiUrl/api/v0/packages/$packageName/install-manifest" + `
    "?client=claude-code&version=1.0.0"
$manifest = Invoke-RestMethod -Uri $manifestUrl -TimeoutSec 10
$actions = @($manifest.installation.steps | ForEach-Object { $_.action })
$grade = [string]$manifest.risk_summary.grade
if ($manifest.name -ne $packageName) { throw "Manifest package mismatch" }
if ($manifest.version -ne "1.0.0") { throw "Manifest version mismatch" }
if ([string]$manifest.source.download_url -ne $artifactUrl) { throw "Manifest URL mismatch" }
if ($manifest.integrity.sha256 -ne $artifactSha256) { throw "Manifest SHA-256 mismatch" }
if ([long]$manifest.integrity.download_size_bytes -ne $artifactSize) { throw "Manifest size mismatch" }
if ($manifest.installation.target_client -ne "claude-code") { throw "Manifest client mismatch" }
if (($actions -join ",") -ne "download,verify,extract,copy") { throw "Manifest step order mismatch" }
if ($manifest.installation.steps[3].destination -ne $copyDestination) { throw "Manifest destination mismatch" }
if ($grade -notmatch '^[A-E]$') {
    throw "Manifest risk_summary.grade must be one of A, B, C, D, E"
}
Write-Host "Manifest OK: $($actions -join ' -> ') grade=$grade"

Write-Host "=== 9. 注册临时用户 ==="
$password = "UninstallPw_$runId"
$registerBody = @{
    username = $temporaryUsername
    password = $password
    email = $temporaryEmail
    display_name = "CLI uninstall acceptance"
} | ConvertTo-Json
$tokens = Invoke-RestMethod `
    -Method Post -Uri "$healthyApiUrl/api/v0/auth/register" `
    -ContentType "application/json" -Body $registerBody -TimeoutSec 10
if ([string]::IsNullOrWhiteSpace([string]$tokens.user.id)) {
    throw "Registration response did not contain user.id"
}
$testUserId = [string]$tokens.user.id
if ([string]::IsNullOrWhiteSpace([string]$tokens.access_token)) {
    throw "Registration response did not contain access_token"
}
$testToken = [string]$tokens.access_token
$env:TRUSTED_AGENT_HUB_TOKEN = $testToken
Write-Host "Temporary user registered: $temporaryUsername"

Write-Host "=== 10. 创建并验证隔离 HOME ==="
New-Item -ItemType Directory -Path $isolatedHome | Out-Null
$env:HOME = $isolatedHome
$env:USERPROFILE = $isolatedHome
$env:TRUSTED_AGENT_HUB_API_URL = $healthyApiUrl
$env:TRUSTED_AGENT_HUB_TOKEN = $testToken
$nodeHome = (& node -e "console.log(require('os').homedir())").Trim()
if ($nodeHome -ne $isolatedHome) {
    throw "Node HOME mismatch: expected $isolatedHome, got $nodeHome"
}
Write-Host "Isolated HOME verified: $isolatedHome"

Write-Host "=== 11. clean 内容和离线卸载 ==="
Install-TestPackage
$countBeforeClean = Get-ServerInstallRecordCount
if ($countBeforeClean -ne 1) {
    throw "Expected one server install record after installation"
}
$env:TRUSTED_AGENT_HUB_API_URL = $offlineApiUrl
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--yes") `
    -ExpectedExitCode 0 -ExpectedStatus "uninstalled"
if (Test-Path -LiteralPath $installPath) { throw "Install directory still exists" }
Assert-MatchingRecordRemoved
Assert-ServerCountUnchanged $countBeforeClean
Assert-NoTransactionLeftovers
Write-Host "Section 11 PASSED"

Write-Host "=== 12.1 modified 默认拒绝，force 成功 ==="
Install-TestPackage
Add-Content -LiteralPath (Join-Path $installPath "SKILL.md") `
    -Value "`nmodified-by-acceptance"
$countBeforeModified = Get-ServerInstallRecordCount
$env:TRUSTED_AGENT_HUB_API_URL = $offlineApiUrl
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--yes") `
    -ExpectedExitCode 1 -ExpectedStatus "modified"
if (-not (Test-Path -LiteralPath $installPath)) { throw "Modified directory was removed" }
$matchingRecords = @(Get-MatchingRecords)
if ($matchingRecords.Count -ne 1) { throw "Modified record was removed" }
Assert-ServerCountUnchanged $countBeforeModified
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--force", "--yes") `
    -ExpectedExitCode 0 -ExpectedStatus "uninstalled"
if (Test-Path -LiteralPath $installPath) { throw "Forced modified uninstall left directory" }
Assert-MatchingRecordRemoved
Assert-ServerCountUnchanged $countBeforeModified
Assert-NoTransactionLeftovers
Write-Host "Section 12.1 PASSED"

Write-Host "=== 12.2 legacy 默认拒绝，force 成功 ==="
Install-TestPackage
$records = Read-LocalRecords
$matching = @($records | Where-Object {
    $_.package_name -eq $packageName -and $_.client -eq "claude-code"
})
if ($matching.Count -ne 1) { throw "Expected one record before legacy mutation" }
$matching[0].PSObject.Properties.Remove("content_hash_algorithm")
$matching[0].PSObject.Properties.Remove("content_sha256")
Write-LocalRecords $records
$countBeforeLegacy = Get-ServerInstallRecordCount
$env:TRUSTED_AGENT_HUB_API_URL = $offlineApiUrl
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--yes") `
    -ExpectedExitCode 1 -ExpectedStatus "legacy_record"
if (-not (Test-Path -LiteralPath $installPath)) { throw "Legacy directory was removed" }
$matchingRecords = @(Get-MatchingRecords)
if ($matchingRecords.Count -ne 1) { throw "Legacy record was removed" }
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--force", "--yes") `
    -ExpectedExitCode 0 -ExpectedStatus "uninstalled"
if (Test-Path -LiteralPath $installPath) { throw "Forced legacy uninstall left directory" }
Assert-MatchingRecordRemoved
Assert-ServerCountUnchanged $countBeforeLegacy
Assert-NoTransactionLeftovers
Write-Host "Section 12.2 PASSED"

Write-Host "=== 12.3 未知字段必须返回 record_invalid ==="
Install-TestPackage
$records = Read-LocalRecords
$matching = @($records | Where-Object {
    $_.package_name -eq $packageName -and $_.client -eq "claude-code"
})
if ($matching.Count -ne 1) { throw "Expected one record before unknown-field mutation" }
$matching[0] | Add-Member -NotePropertyName "unexpected_field" `
    -NotePropertyValue "must-fail-closed"
Write-LocalRecords $records
$countBeforeInvalid = Get-ServerInstallRecordCount
$env:TRUSTED_AGENT_HUB_API_URL = $offlineApiUrl
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--force", "--yes") `
    -ExpectedExitCode 1 -ExpectedStatus "record_invalid"
if (-not (Test-Path -LiteralPath $installPath)) { throw "Invalid-record directory was removed" }
$records = Read-LocalRecords
$matching = @($records | Where-Object {
    $_.package_name -eq $packageName -and $_.client -eq "claude-code"
})
$matching[0].PSObject.Properties.Remove("unexpected_field")
Write-LocalRecords $records
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--force", "--yes") `
    -ExpectedExitCode 0 -ExpectedStatus "uninstalled"
Assert-MatchingRecordRemoved
Assert-ServerCountUnchanged $countBeforeInvalid
Assert-NoTransactionLeftovers
Write-Host "Section 12.3 PASSED"

Write-Host "=== 13. stale record 清理 ==="
Install-TestPackage
$resolvedInstall = [System.IO.Path]::GetFullPath($installPath)
$resolvedClientRoot = [System.IO.Path]::GetFullPath($clientRoot).TrimEnd('\') + '\'
if (-not $resolvedInstall.StartsWith(
    $resolvedClientRoot, [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Refusing to remove unverified install path"
}
Remove-Item -LiteralPath $resolvedInstall -Recurse -Force
$countBeforeStale = Get-ServerInstallRecordCount
$env:TRUSTED_AGENT_HUB_API_URL = $offlineApiUrl
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--yes") `
    -ExpectedExitCode 0 -ExpectedStatus "stale_record_removed"
Assert-MatchingRecordRemoved
Assert-ServerCountUnchanged $countBeforeStale
Assert-NoTransactionLeftovers
Write-Host "Section 13 PASSED"

Write-Host "=== 14. 路径越界和 sentinel 不变量 ==="
Install-TestPackage
$sentinelPath = Join-Path $fixtureRoot "outside-home-sentinel.txt"
[System.IO.File]::WriteAllText($sentinelPath, "sentinel-$runId", $utf8NoBom)
$sentinelContentBefore = Get-Content -LiteralPath $sentinelPath -Raw -Encoding UTF8
$sentinelHashBefore = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash
$sentinelTimeBefore = (Get-Item -LiteralPath $sentinelPath).LastWriteTimeUtc.Ticks
$records = Read-LocalRecords
$matching = @($records | Where-Object {
    $_.package_name -eq $packageName -and $_.client -eq "claude-code"
})
if ($matching.Count -ne 1) { throw "Expected one record before unsafe-path mutation" }
$matching[0].install_path = $sentinelPath
Write-LocalRecords $records
$countBeforeUnsafe = Get-ServerInstallRecordCount
$env:TRUSTED_AGENT_HUB_API_URL = $offlineApiUrl
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--force", "--yes") `
    -ExpectedExitCode 1 -ExpectedStatus "unsafe_path"
$sentinelContentAfter = Get-Content -LiteralPath $sentinelPath -Raw -Encoding UTF8
$sentinelHashAfter = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash
$sentinelTimeAfter = (Get-Item -LiteralPath $sentinelPath).LastWriteTimeUtc.Ticks
if ($sentinelContentAfter -ne $sentinelContentBefore) { throw "Sentinel content changed" }
if ($sentinelHashAfter -ne $sentinelHashBefore) { throw "Sentinel SHA-256 changed" }
if ($sentinelTimeAfter -ne $sentinelTimeBefore) { throw "Sentinel timestamp changed" }
$records = Read-LocalRecords
$matching = @($records | Where-Object {
    $_.package_name -eq $packageName -and $_.client -eq "claude-code"
})
$matching[0].install_path = $installPath
Write-LocalRecords $records
Invoke-Uninstall `
    -Arguments @("uninstall", $packageName, "--client", "claude-code", "--force", "--yes") `
    -ExpectedExitCode 0 -ExpectedStatus "uninstalled"
Assert-MatchingRecordRemoved
Assert-ServerCountUnchanged $countBeforeUnsafe
Assert-NoTransactionLeftovers
Write-Host "Section 14 PASSED: sentinel unchanged"

Write-Host "`n=== UNINSTALL ACCEPTANCE ALL PASSED ==="

$env:HOME = $originalHome
$env:USERPROFILE = $originalUserProfile
$env:TRUSTED_AGENT_HUB_API_URL = $originalApiUrl
$env:TRUSTED_AGENT_HUB_TOKEN = $originalToken
$env:NODE_EXTRA_CA_CERTS = $originalNodeExtraCaCerts
Set-Location $originalLocation

if ($null -ne $artifactProcess) {
    $runningArtifactProcess = Get-Process -Id $artifactProcess.Id -ErrorAction SilentlyContinue
    if ($null -ne $runningArtifactProcess) {
        $sameStartTime = $null -ne $artifactProcessStartTime -and `
            $runningArtifactProcess.StartTime -eq $artifactProcessStartTime
        if ($runningArtifactProcess.ProcessName -eq "node" -and $sameStartTime) {
            Stop-Process -Id $runningArtifactProcess.Id
        } else {
            Write-Warning "Refusing to stop process because identity changed"
        }
    }
}

if (Test-Path -LiteralPath $composeFile) {
    $cleanupSql = @'
BEGIN;
DELETE FROM install_records WHERE version_id = :'version_id';
DELETE FROM package_versions WHERE id = :'version_id' AND package_id = :'package_id';
DELETE FROM packages WHERE id = :'package_id' AND name = :'package_name';
COMMIT;
'@
    $cleanupSql | & docker compose -f $composeFile exec -T db `
        psql -U postgres -d trusted_agent_hub -v "ON_ERROR_STOP=1" `
        -v "version_id=$versionId" -v "package_id=$packageId" `
        -v "package_name=$packageName"
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Database cleanup failed; preserve IDs for manual cleanup"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$testUserId)) {
        $userCleanupSql = @'
DELETE FROM users WHERE id = :'user_id' AND email = :'email';
'@
        $userCleanupSql | & docker compose -f $composeFile exec -T db `
            psql -U postgres -d trusted_agent_hub -v "ON_ERROR_STOP=1" `
            -v "user_id=$testUserId" -v "email=$temporaryEmail"
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Temporary user cleanup failed: $testUserId"
        }
    }
}

function Remove-VerifiedAcceptancePath([string]$Candidate, [string]$ExpectedPrefix) {
    if ([string]::IsNullOrWhiteSpace($Candidate) -or `
        -not (Test-Path -LiteralPath $Candidate)) { return }
    $resolvedCandidate = [System.IO.Path]::GetFullPath($Candidate)
    $resolvedTemp = [System.IO.Path]::GetFullPath($env:TEMP)
    $tempPrefix = $resolvedTemp.TrimEnd('\') + '\'
    $leaf = Split-Path $resolvedCandidate -Leaf
    if ($resolvedCandidate.StartsWith(
        $tempPrefix, [System.StringComparison]::OrdinalIgnoreCase
    ) -and $leaf.StartsWith(
        $ExpectedPrefix, [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Remove-Item -LiteralPath $resolvedCandidate -Recurse -Force
    } else {
        Write-Warning "Refusing to remove unverified path: $resolvedCandidate"
    }
}

Remove-VerifiedAcceptancePath $isolatedHome "tah-uninstall-home-"
Remove-VerifiedAcceptancePath $fixtureRoot "tah-uninstall-fixture-"

$restoredNodeHome = (& node -e "console.log(require('os').homedir())").Trim()
Write-Host "Restored Node HOME: $restoredNodeHome"
