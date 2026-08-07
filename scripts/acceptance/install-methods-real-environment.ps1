# 多安装方式真实环境验收（Consumer 侧）
# 目标：对 npm_install / pip_install / docker_run / manual_steps 四种受管安装方式，
#       以及 copy_directory + MCP 配置写入、claude-code-plugin 插件安装
#       （安装到 ~/.claude/skills/ 后由 Claude Code 自动加载），
#       在隔离 HOME 中真实完成 tah install -> verify -> (update) -> uninstall 闭环。
#
# 前置：docker compose 三服务运行（api/db/web），API 健康；node/npm/python/docker 可用。
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
$fixtureRoot = Join-Path $env:TEMP "tah-install-methods-$runId"
$isolatedHome = Join-Path $env:TEMP "tah-methods-home-$runId"
$artifactProcess = $null
$artifactProcessStartTime = $null
$artifactPort = $null
$certificatePath = $null
$testToken = $null
$testUserId = $null

# ── 待验证包定义 ──
# Kind=copy: 需要 ZIP 制品 + HTTPS artifact server
# Kind=managed: 非 copy 安装方式，写入 ~/.trusted-agent-hub/installed/
$packages = @(
    @{ Name = "demo-npm-install";      SourceDir = "npm-install-demo";      Method = "npm_install";      Client = "claude-code";        Kind = "managed"; SourceType = "npm";          Type = "skill";     AssertRel = ".trusted-agent-hub\installed\demo-npm-install-npm\node_modules\is-number"; Update = $true },
    @{ Name = "demo-pip-install";      SourceDir = "pip-install-demo";      Method = "pip_install";      Client = "claude-code";        Kind = "managed"; SourceType = "pypi";         Type = "skill";     AssertRel = ".trusted-agent-hub\installed\demo-pip-install-pip\idna";                    Update = $false },
    @{ Name = "demo-docker-run";       SourceDir = "docker-run-demo";       Method = "docker_run";       Client = "claude-code";        Kind = "managed"; SourceType = "docker";       Type = "mcp_server"; AssertRel = ".trusted-agent-hub\installed\demo-docker-run-docker\docker-run.json"; Update = $false },
    @{ Name = "demo-mcp-config";       SourceDir = "mcp-config-demo";       Method = "copy_directory";   Client = "claude-code";        Kind = "copy";     SourceType = "local_upload"; Type = "mcp_server"; AssertRel = ".claude\skills\demo-mcp-config\server.py";             McpKey = "demo-mcp-config"; Update = $false },
    @{ Name = "demo-claude-plugin";    SourceDir = "claude-plugin-demo";    Method = "copy_directory";   Client = "claude-code-plugin"; Kind = "copy";     SourceType = "local_upload"; Type = "plugin";    AssertRel = ".claude\skills\demo-claude-plugin\.claude-plugin\plugin.json"; Update = $false },
    @{ Name = "demo-manual-steps";     SourceDir = "manual-steps-demo";     Method = "manual_steps";     Client = "claude-code";        Kind = "managed"; SourceType = "local_upload"; Type = "skill";     AssertRel = ".trusted-agent-hub\installed\demo-manual-steps-manual\steps.txt";        Update = $false }
)

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT FAILED: $Message" }
    Write-Host "  PASS: $Message"
}

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

function Invoke-Psql([string]$Sql) {
    $previousEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $Sql | & docker compose -f $composeFile exec -T db `
            psql -U postgres -d trusted_agent_hub -v "ON_ERROR_STOP=1" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "psql failed" }
    } finally {
        $ErrorActionPreference = $previousEap
    }
}

function Remove-VerifiedTempPath([string]$Candidate, [string]$Prefix) {
    if ([string]::IsNullOrWhiteSpace($Candidate) -or -not (Test-Path -LiteralPath $Candidate)) { return }
    $resolved = [System.IO.Path]::GetFullPath($Candidate)
    $tempPrefix = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd([char]92) + [char]92
    $leaf = Split-Path $resolved -Leaf
    if ($resolved.StartsWith($tempPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and $leaf.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    } else {
        Write-Warning "Refusing to remove unverified path: $resolved"
    }
}

Write-Host "=== 0. 前置检查 ==="
if (-not (Test-Path -LiteralPath $cliEntry -PathType Leaf)) {
    throw "CLI dist missing: $cliEntry (run: cd apps/cli && npm run build)"
}
$health = Invoke-RestMethod -Uri "$api/api/v0/health" -TimeoutSec 10
Assert-True ($health.status -eq "ok") "API health ok"
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null

Write-Host "=== 1. 构建 copy_directory 示例的 ZIP 制品 + HTTPS artifact server ==="
$copyPackages = @($packages | Where-Object { $_.Kind -eq "copy" })
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

foreach ($pkg in $copyPackages) {
    $sourcePath = Join-Path $codeWorktree "examples\$($pkg.SourceDir)"
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
        throw "Example source missing: $sourcePath"
    }
    $zipPath = Join-Path $fixtureRoot ($pkg.Name + ".zip")
    Compress-Archive -LiteralPath $sourcePath -DestinationPath $zipPath -Force
    $pkg.Sha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $pkg.Size = (Get-Item -LiteralPath $zipPath).Length
    $pkg.ZipName = $pkg.Name + ".zip"
    $pkg.RootName = Split-Path $sourcePath -Leaf
    Write-Host "  + $($pkg.Name) sha256=$($pkg.Sha256.Substring(0,12))... size=$($pkg.Size)"
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
foreach ($pkg in $copyPackages) { $args += $pkg.ZipName }
$artifactProcess = Start-Process -FilePath $nodeExe -ArgumentList $args -WindowStyle Hidden -PassThru
$artifactProcessStartTime = $artifactProcess.StartTime
$env:NODE_EXTRA_CA_CERTS = $certificatePath

$artifactReady = $false
1..20 | ForEach-Object {
    if (-not $artifactReady) {
        $previousEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $probe = @(& node -e "fetch(process.argv[1]).then(r=>r.arrayBuffer()).then(b=>console.log(b.byteLength)).catch(e=>process.exit(1))" "https://127.0.0.1:$artifactPort/$($copyPackages[0].ZipName)" 2>&1)
            $artifactReady = $LASTEXITCODE -eq 0 -and [long](($probe -join "").Trim()) -eq $copyPackages[0].Size
        } finally {
            $ErrorActionPreference = $previousEap
        }
        if (-not $artifactReady) { Start-Sleep -Milliseconds 500 }
    }
}
if (-not $artifactReady) { throw "HTTPS artifact server not ready" }
Write-Host "Artifact server ready on port $artifactPort"

Write-Host "=== 2. 写入 published 夹具（6 种安装方式） ==="
foreach ($pkg in $packages) {
    $packageId = "pkg-" + $pkg.Name.Replace("-", "")
    $versionId = "ver-" + $pkg.Name.Replace("-", "")
    $escaped = $pkg.Name.Replace("'", "''")

    if ($pkg.Kind -eq "copy") {
        $artifactUrl = "https://127.0.0.1:$artifactPort/$($pkg.ZipName)"
        # claude-code-plugin 与 claude-code 共用 skills 根目录：Claude Code
        # 会自动加载 ~/.claude/skills/<name>/ 下的插件（<name>@skills-dir）。
        $copyDestination = "~/.claude/skills/$($pkg.Name)/"
        $depsSql = "jsonb_build_object()"
        if ($pkg.McpKey) {
            $depsSql = "jsonb_build_object('mcp_servers', jsonb_build_array(jsonb_build_object('name', '$($pkg.McpKey)', 'command', 'python', 'args', jsonb_build_array('server.py'))))"
        }
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
  '$packageId', '$escaped', 'published', '1.0.0',
  jsonb_build_object('id', '$packageId', 'name', '$escaped', 'description', 'Install methods validation', 'type', '$($pkg.Type)', 'latest_version', '1.0.0', 'status', 'published', 'keywords', jsonb_build_array('validation'), 'compatibility', jsonb_build_array('$($pkg.Client)'), 'install_count', 0)::json
);
INSERT INTO package_versions (id, package_id, version, status, data)
VALUES (
  '$versionId', '$packageId', '1.0.0', 'published',
  jsonb_build_object(
    'id', '$versionId', 'package_id', '$packageId', 'version', '1.0.0', 'status', 'published',
    'source', jsonb_build_object('type', 'local_upload', 'repository_url', 'https://127.0.0.1:$artifactPort/', 'download_url', '$artifactUrl', 'ref', 'v1.0.0', 'commit_hash', '0000000000000000000000000000000000000000', 'verified_owner', true),
    'integrity', jsonb_build_object('sha256', '$($pkg.Sha256)', 'download_size_bytes', $($pkg.Size)),
    'compatibility', jsonb_build_array('$($pkg.Client)'),
    'permissions', jsonb_build_object('filesystem', jsonb_build_object('read', jsonb_build_array(), 'write', jsonb_build_array(), 'delete', false), 'shell', jsonb_build_object('allowed', false, 'commands', jsonb_build_array()), 'network', jsonb_build_object('allowed', false, 'domains', jsonb_build_array())),
    'installation', jsonb_build_object('method', 'copy_directory', 'target_client', '$($pkg.Client)', 'steps', jsonb_build_array(
      jsonb_build_object('action', 'download', 'url', '$artifactUrl'),
      jsonb_build_object('action', 'verify', 'algorithm', 'sha256', 'checksum', '$($pkg.Sha256)'),
      jsonb_build_object('action', 'extract', 'archive', '$($pkg.ZipName)'),
      jsonb_build_object('action', 'copy', 'source', '$($pkg.RootName)/', 'destination', '$copyDestination')
    )),
    'dependencies', $depsSql,
    'trust_score', jsonb_build_object('model_version', 'validation-v1', 'score', 95, 'risk_summary', jsonb_build_object('level', 'low', 'grade', 'A', 'top_risks', jsonb_build_array(), 'install_recommendation', 'safe'))
  )::json
);
COMMIT;
"@
    } else {
        $stepSql = ""
        switch ($pkg.Method) {
            "npm_install" {
                $stepSql = "jsonb_build_object('action', 'npm_install', 'package', 'is-number', 'version', '7.0.0', 'registry', 'https://registry.npmjs.org')"
            }
            "pip_install" {
                $stepSql = "jsonb_build_object('action', 'pip_install', 'package', 'idna', 'version', '3.7', 'index_url', 'https://pypi.org/simple')"
            }
            "docker_run" {
                $stepSql = "jsonb_build_object('action', 'docker_run', 'image', 'nginx', 'tag', 'alpine', 'ports', jsonb_build_array('8080:80'), 'volumes', jsonb_build_array(), 'env', jsonb_build_array('NGINX_HOST=localhost'))"
            }
            "manual_steps" {
                $stepSql = "jsonb_build_object('action', 'manual_steps', 'title', '$($pkg.Name)', 'text', 'Follow the package README and configure your client manually.')"
            }
        }
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
  '$packageId', '$escaped', 'published', '1.0.0',
  jsonb_build_object('id', '$packageId', 'name', '$escaped', 'description', 'Install methods validation', 'type', '$($pkg.Type)', 'latest_version', '1.0.0', 'status', 'published', 'keywords', jsonb_build_array('validation'), 'compatibility', jsonb_build_array('$($pkg.Client)'), 'install_count', 0)::json
);
INSERT INTO package_versions (id, package_id, version, status, data)
VALUES (
  '$versionId', '$packageId', '1.0.0', 'published',
  jsonb_build_object(
    'id', '$versionId', 'package_id', '$packageId', 'version', '1.0.0', 'status', 'published',
    'source', jsonb_build_object('type', '$($pkg.SourceType)', 'repository_url', 'https://github.com/hust-open-atom-club/trusted-agent-hub', 'download_url', NULL, 'ref', 'v1.0.0', 'commit_hash', NULL, 'verified_owner', true),
    'compatibility', jsonb_build_array('$($pkg.Client)'),
    'permissions', jsonb_build_object('filesystem', jsonb_build_object('read', jsonb_build_array(), 'write', jsonb_build_array(), 'delete', false), 'shell', jsonb_build_object('allowed', false, 'commands', jsonb_build_array()), 'network', jsonb_build_object('allowed', false, 'domains', jsonb_build_array())),
    'installation', jsonb_build_object('method', '$($pkg.Method)', 'target_client', '$($pkg.Client)', 'steps', jsonb_build_array($stepSql)),
    'trust_score', jsonb_build_object('model_version', 'validation-v1', 'score', 95, 'risk_summary', jsonb_build_object('level', 'low', 'grade', 'A', 'top_risks', jsonb_build_array(), 'install_recommendation', 'safe'))
  )::json
);
COMMIT;
"@
    }
    Invoke-Psql $sql
    Write-Host "  + fixture $($pkg.Name) ($($pkg.Method))"
}

Write-Host "=== 3. 注册临时用户 ==="
$username = "methods-e2e-$runId"
$password = "MethodsPw_$runId"
$registerBody = @{
    username = $username
    password = $password
    email = "$username@example.com"
    display_name = "Install methods validation"
} | ConvertTo-Json
$tokens = Invoke-RestMethod -Method Post -Uri "$api/api/v0/auth/register" `
    -ContentType "application/json" -Body $registerBody -TimeoutSec 10
$testUserId = [string]$tokens.user.id
$testToken = [string]$tokens.access_token
$env:TRUSTED_AGENT_HUB_TOKEN = $testToken
Write-Host "Registered $username"

Write-Host "=== 4. 隔离 HOME 中逐个 install / verify / (update) / uninstall ==="
New-Item -ItemType Directory -Path $isolatedHome | Out-Null
$env:HOME = $isolatedHome
$env:USERPROFILE = $isolatedHome
$env:TRUSTED_AGENT_HUB_API_URL = $api
$nodeHome = (& node -e "console.log(require('os').homedir())").Trim()
if ($nodeHome -ne $isolatedHome) { throw "HOME mismatch" }

$summary = @()
foreach ($pkg in $packages) {
    $assertPath = Join-Path $isolatedHome $pkg.AssertRel
    $install = Invoke-NodeCli -Arguments @("install", $pkg.Name, "--client", $pkg.Client, "--yes")
    $installed = $install.ExitCode -eq 0 -and (Test-Path -LiteralPath $assertPath)
    $verify = Invoke-NodeCli -Arguments @("verify", $pkg.Name, "--client", $pkg.Client)
    $verified = $verify.ExitCode -eq 0 -and $verify.Text -match "\[valid\]"

    $updated = "-"
    if ($pkg.Update -and $installed) {
        $updateVersionId = "ver-" + $pkg.Name.Replace("-", "") + "-101"
        $updateSql = @"
BEGIN;
DELETE FROM install_records WHERE version_id = '$updateVersionId';
DELETE FROM trust_levels WHERE version_id = '$updateVersionId';
DELETE FROM scan_reports WHERE version_id = '$updateVersionId';
DELETE FROM review_records WHERE version_id = '$updateVersionId';
DELETE FROM audit_logs WHERE target_id = '$updateVersionId' AND target_type = 'version';
DELETE FROM package_versions WHERE id = '$updateVersionId';
INSERT INTO package_versions (id, package_id, version, status, data)
VALUES (
  '$updateVersionId', 'pkg-$($pkg.Name.Replace('-',''))', '1.0.1', 'published',
  jsonb_build_object(
    'id', '$updateVersionId', 'package_id', 'pkg-$($pkg.Name.Replace('-',''))', 'version', '1.0.1', 'status', 'published',
    'source', jsonb_build_object('type', 'npm', 'repository_url', 'https://github.com/hust-open-atom-club/trusted-agent-hub', 'download_url', NULL, 'ref', 'v1.0.1', 'commit_hash', NULL, 'verified_owner', true),
    'compatibility', jsonb_build_array('$($pkg.Client)'),
    'permissions', jsonb_build_object('filesystem', jsonb_build_object('read', jsonb_build_array(), 'write', jsonb_build_array(), 'delete', false), 'shell', jsonb_build_object('allowed', false, 'commands', jsonb_build_array()), 'network', jsonb_build_object('allowed', false, 'domains', jsonb_build_array())),
    'installation', jsonb_build_object('method', 'npm_install', 'target_client', '$($pkg.Client)', 'steps', jsonb_build_array(jsonb_build_object('action', 'npm_install', 'package', 'is-number', 'version', '7.0.0', 'registry', 'https://registry.npmjs.org'))),
    'trust_score', jsonb_build_object('model_version', 'validation-v1', 'score', 95, 'risk_summary', jsonb_build_object('level', 'low', 'grade', 'A', 'top_risks', jsonb_build_array(), 'install_recommendation', 'safe'))
  )::json
);
UPDATE packages
SET latest_version = '1.0.1',
    data = jsonb_set(data::jsonb, '{latest_version}', '"1.0.1"')::json
WHERE id = 'pkg-$($pkg.Name.Replace('-',''))';
COMMIT;
"@
        Invoke-Psql $updateSql
        $update = Invoke-NodeCli -Arguments @("update", $pkg.Name, "--client", $pkg.Client, "--yes")
        $records = Get-Content (Join-Path $isolatedHome ".trusted-agent-hub\installs.json") -Raw | ConvertFrom-Json
        $record101 = @($records | Where-Object { $_.package_name -eq $pkg.Name -and $_.version -eq "1.0.1" })
        $updated = if ($update.ExitCode -eq 0 -and $record101.Count -ge 1) { "OK" } else { "FAIL" }
    }

    $uninstall = Invoke-NodeCli -Arguments @("uninstall", $pkg.Name, "--client", $pkg.Client, "--yes")
    $uninstalled = $uninstall.ExitCode -eq 0 -and (-not (Test-Path -LiteralPath $assertPath))
    if ($pkg.McpKey) {
        $claudeJsonPath = Join-Path $isolatedHome ".claude.json"
        if (Test-Path -LiteralPath $claudeJsonPath) {
            $claudeJson = Get-Content -LiteralPath $claudeJsonPath -Raw | ConvertFrom-Json
            $entryStillPresent = $null -ne $claudeJson.mcpServers.PSObject.Properties[$pkg.McpKey]
            if ($entryStillPresent) { $uninstalled = $false }
        }
    }

    $summary += [pscustomobject]@{
        Package = $pkg.Name
        Method = $pkg.Method
        Install = if ($installed) { "OK" } else { "FAIL" }
        Verify = if ($verified) { "OK" } else { "FAIL" }
        Update = $updated
        Uninstall = if ($uninstalled) { "OK" } else { "FAIL" }
    }
    Write-Host "  $($pkg.Name): install=$installed verify=$verified update=$updated uninstall=$uninstalled"
}

$summary | Format-Table -AutoSize
$failed = @($summary | Where-Object {
    $_.Install -ne "OK" -or $_.Verify -ne "OK" -or $_.Uninstall -ne "OK" -or $_.Update -eq "FAIL"
})
if ($failed.Count -gt 0) {
    throw "Validation failed for: $($failed.Package -join ', ')"
}
Write-Host "`n=== INSTALL METHODS REAL ENVIRONMENT ALL PASSED ==="

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
    "DELETE FROM install_records WHERE version_id = '${versionId}-101';"
    "DELETE FROM package_versions WHERE id = '${versionId}-101' AND package_id = '$packageId';"
    "DELETE FROM package_versions WHERE id = '$versionId' AND package_id = '$packageId';"
    "DELETE FROM packages WHERE id = '$packageId' AND name = '$($pkg.Name)';"
})
COMMIT;
"@
try { Invoke-Psql $cleanupSql } catch { Write-Warning "Fixture cleanup failed: $($_.Exception.Message)" }

if (-not [string]::IsNullOrWhiteSpace($testUserId)) {
    $userSql = "DELETE FROM users WHERE id = '$testUserId' AND email = '$username@example.com';"
    try { Invoke-Psql $userSql } catch { Write-Warning "User cleanup failed: $($_.Exception.Message)" }
}

Remove-VerifiedTempPath $isolatedHome "tah-methods-home-"
Remove-VerifiedTempPath $fixtureRoot "tah-install-methods-"
Write-Host "Restored Node HOME: $(& node -e "console.log(require('os').homedir())")"
