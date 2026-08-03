# TrustedAgentHub 全链路 E2E 演示脚本
# 主线: submit -> scan -> review -> publish -> consumer API/Web -> CLI install -> verify -> yank -> audit
#
# 说明:
#   - 扫描阶段: 在 API 容器内用真实 RiskScanner 扫描本地示例包，并调用真实评分引擎
#     rate() 生成 scan_report + trust_score；随后按 test_review_integration 的机制
#     将扫描产物注入数据库，模拟 handle_scan_complete（避免依赖 github.com 网络）。
#   - 其余全部走真实链路: 注册/建包/建版本为 HTTP API；审核、发布、下架、审计查询
#     为 HTTP API；安装/校验为真实 CLI（隔离 HOME + 本地 HTTPS artifact 服务）。
#
# 前置: docker compose 三服务已启动 (api/db/web)，API 健康。
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
$packageName = "e2e-demo-$runId"
$packageId = $null
$versionId = $null
$demoSource = Join-Path $codeWorktree "examples\skills\demo-summarization"
$fixtureRoot = Join-Path $env:TEMP "tah-e2e-fixture-$runId"
$isolatedHome = Join-Path $env:TEMP "tah-e2e-home-$runId"
$reportJsonPath = Join-Path $fixtureRoot "full-report.json"
$artifactProcess = $null
$artifactProcessStartTime = $null
$artifactPort = $null
$artifactUrl = $null
$artifactSha256 = $null
$artifactSize = $null
$certificatePath = $null
$privateKeyPath = $null
$scanReport = $null
$trustScore = $null

$submitterToken = $null
$submitterId = $null
$reviewerToken = $null
$reviewerId = $null
$adminToken = $null
$adminId = $null

$installPath = Join-Path $isolatedHome ".claude\skills\$packageName"
$recordPath = Join-Path $isolatedHome ".trusted-agent-hub\installs.json"

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

function Invoke-Api([string]$Method, [string]$Path, [object]$Body = $null, [string]$Token = "") {
    $headers = @{}
    if ($Token) { $headers["Authorization"] = "Bearer $Token" }
    $params = @{
        Method = $Method
        Uri = "$api$Path"
        Headers = $headers
        TimeoutSec = 30
    }
    if ($null -ne $Body) {
        $params.ContentType = "application/json"
        $params.Body = ($Body | ConvertTo-Json -Depth 30)
    }
    try {
        $response = Invoke-RestMethod @params
        [pscustomobject]@{ Ok = $true; Status = 200; Data = $response }
    } catch {
        $statusCode = 0
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        [pscustomobject]@{ Ok = $false; Status = $statusCode; Data = $null }
    }
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
if (-not (Test-Path -LiteralPath $demoSource -PathType Container)) {
    throw "Demo source missing: $demoSource"
}
$health = Invoke-RestMethod -Uri "$api/api/v0/health" -TimeoutSec 10
Assert-True ($health.status -eq "ok") "API health ok"
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null

Write-Host "=== 1. 真实扫描 + 真实评分 (API 容器内执行) ==="
$pyScan = @'
import contextlib, io, json
from scanners.risk_scanner.scanner import RiskScanner
from src.routers.trust import _build_package_metadata, _load_scorer

target = "/examples/skills/demo-summarization"
repo_url = "https://github.com/hust-open-atom-club/trusted-agent-hub/tree/main/examples/skills/demo-summarization"
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    report = RiskScanner(target).scan()
    meta = _build_package_metadata(report, target, repo_url=repo_url)
    trust = _load_scorer()(package_metadata=meta, scan_report=report)
out = {"scan_report": report, "trust_score": trust, "package_metadata": meta}
print(json.dumps(out, ensure_ascii=False))
'@
$previousEap = $ErrorActionPreference
$scanAll = @()
try {
    $ErrorActionPreference = "Continue"
    $scanAll = @($pyScan | & docker compose -f $composeFile exec -T api python - 2>&1)
    $scanExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousEap
}
if ($scanExitCode -ne 0) {
    $scanErrors = @($scanAll | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
    throw "Real scan/scoring failed inside API container: $($scanErrors -join ' | ')"
}
$scanLines = @($scanAll | Where-Object { $_ -is [string] })
$fullReportJson = ($scanLines -join "`n")
$fullReport = $fullReportJson | ConvertFrom-Json
$scanReport = $fullReport.scan_report
$trustScore = $fullReport.trust_score
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($reportJsonPath, $fullReportJson + "`n", $utf8NoBom)
$grade = [string]$trustScore.risk_summary.grade
$score = [string]$trustScore.score
Write-Host "  scan findings=$($scanReport.summary.total) grade=$grade score=$score"
Assert-True ($grade -ne "E") "auto grade is not blocked (E)"

Write-Host "=== 2. 构建 artifact zip + HTTPS artifact server ==="
$zipName = "$packageName-1.0.0-aaaaaaaa.zip"
$zipPath = Join-Path $fixtureRoot $zipName
Compress-Archive -LiteralPath $demoSource -DestinationPath $zipPath -Force
$artifactSha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$artifactSize = (Get-Item -LiteralPath $zipPath).Length
$rootName = Split-Path $demoSource -Leaf
Write-Host "  zip=$zipName sha256=$($artifactSha256.Substring(0,12))... size=$artifactSize root=$rootName"

$portProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$portProbe.Start()
$artifactPort = ([System.Net.IPEndPoint]$portProbe.LocalEndpoint).Port
$portProbe.Stop()

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

$serverScriptPath = Join-Path $fixtureRoot "https-server.js"
$serverScript = @'
const https = require('https');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname);
const port = Number(process.argv[2]);
const name = process.argv[3];
const server = https.createServer(
  { cert: fs.readFileSync(path.join(root, 'localhost-cert.pem')), key: fs.readFileSync(path.join(root, 'localhost-key.pem')) },
  (req, res) => {
    const pathname = new URL(req.url, 'https://127.0.0.1').pathname.slice(1);
    if (req.method !== 'GET' || pathname !== name) { res.writeHead(404); res.end('not found'); return; }
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
$artifactProcess = Start-Process -FilePath $nodeExe `
    -ArgumentList @($serverScriptPath, [string]$artifactPort, $zipName) `
    -WindowStyle Hidden -PassThru
$artifactProcessStartTime = $artifactProcess.StartTime
$env:NODE_EXTRA_CA_CERTS = $certificatePath
$artifactUrl = "https://127.0.0.1:$artifactPort/$zipName"

$artifactReady = $false
1..20 | ForEach-Object {
    if (-not $artifactReady) {
        $previousEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $probe = @(& node -e "fetch(process.argv[1]).then(r=>r.arrayBuffer()).then(b=>console.log(b.byteLength)).catch(e=>process.exit(1))" $artifactUrl 2>&1)
            $artifactReady = $LASTEXITCODE -eq 0 -and [long](($probe -join "").Trim()) -eq $artifactSize
        } finally {
            $ErrorActionPreference = $previousEap
        }
        if (-not $artifactReady) { Start-Sleep -Milliseconds 500 }
    }
}
if (-not $artifactReady) { throw "HTTPS artifact server not ready" }
Write-Host "  artifact server ready: $artifactUrl"

Write-Host "=== 3. 注册临时用户 (submitter / reviewer / admin) ==="
function Register-User([string]$Prefix) {
    $username = "$Prefix-$runId"
    $password = "E2ePw_$runId"
    $email = "$username@example.com"
    $body = @{ email = $email; password = $password; display_name = $Prefix } | ConvertTo-Json
    $resp = Invoke-RestMethod -Method Post -Uri "$api/api/v0/auth/register" `
        -ContentType "application/json" -Body $body -TimeoutSec 10
    [pscustomobject]@{
        Id = [string]$resp.user.id
        Email = $email
        Password = $password
        Token = [string]$resp.access_token
    }
}
function Elevate-Role([string]$Email, [string]$Role) {
    $sql = "UPDATE users SET role = '$Role' WHERE email = '$Email';"
    Invoke-Psql $sql
}
function Login-User([string]$Email, [string]$Password) {
    $body = @{ email = $Email; password = $Password } | ConvertTo-Json
    $resp = Invoke-RestMethod -Method Post -Uri "$api/api/v0/auth/login" `
        -ContentType "application/json" -Body $body -TimeoutSec 10
    [string]$resp.access_token
}

$submitter = Register-User "e2e-submitter"
$reviewer = Register-User "e2e-reviewer"
$admin = Register-User "e2e-admin"
Elevate-Role $reviewer.Email "reviewer"
Elevate-Role $admin.Email "admin"
$submitterId = $submitter.Id
$submitterToken = $submitter.Token
$reviewerId = $reviewer.Id
$reviewerToken = Login-User $reviewer.Email $reviewer.Password
$adminId = $admin.Id
$adminToken = Login-User $admin.Email $admin.Password
Write-Host "  users registered: $submitterId / $reviewerId / $adminId"

Write-Host "=== 4. Producer API: 创建包 + 创建版本 ==="
$pkgBody = @{
    name = $packageName
    type = "skill"
    description = "E2E demo package (submit-to-install full chain)"
    license = "MIT"
    keywords = @("e2e", "demo")
    compatibility = @("claude-code")
}
$pkgResp = Invoke-Api "Post" "/api/v0/producer/packages" $pkgBody $submitterToken
Assert-True ($pkgResp.Ok -and -not [string]::IsNullOrWhiteSpace([string]$pkgResp.Data.id)) "create package ok"
$packageId = [string]$pkgResp.Data.id
Write-Host "  packageId=$packageId"

$verBody = @{
    version = "1.0.0"
    repo_url = "https://github.com/hust-open-atom-club/trusted-agent-hub/tree/main/examples/skills/demo-summarization"
    compatibility = @("claude-code")
}
$verResp = Invoke-Api "Post" "/api/v0/producer/packages/$packageId/versions" $verBody $submitterToken
Assert-True ($verResp.Ok -and -not [string]::IsNullOrWhiteSpace([string]$verResp.Data.id)) "create version ok"
$versionId = [string]$verResp.Data.id
Write-Host "  versionId=$versionId"

Write-Host "=== 5. 注入扫描产物 (模拟 handle_scan_complete) ==="
$commitHash = "a" * 40
$trustScoreJson = $trustScore | ConvertTo-Json -Depth 30
$trustScoreObj = $trustScoreJson | ConvertFrom-Json
$installData = [ordered]@{
    id = $versionId
    package_id = $packageId
    name = $packageName
    version = "1.0.0"
    status = "pending_review"
    type = "skill"
    description = "E2E demo package (submit-to-install full chain)"
    source = [ordered]@{
        type = "local_upload"
        repository_url = "https://github.com/hust-open-atom-club/trusted-agent-hub/tree/main/examples/skills/demo-summarization"
        download_url = $artifactUrl
        ref = "v1.0.0"
        commit_hash = $commitHash
    }
    integrity = [ordered]@{
        sha256 = $artifactSha256
        download_size_bytes = $artifactSize
    }
    compatibility = @("claude-code")
    permissions = [ordered]@{
        filesystem = [ordered]@{ read = @(); write = @(); delete = $false }
        shell = [ordered]@{ allowed = $false; commands = @() }
        network = [ordered]@{ allowed = $false; domains = @() }
    }
    installation = [ordered]@{
        method = "copy_directory"
        target_client = "claude-code"
        steps = @(
            [ordered]@{ action = "download"; url = $artifactUrl },
            [ordered]@{ action = "verify"; algorithm = "sha256"; checksum = $artifactSha256 },
            [ordered]@{ action = "extract"; archive = $zipName },
            [ordered]@{ action = "copy"; source = "$rootName/"; destination = "~/.claude/skills/$packageName/" }
        )
    }
    trust_score = $trustScoreObj
}
$installJson = $installData | ConvertTo-Json -Depth 30
$scanJsonEscaped = ($fullReportJson).Replace("'", "''")
$installJsonEscaped = $installJson.Replace("'", "''")

$injectSql = @"
BEGIN;
INSERT INTO scan_reports (version_id, scan_json, report_path, scanned_at)
VALUES ('$versionId', '$scanJsonEscaped'::jsonb, 'acceptance/e2e/full-report.json', now())
ON CONFLICT (version_id) DO UPDATE SET scan_json = EXCLUDED.scan_json, report_path = EXCLUDED.report_path, scanned_at = now();
UPDATE package_versions
SET status = 'pending_review', data = '$installJsonEscaped'::jsonb
WHERE id = '$versionId' AND package_id = '$packageId';
INSERT INTO audit_logs (id, action, target_type, target_id, operator_id, detail, timestamp)
VALUES ('audit-e2e-$runId-submit', 'submit', 'version', '$versionId', '$submitterId',
        jsonb_build_object('note', 'E2E: scan report generated by real local scanner, injected as handle_scan_complete'), now());
COMMIT;
"@
Invoke-Psql $injectSql
Write-Host "  injected scan_report + install manifest data + submit audit log"

$versionDetail = Invoke-Api "Get" "/api/v0/producer/versions/$versionId" $null $submitterToken
Assert-True ($versionDetail.Ok -and $versionDetail.Data.status -eq "pending_review") "version status pending_review"

Write-Host "=== 6. Reviewer 审核通过 ==="
$reviewResp = Invoke-Api "Post" "/api/v0/producer/versions/$versionId/reviews" `
    @{ conclusion = "approved"; comment = "E2E auto-approved" } $reviewerToken
Assert-True ($reviewResp.Ok -and $reviewResp.Data.new_status -eq "approved") "review approved"

Write-Host "=== 7. Admin 发布 ==="
$publishResp = Invoke-Api "Post" "/api/v0/producer/versions/$versionId/publish" $null $adminToken
Assert-True ($publishResp.Ok -and $publishResp.Data.new_status -eq "published") "publish -> published"

Write-Host "=== 8. Consumer 视角 (Web/API 数据源) ==="
$pubDetail = Invoke-Api "Get" "/api/v0/packages/$packageName"
Assert-True ($pubDetail.Ok -and $pubDetail.Data.status -eq "published") "consumer package detail published"
Assert-True (-not [string]::IsNullOrWhiteSpace([string]$pubDetail.Data.grade)) "package grade populated"
$trustHistory = Invoke-Api "Get" "/api/v0/packages/$packageName/trust-history"
Assert-True ($trustHistory.Ok -and @($trustHistory.Data).Count -ge 1) "trust-history endpoint returns points"
$manifest = Invoke-Api "Get" "/api/v0/packages/$packageName/install-manifest?client=claude-code"
Assert-True ($manifest.Ok -and $manifest.Data.name -eq $packageName) "install-manifest available"
Write-Host "  published grade=$($pubDetail.Data.grade)"

Write-Host "=== 9. CLI: tah install -> tah verify (隔离 HOME) ==="
New-Item -ItemType Directory -Path $isolatedHome | Out-Null
$env:HOME = $isolatedHome
$env:USERPROFILE = $isolatedHome
$env:TRUSTED_AGENT_HUB_API_URL = $api
$env:TRUSTED_AGENT_HUB_TOKEN = $submitterToken
$nodeHome = (& node -e "console.log(require('os').homedir())").Trim()
Assert-True ($nodeHome -eq $isolatedHome) "node HOME points to isolated home"

$install = Invoke-NodeCli -Arguments @("install", $packageName, "--client", "claude-code", "--yes")
$installed = $install.ExitCode -eq 0 -and (Test-Path -LiteralPath $installPath -PathType Container)
Assert-True $installed "tah install exits 0 and skill directory exists"
$verify = Invoke-NodeCli -Arguments @("verify", $packageName, "--client", "claude-code")
$verified = $verify.ExitCode -eq 0 -and $verify.Text -match "\[valid\]"
Assert-True $verified "tah verify reports [valid]"
Assert-True (Test-Path -LiteralPath $recordPath) "local install record written"

Write-Host "=== 10. Admin 下架 (yank) ==="
$yankResp = Invoke-Api "Post" "/api/v0/producer/versions/$versionId/yank?reason=e2e-demo-complete" $null $adminToken
Assert-True ($yankResp.Ok -and $yankResp.Data.new_status -eq "yanked") "yank -> yanked"

Write-Host "=== 11. 下架后验证: 消费者不可见 + 审计链完整 ==="
$hiddenDetail = Invoke-Api "Get" "/api/v0/packages/$packageName"
Assert-True (-not $hiddenDetail.Ok -and $hiddenDetail.Status -eq 404) "consumer detail 404 after yank"
$hiddenManifest = Invoke-Api "Get" "/api/v0/packages/$packageName/install-manifest?client=claude-code"
Assert-True (-not $hiddenManifest.Ok -and $hiddenManifest.Status -eq 404) "install-manifest 404 after yank"
$audit = Invoke-Api "Get" "/api/v0/producer/audit-logs?target_id=$versionId&target_type=version" $null $adminToken
Assert-True $audit.Ok "audit log query ok"
$actions = @($audit.Data | ForEach-Object { [string]$_.action })
Write-Host "  audit actions: $($actions -join ', ')"
Assert-True ($actions -contains "submit") "audit contains submit"
Assert-True ($actions -contains "approve") "audit contains approve"
Assert-True ($actions -contains "publish") "audit contains publish"
Assert-True ($actions -contains "yank") "audit contains yank"

Write-Host "`n=== SUBMIT-TO-INSTALL E2E ALL PASSED ==="

# ---- 恢复与清理 ----
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

if (-not [string]::IsNullOrWhiteSpace($versionId)) {
    $cleanupSql = @"
BEGIN;
DELETE FROM scan_reports WHERE version_id = '$versionId';
DELETE FROM review_records WHERE version_id = '$versionId';
DELETE FROM audit_logs WHERE target_id = '$versionId' AND target_type = 'version';
DELETE FROM install_records WHERE version_id = '$versionId';
DELETE FROM trust_levels WHERE version_id = '$versionId';
DELETE FROM package_versions WHERE id = '$versionId' AND package_id = '$packageId';
DELETE FROM packages WHERE id = '$packageId' AND name = '$packageName';
DELETE FROM users WHERE id IN ('$submitterId', '$reviewerId', '$adminId');
COMMIT;
"@
    Invoke-Psql $cleanupSql
    Write-Host "Database cleanup complete"
}

Remove-VerifiedTempPath $isolatedHome "tah-e2e-home-"
Remove-VerifiedTempPath $fixtureRoot "tah-e2e-fixture-"
Write-Host "E2E cleanup complete"
