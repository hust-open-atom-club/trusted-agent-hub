<#
.SYNOPSIS
清理不可安装数据，并向数据库 seed 一批"真实世界"的持久可安装包。

.DESCRIPTION
1. 备份式安全删除：删除所有状态不是 published 的包，以及 published 但
   install-manifest 校验不通过（409）的包；保留可安装的包。
2. 将 examples/ 下的示例包打包为 ZIP 放入 API 的 artifacts 卷
   （/api/v0/artifacts/*.zip，容器重启后仍有效），并插入完整 published 夹具：
   - copy_directory：code-review-skill / summarization-skill / test-generation-skill
     / filesystem-mcp / sql-explorer-mcp / dev-toolkit-plugin
   - copy_directory + MCP 配置：mcp-config-demo
   - claude-code-plugin 目标：claude-plugin-demo
   - 真实外部包：npm-install-demo（is-number@7.0.0）、pip-install-demo（six==1.16.0）、
     docker-run-demo（alpine:3.20）、manual-steps-demo
3. 验证所有 published 包的 install-manifest 返回 200。

前置：docker compose 三服务运行（db/api/web），API 健康。
#>

param(
    [string]$RepoRoot = "D:\Github\Documents\GitHub\trusted-agent-hub"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$api = "http://127.0.0.1:8000"
$composeFile = Join-Path $RepoRoot "docker-compose.yml"
$tmpRoot = Join-Path $env:TEMP "tah-seed-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null

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

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT FAILED: $Message" }
    Write-Host "  [PASS] $Message"
}

function Get-PsqlRows([string]$Sql) {
    $previousEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $rows = @(
            $Sql | & docker compose -f $composeFile exec -T db `
                psql -U postgres -d trusted_agent_hub -tAc $Sql 2>&1 |
                Where-Object { $_ -is [string] }
        )
    } finally {
        $ErrorActionPreference = $previousEap
    }
    return $rows
}

Write-Host "=== 0. 前置检查 ==="
$health = Invoke-RestMethod -Uri "$api/api/v0/health" -TimeoutSec 10
Assert-True ($health.status -eq "ok") "API health ok"
$gitHash = (& git -C $RepoRoot rev-parse HEAD).Trim()
Write-Host "  source commit: $gitHash"

Write-Host "=== 1. 删除不可安装的数据 ==="
# 规则：保留 install-manifest 返回 200 的包；删除其余全部包（含非 published
# 状态与 published 但资料不完整 409 的包）。
$keepNames = @()
$allNames = @(Get-PsqlRows "SELECT name FROM packages ORDER BY name;")
foreach ($n in $allNames) {
    $n = $n.Trim()
    if (-not $n) { continue }
    try {
        $r = Invoke-WebRequest -Uri "$api/api/v0/packages/$([uri]::EscapeDataString($n))/install-manifest?client=claude-code" -UseBasicParsing -TimeoutSec 10
        if ($r.StatusCode -eq 200) { $keepNames += $n }
    } catch { }
}
Write-Host "  保留可安装包: $($keepNames -join ', ')"

$keepList = @($keepNames | ForEach-Object { "'$($_ -replace "'", "''")'" }) -join ", "
if ([string]::IsNullOrWhiteSpace($keepList)) { $keepList = "''" }
$cleanupSql = @"
BEGIN;
DELETE FROM install_records
WHERE version_id IN (SELECT id FROM package_versions WHERE package_id IN (SELECT id FROM packages WHERE name NOT IN ($keepList)));
DELETE FROM trust_levels
WHERE version_id IN (SELECT id FROM package_versions WHERE package_id IN (SELECT id FROM packages WHERE name NOT IN ($keepList)));
DELETE FROM scan_reports
WHERE version_id IN (SELECT id FROM package_versions WHERE package_id IN (SELECT id FROM packages WHERE name NOT IN ($keepList)));
DELETE FROM review_records
WHERE version_id IN (SELECT id FROM package_versions WHERE package_id IN (SELECT id FROM packages WHERE name NOT IN ($keepList)));
DELETE FROM audit_logs
WHERE target_id IN (SELECT id FROM package_versions WHERE package_id IN (SELECT id FROM packages WHERE name NOT IN ($keepList)));
DELETE FROM feedback_records
WHERE package_id IN (SELECT id FROM packages WHERE name NOT IN ($keepList));
DELETE FROM package_versions
WHERE package_id IN (SELECT id FROM packages WHERE name NOT IN ($keepList));
DELETE FROM packages WHERE name NOT IN ($keepList);
COMMIT;
"@
Invoke-Psql $cleanupSql
Write-Host "  清理完成，保留 $($keepNames.Count) 个可安装包"

Write-Host "=== 2. 构建 ZIP 制品并放入 artifacts 卷 ==="
$copyPackages = @(
    @{ Name = "code-review-skill";      SourceDir = "skills\demo-code-review";        Type = "skill";      Grade = "A"; Client = "claude-code" },
    @{ Name = "summarization-skill";    SourceDir = "skills\demo-summarization";      Type = "skill";      Grade = "A"; Client = "claude-code" },
    @{ Name = "test-generation-skill";  SourceDir = "skills\demo-test-generation";    Type = "skill";      Grade = "A"; Client = "claude-code" },
    @{ Name = "filesystem-mcp";         SourceDir = "mcp-servers\demo-filesystem";    Type = "mcp_server"; Grade = "B"; Client = "claude-code" },
    @{ Name = "sql-explorer-mcp";       SourceDir = "mcp-servers\demo-sql-explorer";  Type = "mcp_server"; Grade = "A"; Client = "claude-code" },
    @{ Name = "dev-toolkit-plugin";     SourceDir = "plugins\demo-dev-toolkit";       Type = "plugin";     Grade = "A"; Client = "claude-code" },
    @{ Name = "mcp-config-demo";        SourceDir = "mcp-config-demo";                Type = "mcp_server"; Grade = "B"; Client = "claude-code" },
    @{ Name = "claude-plugin-demo";     SourceDir = "claude-plugin-demo";             Type = "plugin";     Grade = "B"; Client = "claude-code-plugin" }
)

$seeds = @()
foreach ($pkg in $copyPackages) {
    $sourcePath = Join-Path $RepoRoot "examples\$($pkg.SourceDir)"
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
        throw "Example source missing: $sourcePath"
    }
    $zipPath = Join-Path $tmpRoot "$($pkg.Name).zip"
    Compress-Archive -LiteralPath $sourcePath -DestinationPath $zipPath -Force
    $sha = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $zipPath).Length
    $zipName = "$($pkg.Name).zip"
    $previousEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & docker compose -f $composeFile cp "$zipPath" "api:/artifacts/$zipName" 2>&1 | Out-Null
        $cpExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEap
    }
    if ($cpExit -ne 0) {
        # 兼容 cp 语法：docker cp 源 容器:目标
        $cid = (& docker compose -f $composeFile ps -q api).Trim()
        $previousEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            & docker cp "$zipPath" "${cid}:/artifacts/$zipName" 2>&1 | Out-Null
            $cpExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousEap
        }
        if ($cpExit -ne 0) { throw "Failed to copy $zipName into api artifacts" }
    }
    $rootName = Split-Path $sourcePath -Leaf
    $seeds += [pscustomobject]@{
        Name = $pkg.Name; Type = $pkg.Type; Grade = $pkg.Grade; Client = $pkg.Client
        Method = "copy_directory"; ZipName = $zipName; Sha256 = $sha; Size = $size; RootName = $rootName
        Mcp = if ($pkg.Name -eq "mcp-config-demo") { $true } else { $false }
    }
    Write-Host "  + $($pkg.Name) sha256=$($sha.Substring(0,12))… size=$size"
}

# 真实外部包（无需 ZIP 制品）
$seeds += [pscustomobject]@{ Name = "npm-install-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Method = "npm_install"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; Mcp = $false }
$seeds += [pscustomobject]@{ Name = "pip-install-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Method = "pip_install"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; Mcp = $false }
$seeds += [pscustomobject]@{ Name = "docker-run-demo"; Type = "mcp_server"; Grade = "B"; Client = "claude-code"; Method = "docker_run"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; Mcp = $false }
$seeds += [pscustomobject]@{ Name = "manual-steps-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Method = "manual_steps"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; Mcp = $false }

Write-Host "=== 3. 插入 published 夹具 ==="
foreach ($pkg in $seeds) {
    $packageId = "pkg-" + $pkg.Name.Replace("-", "")
    $versionId = "ver-" + $pkg.Name.Replace("-", "")
    $repoUrl = "https://github.com/hust-open-atom-club/trusted-agent-hub/tree/main/examples"
    $compat = if ($pkg.Client -eq "claude-code-plugin") { "claude-code-plugin" } else { "claude-code" }

    if ($pkg.Method -eq "copy_directory") {
        $sourceJson = "jsonb_build_object('type','local_upload','repository_url','$repoUrl','download_url','http://127.0.0.1:8000/api/v0/artifacts/$($pkg.ZipName)','ref','main','commit_hash','$gitHash','verified_owner',true)"
        $integrityJson = "jsonb_build_object('sha256','$($pkg.Sha256)','download_size_bytes',$($pkg.Size))"
        $stepsJson = "jsonb_build_array(
            jsonb_build_object('action','download','url','http://127.0.0.1:8000/api/v0/artifacts/$($pkg.ZipName)'),
            jsonb_build_object('action','verify','algorithm','sha256','checksum','$($pkg.Sha256)'),
            jsonb_build_object('action','extract','archive','$($pkg.ZipName)'),
            jsonb_build_object('action','copy','source','$($pkg.RootName)/','destination','~/.claude/skills/$($pkg.Name)/')
        )"
        if ($pkg.Client -eq "claude-code-plugin") {
            $stepsJson = $stepsJson.Replace("~/.claude/skills/", "~/.claude/plugins/")
        }
        $mcpJson = if ($pkg.Mcp) {
            "jsonb_build_array(jsonb_build_object('name','$($pkg.Name)','command','node','args',jsonb_build_array('server.py'),'env',jsonb_build_object('LOG_LEVEL','info')))"
        } else {
            "null"
        }
    } elseif ($pkg.Method -eq "npm_install") {
        $sourceJson = "jsonb_build_object('type','npm','repository_url','https://github.com/jonschlinkert/is-number','ref','main')"
        $integrityJson = "null"
        $stepsJson = "jsonb_build_array(jsonb_build_object('action','npm_install','package','is-number','version','7.0.0','registry','https://registry.npmjs.org/'))"
        $mcpJson = "null"
    } elseif ($pkg.Method -eq "pip_install") {
        $sourceJson = "jsonb_build_object('type','pypi','repository_url','https://github.com/benjaminp/six','ref','main')"
        $integrityJson = "null"
        $stepsJson = "jsonb_build_array(jsonb_build_object('action','pip_install','package','six','version','1.16.0','index_url','https://pypi.org/simple'))"
        $mcpJson = "null"
    } elseif ($pkg.Method -eq "docker_run") {
        $sourceJson = "jsonb_build_object('type','docker','repository_url','https://github.com/alpinelinux/docker-alpine','ref','main')"
        $integrityJson = "null"
        $stepsJson = "jsonb_build_array(jsonb_build_object('action','docker_run','image','alpine','tag','3.20','ports',jsonb_build_array(),'volumes',jsonb_build_array(),'env',jsonb_build_array()))"
        $mcpJson = "null"
    } else { # manual_steps
        $sourceJson = "jsonb_build_object('type','local_upload','repository_url','$repoUrl','ref','main')"
        $integrityJson = "null"
        $stepsJson = "jsonb_build_array(jsonb_build_object('action','manual_steps','title','$($pkg.Name)','text','1. 下载安装包`n2. 按 README 手动配置'))"
        $mcpJson = "null"
    }

    $level = if ($pkg.Grade -eq "A") { "low_risk" } else { "medium_risk" }
    $rec = if ($pkg.Grade -eq "A") { "safe" } else { "review_recommended" }
    $score = if ($pkg.Grade -eq "A") { 92 } else { 72 }
    $desc = switch ($pkg.Name) {
        "code-review-skill" { "AI 代码审查助手：分析 diff、识别问题并给出修复建议。" }
        "summarization-skill" { "文档摘要 Skill：为长文生成结构化摘要。" }
        "test-generation-skill" { "测试生成 Skill：根据源码生成单元测试用例。" }
        "filesystem-mcp" { "文件系统只读 MCP Server：安全访问指定目录。" }
        "sql-explorer-mcp" { "PostgreSQL 只读查询 MCP Server。" }
        "dev-toolkit-plugin" { "开发者工具箱 Plugin：git 命令、代码审查与分支管理。" }
        "mcp-config-demo" { "MCP 配置演示包：安装时写入客户端 mcpServers 配置。" }
        "claude-plugin-demo" { "Claude Code 插件示例：安装到 ~/.claude/plugins/。" }
        "npm-install-demo" { "npm 安装演示：真实安装 is-number@7.0.0 到受管目录。" }
        "pip-install-demo" { "pip 安装演示：真实安装 six==1.16.0 到受管目录。" }
        "docker-run-demo" { "Docker 安装演示：拉取 alpine:3.20 并生成运行配置。" }
        "manual-steps-demo" { "人工步骤安装演示：按说明手动安装。" }
        default { "示例能力包" }
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
  '$packageId', '$($pkg.Name)', 'published', '1.0.0',
  jsonb_build_object(
    'id', '$packageId', 'name', '$($pkg.Name)', 'description', '$desc',
    'type', '$($pkg.Type)', 'license', 'MIT', 'keywords', jsonb_build_array('seed','example'),
    'category', 'seed', 'homepage', '$repoUrl', 'status', 'published',
    'latest_version', '1.0.0', 'compatibility', jsonb_build_array('$compat'),
    'install_count', 0, 'grade', '$($pkg.Grade)', 'risk_level', '$level',
    'avg_rating', null, 'created_at', now(), 'updated_at', now()
  )::json
);
INSERT INTO package_versions (id, package_id, version, status, data)
VALUES (
  '$versionId', '$packageId', '1.0.0', 'published',
  jsonb_build_object(
    'id', '$versionId', 'package_id', '$packageId', 'version', '1.0.0', 'status', 'published',
    'source', $sourceJson,
    'integrity', $integrityJson,
    'compatibility', jsonb_build_array('$compat'),
    'permissions', jsonb_build_object(
      'filesystem', jsonb_build_object('read', jsonb_build_array(), 'write', jsonb_build_array(), 'delete', false),
      'shell', jsonb_build_object('allowed', false, 'commands', jsonb_build_array()),
      'network', jsonb_build_object('allowed', false, 'domains', jsonb_build_array())
    ),
    'installation', jsonb_build_object(
      'method', '$($pkg.Method)', 'target_client', '$compat',
      'steps', $stepsJson,
      'pre_install_message', '请确认来源可信后再安装。',
      'post_install_message', '安装完成，可在客户端中确认工具可用。'
    ),
    'dependencies', jsonb_build_object('npm', null, 'pip', null, 'system', null, 'docker', null, 'mcp_servers', $mcpJson),
    'trust_score', jsonb_build_object(
      'model_version', '0.2.0', 'score', $score,
      'risk_summary', jsonb_build_object(
        'level', '$level', 'grade', '$($pkg.Grade)',
        'top_risks', jsonb_build_array(), 'install_recommendation', '$rec',
        'auto_grade', '$($pkg.Grade)', 'effective_grade', '$($pkg.Grade)'
      )
    ),
    'submitted_at', now(), 'published_at', now(), 'created_at', now()
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
    Write-Host "  + fixture $($pkg.Name) ($($pkg.Method), grade $($pkg.Grade))"
}

Write-Host "=== 4. 验证所有 published 包 install-manifest ==="
$published = @(Get-PsqlRows "SELECT DISTINCT p.name FROM packages p JOIN package_versions v ON v.package_id=p.id AND v.status='published' WHERE p.status='published' ORDER BY p.name;")
$okCount = 0
$failList = @()
foreach ($n in $published) {
    $n = $n.Trim()
    if (-not $n) { continue }
    $client = if ($n -eq "claude-plugin-demo") { "claude-code-plugin" } else { "claude-code" }
    try {
        $r = Invoke-WebRequest -Uri "$api/api/v0/packages/$([uri]::EscapeDataString($n))/install-manifest?client=$client" -UseBasicParsing -TimeoutSec 10
        if ($r.StatusCode -eq 200) { $okCount++ } else { $failList += "$n($($r.StatusCode))" }
    } catch {
        $failList += "$n(ERR)"
    }
}
Write-Host "  install-manifest OK: $okCount / $($published.Count)"
if ($failList.Count -gt 0) { Write-Host "  FAILED: $($failList -join ', ')" }

Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "SEED COMPLETE"
