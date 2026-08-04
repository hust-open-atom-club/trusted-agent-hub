<#
.SYNOPSIS
重建数据库：清空所有能力包，并 seed 一批来自网上真实仓库的可安装包。

.DESCRIPTION
包来源（全部真实，非项目 examples）：
- Skills：Anthropic 官方 anthropics/skills（docx / pdf / pptx / xlsx / skill-creator）
- MCP Servers：Model Context Protocol 官方 modelcontextprotocol/servers
  （memory / filesystem / time）
- Plugin：基于 anthropics/skills 官方内容组织的 claude-skills-plugin
- 外部真实包：npm is-number@7.0.0、PyPI six==1.16.0、Docker alpine:3.20
- manual-steps-demo：人工安装方式演示

所有文案使用英文（避免 PowerShell -> psql 管道中文乱码）。
ZIP 制品放入 API artifacts 卷（/api/v0/artifacts/*.zip），容器重启后仍有效。

前置：docker compose 三服务运行（db/api/web），API 健康；git 可访问 GitHub。
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

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT FAILED: $Message" }
    Write-Host "  [PASS] $Message"
}

function Copy-ZipToArtifacts([string]$ZipPath, [string]$ZipName) {
    $previousEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & docker compose -f $composeFile cp "$ZipPath" "api:/artifacts/$ZipName" 2>&1 | Out-Null
        $cpExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEap
    }
    if ($cpExit -ne 0) {
        $previousEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $cid = (& docker compose -f $composeFile ps -q api).Trim()
            & docker cp "$ZipPath" "${cid}:/artifacts/$ZipName" 2>&1 | Out-Null
            $cpExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousEap
        }
        if ($cpExit -ne 0) { throw "Failed to copy $ZipName into api artifacts" }
    }
}

Write-Host "=== 0. 前置检查 ==="
$health = Invoke-RestMethod -Uri "$api/api/v0/health" -TimeoutSec 10
Assert-True ($health.status -eq "ok") "API health ok"

Write-Host "=== 1. 清空现有能力包数据 ==="
Invoke-Psql @"
BEGIN;
DELETE FROM install_records;
DELETE FROM trust_levels;
DELETE FROM scan_reports;
DELETE FROM review_records;
DELETE FROM audit_logs;
DELETE FROM feedback_records;
DELETE FROM package_versions;
DELETE FROM packages;
COMMIT;
"@
Write-Host "  cleared"

Write-Host "=== 2. 拉取真实仓库并构建 ZIP 制品 ==="
$skillsCache = Join-Path $env:TEMP "tah-real-git\skills"
$serversCache = Join-Path $env:TEMP "tah-real-git\servers"
$skillsClone = if (Test-Path -LiteralPath $skillsCache) { $skillsCache } else { Join-Path $tmpRoot "anthropic-skills" }
$serversClone = if (Test-Path -LiteralPath $serversCache) { $serversCache } else { Join-Path $tmpRoot "mcp-servers" }
if (-not (Test-Path -LiteralPath $skillsClone)) {
    $gitEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        git clone --depth 1 https://github.com/anthropics/skills.git $skillsClone 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "git clone anthropics/skills failed" }
    } finally {
        $ErrorActionPreference = $gitEap
    }
}
if (-not (Test-Path -LiteralPath $serversClone)) {
    $gitEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        git clone --depth 1 https://github.com/modelcontextprotocol/servers.git $serversClone 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "git clone modelcontextprotocol/servers failed" }
    } finally {
        $ErrorActionPreference = $gitEap
    }
}

# 真实来源包：SourceDir 指向克隆仓库内的子目录，Name 为安装名
$copyPackages = @(
    @{ Name = "docx";             Source = Join-Path $skillsClone "skills\docx";            Repo = "https://github.com/anthropics/skills/tree/main/skills/docx";            Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official DOCX skill: create, edit and convert Word documents." },
    @{ Name = "pdf";              Source = Join-Path $skillsClone "skills\pdf";             Repo = "https://github.com/anthropics/skills/tree/main/skills/pdf";             Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official PDF skill: analyze and edit PDF documents." },
    @{ Name = "pptx";             Source = Join-Path $skillsClone "skills\pptx";            Repo = "https://github.com/anthropics/skills/tree/main/skills/pptx";            Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official PPTX skill: build and edit PowerPoint decks." },
    @{ Name = "xlsx";             Source = Join-Path $skillsClone "skills\xlsx";            Repo = "https://github.com/anthropics/skills/tree/main/skills/xlsx";            Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official XLSX skill: create and analyze spreadsheets." },
    @{ Name = "skill-creator";    Source = Join-Path $skillsClone "skills\skill-creator";   Repo = "https://github.com/anthropics/skills/tree/main/skills/skill-creator";   Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official skill-creator: design and scaffold new skills." },
    @{ Name = "memory-mcp";       Source = Join-Path $serversClone "src\memory";            Repo = "https://github.com/modelcontextprotocol/servers/tree/main/src/memory";            Type = "mcp_server"; Grade = "B"; Client = "claude-code";        Desc = "Official MCP reference server: persistent memory with graph knowledge."; McpServers = @([pscustomobject]@{ name = "memory"; command = "npx"; args = @("-y", "@modelcontextprotocol/server-memory"); env = $null }) },
    @{ Name = "filesystem-mcp";   Source = Join-Path $serversClone "src\filesystem";        Repo = "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem";        Type = "mcp_server"; Grade = "B"; Client = "claude-code";        Desc = "Official MCP reference server: safe filesystem operations." },
    @{ Name = "time-mcp";         Source = Join-Path $serversClone "src\time";              Repo = "https://github.com/modelcontextprotocol/servers/tree/main/src/time";              Type = "mcp_server"; Grade = "B"; Client = "claude-code";        Desc = "Official MCP reference server: time and timezone utilities." },
    @{ Name = "claude-skills-plugin"; Source = Join-Path $skillsClone "skills";             Repo = "https://github.com/anthropics/skills";             Type = "plugin";     Grade = "B"; Client = "claude-code-plugin"; Desc = "Claude skills plugin based on Anthropic official skills (docx/pdf/pptx/xlsx/skill-creator)." },
    @{ Name = "canvas-design";       Source = Join-Path $skillsClone "skills\canvas-design"; Repo = "https://github.com/anthropics/skills/tree/main/skills/canvas-design"; Type = "skill";      Grade = "A"; Client = "cursor";             Desc = "Anthropic official canvas-design skill for Cursor: create and iterate on web artifacts." }
)

$seeds = @()
foreach ($pkg in $copyPackages) {
    if (-not (Test-Path -LiteralPath $pkg.Source -PathType Container)) {
        throw "Source missing: $($pkg.Source)"
    }
    $zipPath = Join-Path $tmpRoot "$($pkg.Name).zip"
    Compress-Archive -LiteralPath $pkg.Source -DestinationPath $zipPath -Force
    $sha = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $zipPath).Length
    $zipName = "$($pkg.Name).zip"
    Copy-ZipToArtifacts $zipPath $zipName
    $rootName = Split-Path $pkg.Source -Leaf
    $seeds += [pscustomobject]@{
        Name = $pkg.Name; Type = $pkg.Type; Grade = $pkg.Grade; Client = $pkg.Client; Desc = $pkg.Desc
        Method = "copy_directory"; Repo = $pkg.Repo; ZipName = $zipName; Sha256 = $sha; Size = $size; RootName = $rootName
        McpServers = if ($pkg.ContainsKey('McpServers')) { $pkg.McpServers } else { $null }
    }
    Write-Host "  + $($pkg.Name) sha256=$($sha.Substring(0,12))… size=$size"
}

# 真实外部包（无需 ZIP 制品）
$seeds += [pscustomobject]@{ Name = "npm-install-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Desc = "Installs the real npm package is-number@7.0.0 into a managed directory."; Method = "npm_install"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; McpServers = $null }
$seeds += [pscustomobject]@{ Name = "pip-install-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Desc = "Installs the real PyPI package six==1.16.0 into a managed directory."; Method = "pip_install"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; McpServers = $null }
$seeds += [pscustomobject]@{ Name = "docker-run-demo"; Type = "mcp_server"; Grade = "B"; Client = "claude-code"; Desc = "Pulls the real docker image alpine:3.21 and generates a run configuration."; Method = "docker_run"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; McpServers = $null }
$seeds += [pscustomobject]@{ Name = "manual-steps-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Desc = "Manual installation steps demo with local record tracking."; Method = "manual_steps"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; McpServers = $null }

Write-Host "=== 3. 插入 published 夹具 ==="
$gitHash = (& git -C $RepoRoot rev-parse HEAD).Trim()
$repoUrl = "https://github.com/hust-open-atom-club/trusted-agent-hub"

foreach ($pkg in $seeds) {
    $packageId = "pkg-" + $pkg.Name.Replace("-", "")
    $versionId = "ver-" + $pkg.Name.Replace("-", "")
    $compat = $pkg.Client
    $artifactUrl = "http://127.0.0.1:8000/api/v0/artifacts/$($pkg.ZipName)"

    if ($pkg.Method -eq "copy_directory") {
        $sourceJson = "jsonb_build_object('type','github','repository_url','$($pkg.Repo)','download_url','$artifactUrl','ref','main','commit_hash','$gitHash','verified_owner',true)"
        $integrityJson = "jsonb_build_object('sha256','$($pkg.Sha256)','download_size_bytes',$($pkg.Size))"
        $destRoot = switch ($pkg.Client) {
            "claude-code-plugin" { "~/.claude/plugins/" }
            "cursor" { "~/.cursor/skills/" }
            default { "~/.claude/skills/" }
        }
        $stepsJson = "jsonb_build_array(" +
            "jsonb_build_object('action','download','url','$artifactUrl')," +
            "jsonb_build_object('action','verify','algorithm','sha256','checksum','$($pkg.Sha256)')," +
            "jsonb_build_object('action','extract','archive','$($pkg.ZipName)')," +
            "jsonb_build_object('action','copy','source','$($pkg.RootName)/','destination','$destRoot$($pkg.Name)/')" +
            ")"
    } elseif ($pkg.Method -eq "npm_install") {
        $sourceJson = "jsonb_build_object('type','npm','repository_url','https://github.com/jonschlinkert/is-number','ref','main')"
        $integrityJson = "null"
        $stepsJson = "jsonb_build_array(jsonb_build_object('action','npm_install','package','is-number','version','7.0.0','registry','https://registry.npmjs.org/'))"
    } elseif ($pkg.Method -eq "pip_install") {
        $sourceJson = "jsonb_build_object('type','pypi','repository_url','https://github.com/benjaminp/six','ref','main')"
        $integrityJson = "null"
        $stepsJson = "jsonb_build_array(jsonb_build_object('action','pip_install','package','six','version','1.16.0','index_url','https://pypi.org/simple'))"
    } elseif ($pkg.Method -eq "docker_run") {
        $sourceJson = "jsonb_build_object('type','docker','repository_url','https://github.com/alpinelinux/docker-alpine','ref','main')"
        $integrityJson = "null"
        $stepsJson = "jsonb_build_array(jsonb_build_object('action','docker_run','image','alpine','tag','3.21','ports',jsonb_build_array(),'volumes',jsonb_build_array(),'env',jsonb_build_array()))"
    } else {
        $sourceJson = "jsonb_build_object('type','local_upload','repository_url','$repoUrl','ref','main')"
        $integrityJson = "null"
        $stepsJson = "jsonb_build_array(jsonb_build_object('action','manual_steps','title','$($pkg.Name)','text','1. Download the package.' || chr(10) || '2. Follow the README to install manually.'))"
    }

    $level = if ($pkg.Grade -eq "A") { "low_risk" } else { "medium_risk" }
    $rec = if ($pkg.Grade -eq "A") { "safe" } else { "review_recommended" }
    $score = if ($pkg.Grade -eq "A") { 92 } else { 72 }
    $desc = $pkg.Desc.Replace("'", "''")

    $mcpJson = "null"
    if ($pkg.McpServers) {
        $mcpItems = @()
        foreach ($m in $pkg.McpServers) {
            $argsJson = if ($m.args -and $m.args.Count -gt 0) {
                "jsonb_build_array(" + (($m.args | ForEach-Object { "'$_'" }) -join ",") + ")"
            } else { "jsonb_build_array()" }
            $mcpItems += "jsonb_build_object('name','$($m.name)','command','$($m.command)','args',$argsJson,'env',null)"
        }
        $mcpJson = "jsonb_build_array(" + ($mcpItems -join ",") + ")"
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
    'type', '$($pkg.Type)', 'license', 'MIT', 'keywords', jsonb_build_array('real','official'),
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
      'pre_install_message', 'Verify the source before installing.',
      'post_install_message', 'Installed. Confirm the capability in your client.'
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
    $client = if ($n -eq "claude-skills-plugin") { "claude-code-plugin" }
              elseif ($n -eq "canvas-design") { "cursor" }
              else { "claude-code" }
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
