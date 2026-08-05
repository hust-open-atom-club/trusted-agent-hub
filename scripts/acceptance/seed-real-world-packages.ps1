<#
.SYNOPSIS
重建数据库：清空所有能力包，并 seed 一批来自网上真实仓库的可安装包。

.DESCRIPTION
包来源（全部真实，非项目 examples）：
- Skills：Anthropic 官方 anthropics/skills（docx / pdf / pptx / xlsx / skill-creator / mcp-builder / algorithmic-art / brand-guidelines / webapp-testing / theme-factory / frontend-design / canvas-design）
- MCP Servers：Model Context Protocol 官方 modelcontextprotocol/servers
  （memory / filesystem / time / sequential-thinking / everything）
- Plugin：基于 anthropics/skills 官方内容组织的 claude-skills-plugin / anthropic-skills-plugin / anthropic-web-skills-plugin，以及 MIT 开源 obra/superpowers
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

Write-Host "=== 2. 拉取真实仓库并构建 ZIP 制品（优先使用 examples/real-world 内置内容） ==="
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
    @{ Name = "docx";             Source = Join-Path $skillsClone "skills\docx";            Repo = "https://github.com/anthropics/skills/tree/main/skills/docx";            Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official DOCX skill: create, edit and convert Word documents."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/docx/" }, @{ client = "cursor"; destination = "~/.cursor/skills/docx/" }) },
    @{ Name = "pdf";              Source = Join-Path $skillsClone "skills\pdf";             Repo = "https://github.com/anthropics/skills/tree/main/skills/pdf";             Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official PDF skill: analyze and edit PDF documents."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/pdf/" }, @{ client = "cursor"; destination = "~/.cursor/skills/pdf/" }) },
    @{ Name = "pptx";             Source = Join-Path $skillsClone "skills\pptx";            Repo = "https://github.com/anthropics/skills/tree/main/skills/pptx";            Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official PPTX skill: build and edit PowerPoint decks."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/pptx/" }, @{ client = "cursor"; destination = "~/.cursor/skills/pptx/" }) },
    @{ Name = "xlsx";             Source = Join-Path $skillsClone "skills\xlsx";            Repo = "https://github.com/anthropics/skills/tree/main/skills/xlsx";            Type = "skill";      Grade = "A"; Client = "claude-code";        Desc = "Anthropic official XLSX skill: create and analyze spreadsheets."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/xlsx/" }, @{ client = "cursor"; destination = "~/.cursor/skills/xlsx/" }) },
    @{ Name = "anthropic-skill-creator"; Source = Join-Path $RepoRoot "examples\real-world\skills\skill-creator"; Repo = "https://github.com/anthropics/skills/tree/main/skills/skill-creator"; Type = "skill"; Grade = "A"; Client = "claude-code"; Desc = "Anthropic official skill-creator: design and scaffold new skills."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/anthropic-skill-creator/" }, @{ client = "cursor"; destination = "~/.cursor/skills/anthropic-skill-creator/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills/tree/main/skills/skill-creator" },
    @{ Name = "anthropic-mcp-builder"; Source = Join-Path $RepoRoot "examples\real-world\skills\mcp-builder"; Repo = "https://github.com/anthropics/skills/tree/main/skills/mcp-builder"; Type = "skill"; Grade = "A"; Client = "claude-code"; Desc = "Anthropic official mcp-builder: design and implement MCP servers."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/anthropic-mcp-builder/" }, @{ client = "cursor"; destination = "~/.cursor/skills/anthropic-mcp-builder/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills/tree/main/skills/mcp-builder" },
    @{ Name = "anthropic-algorithmic-art"; Source = Join-Path $RepoRoot "examples\real-world\skills\algorithmic-art"; Repo = "https://github.com/anthropics/skills/tree/main/skills/algorithmic-art"; Type = "skill"; Grade = "A"; Client = "claude-code"; Desc = "Anthropic official algorithmic-art: generate animated generative art."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/anthropic-algorithmic-art/" }, @{ client = "cursor"; destination = "~/.cursor/skills/anthropic-algorithmic-art/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills/tree/main/skills/algorithmic-art" },
    @{ Name = "anthropic-brand-guidelines"; Source = Join-Path $RepoRoot "examples\real-world\skills\brand-guidelines"; Repo = "https://github.com/anthropics/skills/tree/main/skills/brand-guidelines"; Type = "skill"; Grade = "A"; Client = "claude-code"; Desc = "Anthropic official brand-guidelines: produce on-brand copy and visual assets."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/anthropic-brand-guidelines/" }, @{ client = "cursor"; destination = "~/.cursor/skills/anthropic-brand-guidelines/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills/tree/main/skills/brand-guidelines" },
    @{ Name = "anthropic-webapp-testing"; Source = Join-Path $RepoRoot "examples\real-world\skills\webapp-testing"; Repo = "https://github.com/anthropics/skills/tree/main/skills/webapp-testing"; Type = "skill"; Grade = "B"; Client = "claude-code"; Desc = "Anthropic official webapp-testing: automated web application testing workflows."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/anthropic-webapp-testing/" }, @{ client = "cursor"; destination = "~/.cursor/skills/anthropic-webapp-testing/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills/tree/main/skills/webapp-testing" },
    @{ Name = "anthropic-theme-factory"; Source = Join-Path $RepoRoot "examples\real-world\skills\theme-factory"; Repo = "https://github.com/anthropics/skills/tree/main/skills/theme-factory"; Type = "skill"; Grade = "A"; Client = "claude-code"; Desc = "Anthropic official theme-factory: create cohesive visual themes for apps."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/anthropic-theme-factory/" }, @{ client = "cursor"; destination = "~/.cursor/skills/anthropic-theme-factory/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills/tree/main/skills/theme-factory" },
    @{ Name = "anthropic-frontend-design"; Source = Join-Path $RepoRoot "examples\real-world\skills\frontend-design"; Repo = "https://github.com/anthropics/skills/tree/main/skills/frontend-design"; Type = "skill"; Grade = "A"; Client = "claude-code"; Desc = "Anthropic official frontend-design: accessible, polished frontend interfaces."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/anthropic-frontend-design/" }, @{ client = "cursor"; destination = "~/.cursor/skills/anthropic-frontend-design/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills/tree/main/skills/frontend-design" },
    @{ Name = "mcp-server-memory"; Source = Join-Path $RepoRoot "examples\real-world\mcp-servers\memory";  Repo = "https://github.com/modelcontextprotocol/servers/tree/main/src/memory";            Type = "mcp_server"; Grade = "B"; Client = "claude-code";        Desc = "Official MCP reference server: persistent memory with graph knowledge."; Version = "0.6.3"; McpServers = @([pscustomobject]@{ name = "memory"; command = "npx"; args = @("-y", "@modelcontextprotocol/server-memory"); env = $null }); Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/mcp-server-memory/" }, @{ client = "cursor"; destination = "~/.cursor/skills/mcp-server-memory/" }); CommitHash = "76d64c822f5125032f89eb71dbdb94e42b434821"; License = "Apache-2.0"; Homepage = "https://github.com/modelcontextprotocol/servers/tree/main/src/memory" },
    @{ Name = "mcp-server-filesystem"; Source = Join-Path $RepoRoot "examples\real-world\mcp-servers\filesystem"; Repo = "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem";        Type = "mcp_server"; Grade = "B"; Client = "claude-code";        Desc = "Official MCP reference server: safe filesystem operations."; Version = "0.6.3"; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/mcp-server-filesystem/" }, @{ client = "cursor"; destination = "~/.cursor/skills/mcp-server-filesystem/" }); CommitHash = "76d64c822f5125032f89eb71dbdb94e42b434821"; License = "Apache-2.0"; Homepage = "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem" },
    @{ Name = "mcp-server-sequential-thinking"; Source = Join-Path $RepoRoot "examples\real-world\mcp-servers\sequentialthinking"; Repo = "https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking"; Type = "mcp_server"; Grade = "A"; Client = "claude-code"; Desc = "Official MCP reference server: sequential thinking and problem solving."; Version = "0.6.2"; McpServers = @([pscustomobject]@{ name = "sequentialthinking"; command = "npx"; args = @("-y", "@modelcontextprotocol/server-sequential-thinking"); env = $null }); Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/mcp-server-sequential-thinking/" }, @{ client = "cursor"; destination = "~/.cursor/skills/mcp-server-sequential-thinking/" }); CommitHash = "76d64c822f5125032f89eb71dbdb94e42b434821"; License = "Apache-2.0"; Homepage = "https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking" },
    @{ Name = "mcp-server-everything"; Source = Join-Path $RepoRoot "examples\real-world\mcp-servers\everything"; Repo = "https://github.com/modelcontextprotocol/servers/tree/main/src/everything"; Type = "mcp_server"; Grade = "B"; Client = "claude-code"; Desc = "Official MCP reference server: exercises all MCP protocol features."; Version = "2.0.0"; McpServers = @([pscustomobject]@{ name = "everything"; command = "npx"; args = @("-y", "@modelcontextprotocol/server-everything", "stdio"); env = $null }); Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/mcp-server-everything/" }, @{ client = "cursor"; destination = "~/.cursor/skills/mcp-server-everything/" }); CommitHash = "76d64c822f5125032f89eb71dbdb94e42b434821"; License = "Apache-2.0"; Homepage = "https://github.com/modelcontextprotocol/servers/tree/main/src/everything" },
    @{ Name = "time-mcp";         Source = Join-Path $serversClone "src\time";              Repo = "https://github.com/modelcontextprotocol/servers/tree/main/src/time";              Type = "mcp_server"; Grade = "B"; Client = "claude-code";        Desc = "Official MCP reference server: time and timezone utilities."; Compat = @("claude-code", "cursor"); Targets = @(@{ client = "claude-code"; destination = "~/.claude/skills/time-mcp/" }, @{ client = "cursor"; destination = "~/.cursor/skills/time-mcp/" }) },
    @{ Name = "claude-skills-plugin"; Source = Join-Path $skillsClone "skills";             Repo = "https://github.com/anthropics/skills";             Type = "plugin";     Grade = "B"; Client = "claude-code-plugin"; Desc = "Claude skills plugin based on Anthropic official skills (docx/pdf/pptx/xlsx/skill-creator)." },
    @{ Name = "anthropic-skills-plugin"; Source = Join-Path $RepoRoot "examples\real-world\plugins\anthropic-skills-plugin"; Repo = "https://github.com/anthropics/skills"; Type = "plugin"; Grade = "A"; Client = "claude-code-plugin"; Desc = "Claude Code plugin bundling Apache-2.0 Anthropic skills (skill-creator/mcp-builder/algorithmic-art)."; Compat = @("claude-code-plugin"); Targets = @(@{ client = "claude-code-plugin"; destination = "~/.claude/plugins/anthropic-skills-plugin/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills" },
    @{ Name = "anthropic-web-skills-plugin"; Source = Join-Path $RepoRoot "examples\real-world\plugins\anthropic-web-skills-plugin"; Repo = "https://github.com/anthropics/skills"; Type = "plugin"; Grade = "B"; Client = "claude-code-plugin"; Desc = "Claude Code plugin bundling Anthropic web skills (brand/webapp-testing/theme/frontend)."; Compat = @("claude-code-plugin"); Targets = @(@{ client = "claude-code-plugin"; destination = "~/.claude/plugins/anthropic-web-skills-plugin/" }); CommitHash = "b29e7cf65e5cb78a5ac33d582270551bc74a14eb"; License = "Apache-2.0"; Homepage = "https://github.com/anthropics/skills" },
    @{ Name = "superpowers"; Source = Join-Path $RepoRoot "examples\real-world\plugins\superpowers"; Repo = "https://github.com/obra/superpowers"; Type = "plugin"; Grade = "B"; Client = "claude-code-plugin"; Desc = "Superpowers: MIT core skills library for Claude Code (TDD, debugging, collaboration)."; Version = "6.2.0"; Compat = @("claude-code-plugin"); Targets = @(@{ client = "claude-code-plugin"; destination = "~/.claude/plugins/superpowers/" }); CommitHash = "44c9b2d6e889982ac18c27d05a19fefe335194e1"; License = "MIT"; Homepage = "https://github.com/obra/superpowers" },
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
        Compat = if ($pkg.ContainsKey('Compat')) { $pkg.Compat } else { $null }
        Targets = if ($pkg.ContainsKey('Targets')) { $pkg.Targets } else { $null }
        CommitHash = if ($pkg.ContainsKey('CommitHash')) { $pkg.CommitHash } else { $null }
        License = if ($pkg.ContainsKey('License')) { $pkg.License } else { $null }
        Homepage = if ($pkg.ContainsKey('Homepage')) { $pkg.Homepage } else { $null }
        Version = if ($pkg.ContainsKey('Version')) { $pkg.Version } else { $null }
    }
    Write-Host "  + $($pkg.Name) sha256=$($sha.Substring(0,12))… size=$size"
}

# 真实外部包（无需 ZIP 制品）
$seeds += [pscustomobject]@{ Name = "npm-install-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Desc = "Installs the real npm package is-number@7.0.0 into a managed directory."; Method = "npm_install"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; McpServers = $null; Compat = $null; Targets = $null }
$seeds += [pscustomobject]@{ Name = "pip-install-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Desc = "Installs the real PyPI package six==1.16.0 into a managed directory."; Method = "pip_install"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; McpServers = $null; Compat = $null; Targets = $null }
$seeds += [pscustomobject]@{ Name = "docker-run-demo"; Type = "mcp_server"; Grade = "B"; Client = "claude-code"; Desc = "Pulls the real docker image alpine:3.21 and generates a run configuration."; Method = "docker_run"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; McpServers = $null; Compat = $null; Targets = $null }
$seeds += [pscustomobject]@{ Name = "manual-steps-demo"; Type = "skill"; Grade = "B"; Client = "claude-code"; Desc = "Manual installation steps demo with local record tracking."; Method = "manual_steps"; ZipName = $null; Sha256 = $null; Size = $null; RootName = $null; McpServers = $null; Compat = $null; Targets = $null }

Write-Host "=== 3. 插入 published 夹具 ==="
$gitHash = (& git -C $RepoRoot rev-parse HEAD).Trim()
$repoUrl = "https://github.com/hust-open-atom-club/trusted-agent-hub"

foreach ($pkg in $seeds) {
    $packageId = "pkg-" + $pkg.Name.Replace("-", "")
    $versionId = "ver-" + $pkg.Name.Replace("-", "")
    $compatList = @(if ($pkg.PSObject.Properties['Compat'] -and $pkg.Compat) { $pkg.Compat } else { $pkg.Client })
    $compatSql = "jsonb_build_array(" + (($compatList | ForEach-Object { "'$_'" }) -join ",") + ")"
    $primaryClient = $compatList[0]

    $targetsJson = "null"
    if ($pkg.PSObject.Properties['Targets'] -and $pkg.Targets) {
        $targetItems = @()
        foreach ($t in $pkg.Targets) {
            $targetItems += "jsonb_build_object('client','$($t.client)','destination','$($t.destination)')"
        }
        $targetsJson = "jsonb_build_array(" + ($targetItems -join ",") + ")"
    }
    $artifactUrl = "http://127.0.0.1:8000/api/v0/artifacts/$($pkg.ZipName)"
    $commitHash = if ($pkg.PSObject.Properties['CommitHash'] -and $pkg.CommitHash) { $pkg.CommitHash } else { $gitHash }

    if ($pkg.Method -eq "copy_directory") {
        $sourceJson = "jsonb_build_object('type','github','repository_url','$($pkg.Repo)','download_url','$artifactUrl','ref','main','commit_hash','$commitHash','verified_owner',true)"
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
    $license = if ($pkg.PSObject.Properties['License'] -and $pkg.License) { $pkg.License } else { "MIT" }
    $homepage = if ($pkg.PSObject.Properties['Homepage'] -and $pkg.Homepage) { $pkg.Homepage } else { $repoUrl }
    $version = if ($pkg.PSObject.Properties['Version'] -and $pkg.Version) { $pkg.Version } else { "1.0.0" }

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
  '$packageId', '$($pkg.Name)', 'published', '$version',
  jsonb_build_object(
    'id', '$packageId', 'name', '$($pkg.Name)', 'description', '$desc',
    'type', '$($pkg.Type)', 'license', '$license', 'keywords', jsonb_build_array('real','official'),
    'category', 'seed', 'homepage', '$homepage', 'status', 'published',
    'latest_version', '$version', 'compatibility', $compatSql,
    'install_count', 0, 'grade', '$($pkg.Grade)', 'risk_level', '$level',
    'avg_rating', null, 'created_at', now(), 'updated_at', now()
  )::json
);
INSERT INTO package_versions (id, package_id, version, status, data)
VALUES (
  '$versionId', '$packageId', '$version', 'published',
  jsonb_build_object(
    'id', '$versionId', 'package_id', '$packageId', 'version', '$version', 'status', 'published',
    'source', $sourceJson,
    'integrity', $integrityJson,
    'compatibility', $compatSql,
    'permissions', jsonb_build_object(
      'filesystem', jsonb_build_object('read', jsonb_build_array(), 'write', jsonb_build_array(), 'delete', false),
      'shell', jsonb_build_object('allowed', false, 'commands', jsonb_build_array()),
      'network', jsonb_build_object('allowed', false, 'domains', jsonb_build_array())
    ),
    'installation', jsonb_build_object(
      'method', '$($pkg.Method)', 'target_client', '$primaryClient',
      'steps', $stepsJson,
      'targets', $targetsJson,
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
    $client = if ($n -in @("claude-skills-plugin", "anthropic-skills-plugin", "anthropic-web-skills-plugin", "superpowers")) { "claude-code-plugin" }
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
