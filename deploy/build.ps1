# TrustedAgentHub - 交互式 Docker 构建脚本
# 用法: 在项目根目录执行  powershell -ExecutionPolicy Bypass -File .\deploy\build.ps1
#     或直接  .\deploy\build.ps1
#
# 作用: 构建前询问是否启用 SR-017 本地语义模型 (fastembed + MiniLM-L12),
#      让构建者自己决定镜像大小与构建速度的取舍。

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  TrustedAgentHub - Docker 构建" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "SR-017 本地语义模型 (fastembed + MiniLM-L12):" -ForegroundColor White
Write-Host "  [y] 启用  - 构建时下载嵌入模型 (~241MB), 镜像约增大 300MB," -ForegroundColor Gray
Write-Host "             构建更慢, 但 MCP 工具描述投毒检测完全离线可用" -ForegroundColor Gray
Write-Host "  [n] 跳过  - 镜像更小、构建更快, 语义检测自动降级为纯规则模式 (默认)" -ForegroundColor Gray
Write-Host ""
$choice = Read-Host "是否启用语义模型构建? (y/n)"

if ($choice -match '^[yY]$') {
    $env:ENABLE_SEMANTIC_MODEL = "true"
    Write-Host ""
    Write-Host ">> 已启用: 本次构建将包含 fastembed + MiniLM-L12 模型" -ForegroundColor Green
} else {
    $env:ENABLE_SEMANTIC_MODEL = "false"
    Write-Host ""
    Write-Host ">> 已跳过: 快速构建, SR-017 将运行纯规则模式" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "开始构建 (docker compose build)..."
Write-Host ""
docker compose build

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "构建失败, 请查看上方日志。" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "构建成功!" -ForegroundColor Green
Write-Host "启动服务:  docker compose up -d" -ForegroundColor Cyan
Write-Host "查看状态:  docker compose ps" -ForegroundColor Cyan
Write-Host ""
