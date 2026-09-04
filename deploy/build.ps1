# Validate, build, and start TrustedAgentHub from the repository-root .env.

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $repoRoot ".env"
if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw "Missing $envFile. Copy .env.example to .env and fill required values."
}

$apiDockerfilePath = Join-Path $repoRoot "apps/api/Dockerfile"
$apiDockerfileTemplate = Join-Path $repoRoot "apps/api/Dockerfile.example"
if (-not (Test-Path -LiteralPath $apiDockerfilePath -PathType Leaf)) {
    if (-not (Test-Path -LiteralPath $apiDockerfileTemplate -PathType Leaf)) {
        throw "Missing $apiDockerfileTemplate."
    }
    Copy-Item -LiteralPath $apiDockerfileTemplate -Destination $apiDockerfilePath
    Write-Host "Created local API Dockerfile from Dockerfile.example." -ForegroundColor Yellow
}

Push-Location $repoRoot
try {
    Write-Host "Validating Docker Compose configuration..." -ForegroundColor Cyan
    docker compose --env-file $envFile config --quiet
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose configuration is invalid." }

    Write-Host "Building and starting services..." -ForegroundColor Cyan
    docker compose --env-file $envFile up -d --build
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose deployment failed." }

    docker compose --env-file $envFile ps
} finally {
    Pop-Location
}
