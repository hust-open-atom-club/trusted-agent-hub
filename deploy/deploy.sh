#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(dirname -- "$SCRIPT_DIR")
ENV_FILE="$REPO_ROOT/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE. Copy .env.example to .env and fill required values." >&2
  exit 1
fi

DOCKERFILE_PATH="$REPO_ROOT/apps/api/Dockerfile"
DOCKERFILE_TEMPLATE="$REPO_ROOT/apps/api/Dockerfile.example"
if [ ! -f "$DOCKERFILE_PATH" ]; then
  if [ ! -f "$DOCKERFILE_TEMPLATE" ]; then
    echo "Missing $DOCKERFILE_TEMPLATE." >&2
    exit 1
  fi
  cp "$DOCKERFILE_TEMPLATE" "$DOCKERFILE_PATH"
  echo "Created local API Dockerfile from Dockerfile.example."
fi

cd "$REPO_ROOT"
docker compose --env-file "$ENV_FILE" config --quiet
docker compose --env-file "$ENV_FILE" up -d --build
docker compose --env-file "$ENV_FILE" ps
