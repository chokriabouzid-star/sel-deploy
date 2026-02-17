#!/usr/bin/env bash
set -euo pipefail

SEL_DEPLOY="./target/release/sel-deploy"

# 1. Generate key (first time only)
if [ ! -f ~/.local/share/sel-deploy/keys/default.pem ]; then
    $SEL_DEPLOY keygen
fi

# 2. Run attested deployment
$SEL_DEPLOY run --env production -- echo "Deploying app v1.0.0"

# 3. View history
$SEL_DEPLOY history

# 4. Verify chain
$SEL_DEPLOY verify
