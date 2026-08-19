#!/usr/bin/env bash
# Minimal attested-deploy demo. Uses SEL_DEPLOY_HOME so it never touches
# your real ~/.local/share/sel-deploy directory.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEL_DEPLOY="${SEL_DEPLOY:-$ROOT/target/release/sel-deploy}"
if [ ! -x "$SEL_DEPLOY" ]; then
    SEL_DEPLOY="$ROOT/target/debug/sel-deploy"
fi
if [ ! -x "$SEL_DEPLOY" ]; then
    echo "Build first: cargo build --release" >&2
    exit 1
fi

export SEL_DEPLOY_HOME="${SEL_DEPLOY_HOME:-$(mktemp -d /tmp/sel-deploy-demo.XXXXXX)}"
echo "Using SEL_DEPLOY_HOME=$SEL_DEPLOY_HOME"

if [ ! -f "$SEL_DEPLOY_HOME/keys/default.pem" ]; then
    "$SEL_DEPLOY" keygen
fi

# Successful deploy (exit 0)
"$SEL_DEPLOY" run --env production -- echo "Deploying app v1.0.0"

# Failed deploy — the wrapper now exits 7 as well (unless --ignore-fail)
set +e
"$SEL_DEPLOY" run --env staging --ignore-fail -- sh -c 'echo boom; exit 7'
set -e

"$SEL_DEPLOY" history
"$SEL_DEPLOY" verify
"$SEL_DEPLOY" rebuild
echo "OK"
