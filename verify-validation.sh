#!/usr/bin/env bash
# Have every port validate the shared token vectors and confirm all three agree with the expected verdicts.
# Requires: python3 (+ PyJWT, cryptography), node/npm, go.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "== validate-emit: python =="
( cd python && PYTHONPATH=src python3 validate_emit.py )

echo "== validate-emit: typescript =="
( cd typescript && npm install --silent && npx tsx validate-emit.ts )

echo "== validate-emit: go =="
( cd go && go run ./cmd/validate-emit )

echo "== cross-language agreement =="
python3 validation/check.py
