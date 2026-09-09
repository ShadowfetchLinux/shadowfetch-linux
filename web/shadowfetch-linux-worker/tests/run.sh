#!/usr/bin/env bash
# Both test suites for the artifact worker. No network, no credentials, no deploy.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tools/sync_retirement_policy.py --check
python3 -m unittest discover -s tests "$@"
node --test tests/worker.test.mjs
