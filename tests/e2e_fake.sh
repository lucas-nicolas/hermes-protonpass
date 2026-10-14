#!/usr/bin/env bash
# End-to-end: real `hermes` binary + real plugin install from git, fake pass-cli (no Proton account).
# Usage: e2e_fake.sh <git-url-or-path> <ref>
set -euo pipefail
SRC=${1:?git url}; REF=${2:?sha}
ROOT=$(mktemp -d -p "$HOME/.hermes/cache/scratch" e2e-XXXX)
export HERMES_HOME=$ROOT/hermes FAKEHOME=$ROOT/home
mkdir -p "$HERMES_HOME" "$FAKEHOME" "$ROOT/bin"
HERMES_PY=$HOME/.hermes/hermes-agent/venv/bin/python
TOKEN="pst_$(printf 'e%.0s' $(seq 64))::E2EKEY"

# fake pass-cli from the plugin's own test fixture
"$HERMES_PY" - "$ROOT/bin/pass-cli" <<EOF
import importlib.util, sys, pathlib, json
spec = importlib.util.spec_from_file_location("c", "$PWD/tests/conftest.py")
src = pathlib.Path("$PWD/tests/conftest.py").read_text()
fake = src.split("FAKE = r'''", 1)[1].split("'''", 1)[0].format(python=sys.executable)
p = pathlib.Path(sys.argv[1]); p.write_text(fake); p.chmod(0o755)
EOF
cat > "$FAKEHOME/state.json" <<EOF
{"valid_token": "$TOKEN", "items": {"pass://Hermes/OpenAI/password": "sk-e2e-from-proton"},
 "vaults": {"Hermes": {"items": [{"content": {"title": "GROQ_API_KEY", "content": {"Login": {"password": "gsk-e2e"}}, "extra_fields": []}}]}}}
EOF
printf 'OPENAI_API_KEY=stale-dotenv-value\n' > "$HERMES_HOME/.env"
export PATH="$ROOT/bin:$PATH" HOME_ORIG=$HOME
run() { echo "\$ hermes $*"; HOME=$FAKEHOME hermes "$@" 2>&1 | sed 's/^/    /'; }

run plugins install "$SRC" --ref "$REF" --enable
run plugins list | grep -i protonpass || true
run protonpass setup --token "$TOKEN" --vault Hermes
run protonpass set OPENAI_API_KEY "pass://Hermes/OpenAI/password"
run protonpass status
run protonpass sync
run plugins doctor protonpass

echo "--- fresh process, real startup order (dotenv -> plugin discovery -> secret refresh)"
HOME=$FAKEHOME PYTHONPATH=$HOME_ORIG/.hermes/hermes-agent "$HERMES_PY" - <<'EOF'
import os
from hermes_cli.env_loader import load_hermes_dotenv, get_secret_source
load_hermes_dotenv()
print("after dotenv  :", os.environ.get("OPENAI_API_KEY"))
from hermes_cli.plugins import discover_plugins
discover_plugins()
for var in ("OPENAI_API_KEY", "GROQ_API_KEY"):
    print(f"after plugins : {var}={os.environ.get(var)!r} source={get_secret_source(var)!r}")
assert os.environ["OPENAI_API_KEY"] == "sk-e2e-from-proton"
assert os.environ["GROQ_API_KEY"] == "gsk-e2e"
print("E2E OK")
EOF
echo "--- pass-cli calls made:"; python3 -c "import json;[print('   ',' '.join(json.loads(l)['argv'][:2]), '| token-in-env' if json.loads(l)['token'] else '') for l in open('$FAKEHOME/calls.jsonl')]"
echo "--- secrets on disk:"; ls -la "$HERMES_HOME/cache" | sed 's/^/    /'; stat -c '%a %n' "$HERMES_HOME"/cache/protonpass/* 
grep -rl "$TOKEN" "$HERMES_HOME" --exclude=.env && echo "TOKEN LEAKED OUTSIDE .env" || echo "token only in .env: OK"
rm -rf "$ROOT"
