"""Load the plugin as a package, ship a fake ``pass-cli``, and expose Hermes' conformance kit."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_plugin():
    spec = importlib.util.spec_from_file_location(
        "protonpass_plugin", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec)
    sys.modules["protonpass_plugin"] = module
    spec.loader.exec_module(module)
    return module


plugin = _load_plugin()

FAKE = r'''#!{python}
"""Fake pass-cli mirroring verified 2.1.2 behaviour. State: $HOME/state.json, log: $HOME/calls.jsonl."""
import json, os, sys
from pathlib import Path

home = Path(os.environ["HOME"])
state = json.loads((home / "state.json").read_text())
argv = sys.argv[1:]
with open(home / "calls.jsonl", "a") as fh:
    fh.write(json.dumps({{"argv": argv, "env": sorted(os.environ),
                         "token": os.environ.get("PROTON_PASS_PERSONAL_ACCESS_TOKEN"),
                         "reason": os.environ.get("PROTON_PASS_AGENT_REASON"),
                         "session_dir": os.environ.get("PROTON_PASS_SESSION_DIR"),
                         "key_provider": os.environ.get("PROTON_PASS_KEY_PROVIDER")}}) + "\n")
root = Path(os.environ.get("PROTON_PASS_SESSION_DIR") or home / ".local/share/proton-pass-cli")
session = root / ".session" / "ok"
NO_SESSION = ("2026-10-14T22:26:00.890790Z ERROR pass-cli/src/main.rs:329: Command is not logout there is no "
              "session\nError: This operation requires an authenticated client\n")

def die(msg, code=1):
    sys.stderr.write(msg); sys.exit(code)

if argv[:1] == ["--version"]:
    print("Proton Pass CLI 2.1.2 (fake)"); sys.exit(0)
if argv[:1] == ["logout"]:
    if session.exists(): session.unlink()
    print("Successfully performed force logout"); sys.exit(0)
if argv[:1] == ["login"]:
    if "--pat" in argv: die("token on argv is forbidden in tests\n", 9)
    if os.environ.get("PROTON_PASS_PERSONAL_ACCESS_TOKEN") != state["valid_token"]:
        leak = f" (token {{os.environ.get('PROTON_PASS_PERSONAL_ACCESS_TOKEN')}})" if state.get("leak") else ""
        die("Error: Error in personal access token login flow\n\nCaused by:\n    0: Error creating personal "
            "access token session\n    1: Invalid personal access token format" + leak + "\n")
    session.parent.mkdir(parents=True, exist_ok=True); session.write_text("1"); sys.exit(0)
if not session.exists():
    die(NO_SESSION)
if state.get("expire_next"):
    state["expire_next"] = False; (home / "state.json").write_text(json.dumps(state)); session.unlink()
    die(NO_SESSION)
if argv[:1] == ["info"]:
    print("Personal Access Token: hermes"); sys.exit(0)
if argv[:2] == ["item", "view"]:
    if state.get("agent") and not os.environ.get("PROTON_PASS_AGENT_REASON"):
        die("Error: an agent reason is required\n")
    ref = argv[argv.index("--") + 1]
    if ref not in state["items"]: die(f"Error: item not found for {{ref}}\n")
    print(state["items"][ref]); sys.exit(0)
if argv[:2] == ["item", "list"]:
    if state.get("agent") and "--show-secrets" in argv:
        die("Error: --show-secrets is not allowed with agent sessions\n")
    vault = argv[argv.index("--") + 1]
    if vault not in state["vaults"]: die(f"Error: vault {{vault}} not found\n")
    print(json.dumps(state["vaults"][vault])); sys.exit(0)
die(f"unexpected argv {{argv}}\n", 2)
'''

GOOD_TOKEN = "pst_" + "a" * 64 + "::KEY"


def _item(title, typed=None, extra=None):
    return {"content": {"title": title, "content": {"Login": typed or {}},
                        "extra_fields": [{"name": k, "content": {"Hidden": v}} for k, v in (extra or {}).items()]}}


class FakePass:
    def __init__(self, home: Path, binary: Path):
        self.home, self.binary = home, binary
        self.state = {"valid_token": GOOD_TOKEN, "items": {}, "vaults": {}}
        self.save()

    def save(self):
        (self.home / "state.json").write_text(json.dumps(self.state))

    def set(self, **kw):
        self.state.update(kw)
        self.save()

    def calls(self):
        path = self.home / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def verbs(self):
        return [" ".join(c["argv"][:2]) if c["argv"][:1] == ["item"] else c["argv"][0] for c in self.calls()]


@pytest.fixture
def fake(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    binary = tmp_path / "bin" / "pass-cli"
    binary.parent.mkdir()
    binary.write_text(FAKE.format(python=sys.executable))
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{binary.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.delenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("PROTON_PASS_SESSION_DIR", raising=False)
    plugin.protonpass._MEMORY_CACHE.clear()
    fake = FakePass(home, binary)
    fake.item = _item
    return fake


@pytest.fixture
def hermes_home(tmp_path):
    path = tmp_path / "hermes"
    path.mkdir()
    return path


def load_conformance():
    """Hermes ships its conformance kit only in the source tree (tests/secret_sources)."""
    import agent

    kit = Path(agent.__file__).resolve().parents[1] / "tests" / "secret_sources" / "conformance.py"
    if not kit.exists():
        return None
    spec = importlib.util.spec_from_file_location("hermes_secret_source_conformance", kit)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
