"""CLI verbs against a throwaway HERMES_HOME and the fake pass-cli."""

from __future__ import annotations

import argparse

import pytest

from conftest import GOOD_TOKEN, plugin

cli = plugin.cli
REF = "pass://Vault/OpenAI/password"


@pytest.fixture
def home(tmp_path, monkeypatch, fake):
    path = tmp_path / "hermes-home"
    path.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(path))
    return path


def run(*argv):
    parser = argparse.ArgumentParser()
    cli.register_cli(parser)
    args = parser.parse_args(argv)
    return args.func(args)


def secrets_cfg():
    from hermes_cli.config import load_config
    return load_config().get("secrets", {})


def test_setup_verifies_and_stores_token(home, fake, capsys):
    assert run("setup", "--token", GOOD_TOKEN, "--vault", "Keys") == 0
    out = capsys.readouterr().out
    assert GOOD_TOKEN not in out and "token accepted" in out
    assert f"PROTON_PASS_PERSONAL_ACCESS_TOKEN={GOOD_TOKEN}" in (home / ".env").read_text()
    cfg = secrets_cfg()
    assert cfg["protonpass"]["enabled"] is True and cfg["protonpass"]["token_env"] == "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
    assert cfg["protonpass_vault"] == {"enabled": True, "vault": "Keys", "field": "password",
                                       "token_env": "PROTON_PASS_PERSONAL_ACCESS_TOKEN"}
    assert not list((home / "cache").glob("protonpass-verify-*")), "verify session is thrown away"


def test_setup_rejects_bad_token_without_saving(home, fake, capsys):
    assert run("setup", "--token", "pst_bad::KEY") == 1
    assert "rejected" in capsys.readouterr().out
    assert not (home / ".env").exists() or "pst_bad" not in (home / ".env").read_text()
    assert not secrets_cfg().get("protonpass", {}).get("enabled")


def test_setup_without_binary(home, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert run("setup") == 1 and "pass-cli not found" in capsys.readouterr().out


def test_set_remove_roundtrip(home, capsys):
    assert run("set", "OPENAI_API_KEY", f"  {REF} ") == 0
    assert secrets_cfg()["protonpass"]["env"] == {"OPENAI_API_KEY": REF}
    assert run("set", "OPENAI_API_KEY", "op://nope/x/y") == 1
    assert run("remove", "OPENAI_API_KEY") == 0 and secrets_cfg()["protonpass"]["env"] == {}
    assert run("remove", "OPENAI_API_KEY") == 1


def test_status_lists_refs_without_values(home, fake, monkeypatch, capsys):
    fake.set(items={REF: "sk-secret"})
    run("set", "OPENAI_API_KEY", REF)
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", GOOD_TOKEN)
    assert run("status") == 0
    out = capsys.readouterr().out
    assert "OPENAI_API_KEY" in out and REF in out and "sk-secret" not in out and GOOD_TOKEN not in out


def test_sync_dry_run_never_prints_values(home, fake, monkeypatch, capsys):
    fake.set(items={REF: "sk-secret"})
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", GOOD_TOKEN)
    assert run("sync") == 1  # disabled
    run("setup")
    run("set", "OPENAI_API_KEY", REF)
    monkeypatch.setenv("OPENAI_API_KEY", "old")
    capsys.readouterr()
    assert run("sync") == 0
    out = capsys.readouterr().out
    assert "OPENAI_API_KEY" in out and "would export (overrides)" in out and "sk-secret" not in out
    assert not (home / "cache" / "protonpass_cache.json").exists(), "sync bypasses the cache"


def test_token_rotation_clears_old_sessions_and_cache(home, fake, monkeypatch, capsys):
    stale = home / "cache" / "protonpass" / "oldfp"
    stale.mkdir(parents=True)
    (home / "cache" / "protonpass_cache.json").write_text("{}")
    assert run("token", "--token", GOOD_TOKEN) == 0
    assert not stale.exists() and not (home / "cache" / "protonpass_cache.json").exists()
    assert run("token", "--token", "pst_bad::KEY") == 1
    assert "pst_bad" not in (home / ".env").read_text()
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert run("token") == 1 and "--token" in capsys.readouterr().out


def test_disable_keeps_mappings(home, fake):
    run("setup", "--vault", "Keys")
    run("set", "A_KEY", REF)
    assert run("disable") == 0
    cfg = secrets_cfg()
    assert cfg["protonpass"]["enabled"] is False and cfg["protonpass_vault"]["enabled"] is False
    assert cfg["protonpass"]["env"] == {"A_KEY": REF}
