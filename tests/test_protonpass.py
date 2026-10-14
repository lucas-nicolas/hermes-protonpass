"""Behavioural tests against a fake pass-cli (see conftest.FAKE)."""

from __future__ import annotations

import os
import stat

import pytest

from conftest import GOOD_TOKEN, load_conformance, plugin

pp = plugin.protonpass
ErrorKind = pp.ErrorKind
REF = "pass://Vault/OpenAI/password"


def _cfg(**kw):
    return {"enabled": True, "env": {"OPENAI_API_KEY": REF}, **kw}


def _pat(monkeypatch, token=GOOD_TOKEN):
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", token)


# -- mapped source ----------------------------------------------------------------------------


def test_pat_login_then_read(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk-live"})
    _pat(monkeypatch)
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-leak")
    result = pp.ProtonPassSource().fetch(_cfg(), hermes_home)
    assert result.ok and result.secrets == {"OPENAI_API_KEY": "sk-live"}
    calls = fake.calls()
    assert fake.verbs() == ["logout", "login", "item view"]
    for call in calls:
        assert GOOD_TOKEN not in call["argv"], "token must never be on argv"
        assert "UNRELATED_SECRET" not in call["env"], "child env must be allowlisted"
        assert call["session_dir"].startswith(str(hermes_home / "cache" / "protonpass"))
        assert call["key_provider"] == "fs"
    assert [c["token"] is not None for c in calls] == [False, True, False], "token only reaches login"
    assert calls[-1]["argv"] == ["item", "view", "--", REF]
    assert calls[-1]["reason"] == "Hermes startup: load OPENAI_API_KEY"
    session_dir = hermes_home / "cache" / "protonpass"
    assert stat.S_IMODE(next(session_dir.iterdir()).stat().st_mode) == 0o700


def test_session_reused_across_fetches(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk"})
    _pat(monkeypatch)
    pp.ProtonPassSource().fetch(_cfg(cache_ttl_seconds=0), hermes_home)
    pp.ProtonPassSource().fetch(_cfg(cache_ttl_seconds=0), hermes_home)
    assert fake.verbs().count("login") == 1


def test_expired_session_relogs_once(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk"})
    _pat(monkeypatch)
    pp.ProtonPassSource().fetch(_cfg(cache_ttl_seconds=0), hermes_home)
    fake.set(expire_next=True)
    result = pp.ProtonPassSource().fetch(_cfg(cache_ttl_seconds=0), hermes_home)
    assert result.ok and result.secrets == {"OPENAI_API_KEY": "sk"}
    assert fake.verbs().count("login") == 2


def test_bad_token_is_auth_failed(fake, hermes_home, monkeypatch):
    fake.set(leak=True)  # even if pass-cli echoed the token, Hermes must not surface it
    _pat(monkeypatch, "pst_wrong::KEY")
    result = pp.ProtonPassSource().fetch(_cfg(), hermes_home)
    assert result.error_kind == ErrorKind.AUTH_FAILED and not result.secrets
    assert "pst_wrong" not in result.error and "<redacted>" in result.error
    assert "hermes protonpass token" in pp.ProtonPassSource().remediation(result.error_kind, {})
    assert not (hermes_home / "cache" / "protonpass_cache.json").exists()


def test_user_session_mode_never_logs_in(fake, hermes_home):
    fake.set(items={REF: "sk"})
    no_session = pp.ProtonPassSource().fetch(_cfg(cache_ttl_seconds=0), hermes_home)
    assert not no_session.secrets and "authenticated client" in no_session.warnings[0]
    assert "2026-10-14T" not in no_session.warnings[0], "pass-cli log lines are stripped"
    (fake.home / ".local/share/proton-pass-cli/.session").mkdir(parents=True)
    (fake.home / ".local/share/proton-pass-cli/.session/ok").write_text("1")
    result = pp.ProtonPassSource().fetch(_cfg(cache_ttl_seconds=0), hermes_home)
    assert result.secrets == {"OPENAI_API_KEY": "sk"}
    assert "login" not in fake.verbs() and all(c["session_dir"] is None for c in fake.calls())


def test_agent_token_reads_carry_reason(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk"}, agent=True)
    _pat(monkeypatch)
    assert pp.ProtonPassSource().fetch(_cfg(), hermes_home).secrets == {"OPENAI_API_KEY": "sk"}


def test_partial_failure_warns_and_skips_cache(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk", "pass://V/Empty/password": ""})
    _pat(monkeypatch)
    cfg = _cfg(env={"OPENAI_API_KEY": REF, "MISSING": "pass://V/Nope/password", "EMPTY": "pass://V/Empty/password"})
    result = pp.ProtonPassSource().fetch(cfg, hermes_home)
    assert result.ok and result.secrets == {"OPENAI_API_KEY": "sk"}
    assert len(result.warnings) == 2 and any("empty value" in w for w in result.warnings)
    assert not (hermes_home / "cache" / "protonpass_cache.json").exists()


def test_complete_pull_is_cached(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk"})
    _pat(monkeypatch)
    pp.ProtonPassSource().fetch(_cfg(), hermes_home)
    cache = hermes_home / "cache" / "protonpass_cache.json"
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600 and GOOD_TOKEN not in cache.read_text()
    pp._MEMORY_CACHE.clear()  # force the disk layer
    before = len(fake.calls())
    assert pp.ProtonPassSource().fetch(_cfg(), hermes_home).secrets == {"OPENAI_API_KEY": "sk"}
    assert len(fake.calls()) == before
    _pat(monkeypatch, "pst_other::KEY")  # a different identity never sees cached values
    assert pp.ProtonPassSource().fetch(_cfg(), hermes_home).error_kind == ErrorKind.AUTH_FAILED


def test_ttl_zero_writes_nothing(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk"})
    _pat(monkeypatch)
    pp.ProtonPassSource().fetch(_cfg(cache_ttl_seconds=0), hermes_home)
    assert not (hermes_home / "cache" / "protonpass_cache.json").exists()


@pytest.mark.parametrize("env_map, fragment", [
    ({"OK_NAME": "op://x/y/z"}, "expected pass://"),
    ({"OK_NAME": "pass://onlytwo/parts"}, "expected pass://"),
    ({"OK_NAME": "pass://a//c"}, "expected pass://"),
    ({"1BAD": REF}, "not a valid env-var name"),
    ({"OK_NAME": "pass://a/b\x1b[2J/c"}, "control characters"),
])
def test_invalid_refs_warn(env_map, fragment):
    valid, warnings = pp.validate_refs(env_map)
    assert not valid and fragment in warnings[0]


def test_refs_with_names_and_spaces_are_valid():
    valid, _ = pp.validate_refs({"K": "  pass://My Vault/My Item/api key  "})
    assert valid == {"K": "pass://My Vault/My Item/api key"}


def test_flag_like_ref_stays_after_terminator(fake, hermes_home, monkeypatch):
    ref = "pass://--help/x/y"
    fake.set(items={ref: "v"})
    _pat(monkeypatch)
    assert pp.ProtonPassSource().fetch(_cfg(env={"K": ref}), hermes_home).secrets == {"K": "v"}
    assert fake.calls()[-1]["argv"][-2:] == ["--", ref]


def test_empty_map_not_configured(hermes_home):
    result = pp.ProtonPassSource().fetch({"enabled": True}, hermes_home)
    assert result.error_kind == ErrorKind.NOT_CONFIGURED


def test_missing_binary(hermes_home, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert pp.ProtonPassSource().fetch(_cfg(), hermes_home).error_kind == ErrorKind.BINARY_MISSING
    pinned = pp.ProtonPassSource().fetch(_cfg(binary_path=str(tmp_path / "nope")), hermes_home)
    assert pinned.error_kind == ErrorKind.BINARY_MISSING and "binary_path" in pinned.error


def test_pinned_binary_skips_path(fake, hermes_home, monkeypatch, tmp_path):
    fake.set(items={REF: "sk"})
    _pat(monkeypatch)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = pp.ProtonPassSource().fetch(_cfg(binary_path=str(fake.binary)), hermes_home)
    assert result.secrets == {"OPENAI_API_KEY": "sk"} and result.binary_path == fake.binary


def test_token_var_is_protected_and_never_fetched(fake, hermes_home, monkeypatch):
    source = pp.ProtonPassSource()
    assert source.protected_env_vars({}) == {"PROTON_PASS_PERSONAL_ACCESS_TOKEN"}
    assert source.protected_env_vars({"token_env": "MY_PAT"}) == {"MY_PAT"}
    assert source.override_existing({}) is True
    _pat(monkeypatch)
    fake.set(items={REF: "clobber"})
    cfg = {"enabled": True, "env": {"PROTON_PASS_PERSONAL_ACCESS_TOKEN": REF}}
    assert not source.fetch(cfg, hermes_home).secrets
    assert "item view" not in fake.verbs(), "the bootstrap token var is never fetched"


def test_custom_token_env(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk"})
    monkeypatch.setenv("MY_PAT", GOOD_TOKEN)
    assert pp.ProtonPassSource().fetch(_cfg(token_env="MY_PAT"), hermes_home).secrets == {"OPENAI_API_KEY": "sk"}
    assert any(c["token"] == GOOD_TOKEN for c in fake.calls())


def test_fetch_never_raises_on_internal_bug(hermes_home, monkeypatch):
    monkeypatch.setattr(pp, "validate_refs", lambda _: 1 / 0)
    result = pp.ProtonPassSource().fetch(_cfg(), hermes_home)
    assert result.error_kind == ErrorKind.INTERNAL


# -- bulk source -----------------------------------------------------------------------------


def _vault(fake, *items):
    fake.set(vaults={"Keys": {"items": list(items)}})


def test_vault_injects_env_titled_items(fake, hermes_home, monkeypatch):
    _vault(fake,
           fake.item("OPENAI_API_KEY", {"password": "sk-1", "username": "me"}),
           fake.item("GROQ_API_KEY", extra={"password": "gsk"}),
           fake.item("My Bank Login", {"password": "nope"}),
           fake.item("NO_PASSWORD", {"username": "x"}),
           fake.item("PROTON_PASS_PERSONAL_ACCESS_TOKEN", {"password": "clobber"}))
    _pat(monkeypatch)
    result = pp.ProtonPassVaultSource().fetch({"enabled": True, "vault": "Keys"}, hermes_home)
    assert result.ok and result.secrets == {"OPENAI_API_KEY": "sk-1", "GROQ_API_KEY": "gsk"}
    assert any("NO_PASSWORD" in w for w in result.warnings)
    assert fake.calls()[-1]["argv"] == ["item", "list", "--filter-state", "active", "--show-secrets",
                                         "--output", "json", "--", "Keys"]
    assert (hermes_home / "cache" / "protonpass_vault_cache.json").exists(), "item notes don't block cache"


def test_vault_custom_field_and_duplicates(fake, hermes_home, monkeypatch):
    _vault(fake, fake.item("TOKEN_A", extra={"api_key": "1"}), fake.item("TOKEN_A", extra={"api_key": "2"}))
    _pat(monkeypatch)
    result = pp.ProtonPassVaultSource().fetch({"enabled": True, "vault": "Keys", "field": "api_key"}, hermes_home)
    assert result.secrets == {"TOKEN_A": "1"} and "duplicate" in result.warnings[0]


def test_vault_agent_token_gets_hint(fake, hermes_home, monkeypatch):
    _vault(fake, fake.item("A_KEY", {"password": "x"}))
    fake.set(agent=True)
    _pat(monkeypatch)
    result = pp.ProtonPassVaultSource().fetch({"enabled": True, "vault": "Keys"}, hermes_home)
    assert not result.ok and "use mapped pass:// refs" in result.error


def test_vault_errors(fake, hermes_home, monkeypatch):
    assert pp.ProtonPassVaultSource().fetch({"enabled": True}, hermes_home).error_kind == ErrorKind.NOT_CONFIGURED
    _pat(monkeypatch)
    missing = pp.ProtonPassVaultSource().fetch({"enabled": True, "vault": "Nope"}, hermes_home)
    assert not missing.ok and "Nope" in missing.error


def test_shared_session_between_sources(fake, hermes_home, monkeypatch):
    fake.set(items={REF: "sk"})
    _vault(fake, fake.item("B_KEY", {"password": "b"}))
    _pat(monkeypatch)
    pp.ProtonPassSource().fetch(_cfg(), hermes_home)
    pp.ProtonPassVaultSource().fetch({"enabled": True, "vault": "Keys"}, hermes_home)
    assert fake.verbs().count("login") == 1


# -- orchestrator + conformance ----------------------------------------------------------------


def test_apply_all_mapped_beats_bulk(fake, hermes_home, monkeypatch):
    from agent.secret_sources import registry

    fake.set(items={REF: "from-mapped"})
    _vault(fake, fake.item("OPENAI_API_KEY", {"password": "from-bulk"}), fake.item("EXTRA_KEY", {"password": "e"}))
    _pat(monkeypatch)
    registry._reset_registry_for_tests()
    monkeypatch.setattr(registry, "_ensure_builtin_sources", lambda: None)
    try:
        assert registry.register_source(pp.ProtonPassSource())
        assert registry.register_source(pp.ProtonPassVaultSource())
        env = {"PROTON_PASS_PERSONAL_ACCESS_TOKEN": GOOD_TOKEN, "OPENAI_API_KEY": "stale"}
        registry.apply_all({"protonpass": _cfg(), "protonpass_vault": {"enabled": True, "vault": "Keys"}},
                           hermes_home, environ=env)
        assert env["OPENAI_API_KEY"] == "from-mapped" and env["EXTRA_KEY"] == "e"
        assert env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == GOOD_TOKEN
    finally:
        registry._reset_registry_for_tests()


def test_register_wires_sources_and_cli():
    seen = {}

    class Ctx:
        def register_secret_source(self, source):
            seen.setdefault("sources", []).append(source.name)

        def register_cli_command(self, **kw):
            seen["cli"] = kw["name"]

    plugin.register(Ctx())
    assert seen == {"sources": ["protonpass", "protonpass_vault"], "cli": "protonpass"}


_kit = load_conformance()
if _kit is not None:
    class TestMappedConformance(_kit.SecretSourceConformance):
        @pytest.fixture
        def source(self):
            return pp.ProtonPassSource()

    class TestVaultConformance(_kit.SecretSourceConformance):
        @pytest.fixture
        def source(self):
            return pp.ProtonPassVaultSource()
else:  # pragma: no cover
    def test_conformance_kit_available():
        pytest.skip("Hermes source tree (tests/secret_sources/conformance.py) not importable")
