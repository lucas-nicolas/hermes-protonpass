"""``hermes protonpass <verb>`` — same verbs as ``hermes secrets onepassword``.

Config lives under ``secrets.protonpass`` (mapped) and ``secrets.protonpass_vault`` (bulk);
the token lives in ``~/.hermes/.env``. Values are never printed.
"""

from __future__ import annotations

import argparse
import getpass
import os
import shutil
import sys
import tempfile
from pathlib import Path

from . import protonpass as pp


def _home() -> Path:
    from hermes_constants import get_hermes_home
    return Path(get_hermes_home())


def _config() -> dict:
    from hermes_cli.config import load_config
    return load_config()


def _save(cfg: dict) -> None:
    from hermes_cli.config import save_config
    save_config(cfg)


def _section(cfg: dict, name: str = "protonpass") -> dict:
    secrets = cfg.setdefault("secrets", {})
    if not isinstance(secrets.get(name), dict):
        secrets[name] = {}
    return secrets[name]


def _secret(name: str) -> str:
    try:
        from agent.secret_scope import get_secret
        return (get_secret(name) or "").strip()
    except ImportError:  # pragma: no cover - older Hermes
        return os.environ.get(name, "").strip()


def _version(binary: Path) -> str:
    try:
        proc = pp.run_secret_cli([str(binary), "--version"], timeout=10)
        return (proc.stdout or proc.stderr).strip().splitlines()[0][:60] if proc.returncode == 0 else "?"
    except (RuntimeError, IndexError):
        return "?"


def _check_token(binary: Path, token: str) -> tuple[bool, str]:
    """Log in with ``token`` in a throwaway session dir and run ``info``; nothing persists."""
    scratch = _home() / "cache"
    scratch.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="protonpass-verify-", dir=scratch))
    try:
        session = pp.PassSession(binary, token, tmp)
        with session.open():
            proc = session.run("info")
            session.run("logout", "--force")
        return proc.returncode == 0, pp._detail(proc)
    except pp.PassCliError as exc:
        return False, str(exc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _user_session(binary: Path) -> bool:
    try:
        return pp.PassSession(binary, "", _home()).run("info").returncode == 0
    except pp.PassCliError:
        return False


def _store_token(binary: Path, env_name: str, token: str, verify: bool) -> bool:
    if verify:
        ok, detail = _check_token(binary, token)
        if not ok:
            print(f"✗ Proton Pass rejected the token — nothing was changed. {detail}")
            return False
        print("✓ token accepted by Proton Pass")
    from hermes_cli.config import get_env_path, save_env_value
    save_env_value(env_name, token)
    os.environ[env_name] = token
    shutil.rmtree(_home() / "cache" / "protonpass", ignore_errors=True)  # old-token sessions
    pp.clear_caches(_home())
    print(f"✓ stored as {env_name} in {get_env_path()}")
    return True


# -- verbs ---------------------------------------------------------------------------------


def cmd_setup(args) -> int:
    cfg = _config()
    sec = _section(cfg)
    binary_path = (args.binary_path or sec.get("binary_path") or "").strip()
    binary = pp.find_pass_cli(binary_path)
    if binary is None:
        print(f"✗ pass-cli not found{f' at {binary_path}' if binary_path else ' on PATH'}. Install: {pp.DOCS_URL}")
        return 1
    print(f"✓ pass-cli {binary} ({_version(binary)})")
    if args.binary_path:
        sec["binary_path"] = binary_path
    token_env = (args.token_env or sec.get("token_env") or pp.DEFAULT_TOKEN_ENV).strip()
    sec["token_env"] = token_env
    if args.token:
        if not _store_token(binary, token_env, args.token.strip(), verify=True):
            return 1
    elif _secret(token_env):
        print(f"✓ personal access token found in {token_env}")
    elif _user_session(binary):
        print("✓ no token set; using your existing `pass-cli login` session (not available to cron/gateway "
              "unless they share it)")
    else:
        print(f"! no token in {token_env} and no pass-cli session: run `hermes protonpass token` "
              "or `pass-cli login`")
    sec["enabled"] = True
    sec.setdefault("env", {})
    sec.setdefault("cache_ttl_seconds", 300)
    sec.setdefault("override_existing", True)
    if args.vault:
        vault = _section(cfg, "protonpass_vault")
        vault.update(enabled=True, vault=args.vault.strip(), field=(args.field or "password").strip(),
                     token_env=token_env)
        print(f"✓ bulk source enabled for vault {vault['vault']!r} (field {vault['field']!r})")
    _save(cfg)
    print('✓ Proton Pass enabled. Map a key: hermes protonpass set OPENAI_API_KEY "pass://Vault/Item/field"')
    return 0


def cmd_status(args) -> int:
    cfg = _config().get("secrets") or {}
    sec = cfg.get("protonpass") if isinstance(cfg.get("protonpass"), dict) else {}
    bulk = cfg.get("protonpass_vault") if isinstance(cfg.get("protonpass_vault"), dict) else {}
    token_env = sec.get("token_env") or pp.DEFAULT_TOKEN_ENV
    binary = pp.find_pass_cli(str(sec.get("binary_path") or ""))
    has_token = bool(_secret(token_env))
    rows = [("Enabled (mapped)", bool(sec.get("enabled"))),
            ("Enabled (vault)", f"{bool(bulk.get('enabled'))} {bulk.get('vault') or ''}".strip()),
            ("pass-cli", f"{binary} ({_version(binary)})" if binary else "NOT FOUND"),
            ("Token env var", token_env), ("Token set", has_token),
            ("Override existing", bool(sec.get("override_existing", True))),
            ("Cache TTL (s)", sec.get("cache_ttl_seconds", 300))]
    if binary and not has_token:
        rows.append(("pass-cli session", "active" if _user_session(binary) else "none"))
    for key, value in rows:
        print(f"  {key:<18} {value}")
    refs = sec.get("env") if isinstance(sec.get("env"), dict) else {}
    for name in sorted(refs):
        print(f"  {name:<30} {refs[name]}")
    if not refs:
        print('  no references mapped: hermes protonpass set ENV_VAR "pass://Vault/Item/field"')
    return 0


def cmd_token(args) -> int:
    sec = _section(_config())
    binary = pp.find_pass_cli(str(sec.get("binary_path") or ""))
    if binary is None and not args.no_verify:
        print(f"✗ pass-cli not found; install it ({pp.DOCS_URL}) or use --no-verify")
        return 1
    token = (args.token or "").strip()
    if not token:
        if not sys.stdin.isatty():
            print("✗ no TTY: pass the token with --token")
            return 1
        print("Create one with: pass-cli pat create --name hermes --expiration 3m  (then grant vault access)")
        token = getpass.getpass("Personal access token: ").strip()
    if not token:
        print("✗ empty token — nothing changed")
        return 1
    return 0 if _store_token(binary, sec.get("token_env") or pp.DEFAULT_TOKEN_ENV, token, not args.no_verify) else 1


def cmd_set(args) -> int:
    valid, warnings = pp.validate_refs({args.env_var: args.reference})
    if args.env_var not in valid:
        print("✗ " + "; ".join(warnings))
        return 1
    cfg = _config()
    sec = _section(cfg)
    if not isinstance(sec.get("env"), dict):
        sec["env"] = {}
    sec["env"][args.env_var] = valid[args.env_var]
    _save(cfg)
    print(f"✓ {args.env_var} -> {valid[args.env_var]}" + ("" if sec.get("enabled") else
          "  (integration disabled: run `hermes protonpass setup`)"))
    return 0


def cmd_remove(args) -> int:
    cfg = _config()
    env_map = _section(cfg).get("env")
    if not isinstance(env_map, dict) or args.env_var not in env_map:
        print(f"! {args.env_var} is not mapped")
        return 1
    del env_map[args.env_var]
    _save(cfg)
    print(f"✓ removed {args.env_var}")
    return 0


def cmd_sync(args) -> int:
    """Dry-run: resolve now (cache bypassed) and show what startup would apply. Never prints values."""
    cfg = _config().get("secrets") or {}
    sources = [s for s in (pp.ProtonPassSource(), pp.ProtonPassVaultSource())
               if s.is_enabled(cfg.get(s.name) if isinstance(cfg.get(s.name), dict) else {})]
    if not sources:
        print("! Proton Pass is disabled: run `hermes protonpass setup`")
        return 1
    status = 0
    for source in sources:
        section = dict(cfg.get(source.name), cache_ttl_seconds=0)
        result = source.fetch(section, _home())
        print(f"[{source.name}]")
        if result.error:
            print(f"  ✗ {result.error}\n  → {source.remediation(result.error_kind, section)}")
            status = 1
            continue
        override = source.override_existing(section)
        for name in sorted(result.secrets):
            present = bool(os.environ.get(name))
            action = "skip (already set)" if present and not override else \
                "would export" + (" (overrides)" if present else "")
            print(f"  {name:<30} {action}")
        for warning in result.warnings:
            print(f"  ! {warning}")
    return status


def cmd_disable(args) -> int:
    cfg = _config()
    for name in ("protonpass", "protonpass_vault"):
        if isinstance((cfg.get("secrets") or {}).get(name), dict):
            cfg["secrets"][name]["enabled"] = False
    _save(cfg)
    print("✓ disabled; mappings kept in config.yaml")
    return 0


def register_cli(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="protonpass_command", metavar="<command>")
    verbs = (
        ("setup", "Find pass-cli, store/verify a token, enable", cmd_setup, (
            ("--token", "Personal access token to verify and store in .env"),
            ("--token-env", f"Env var holding the token (default {pp.DEFAULT_TOKEN_ENV})"),
            ("--binary-path", "Absolute path to pass-cli (skips PATH lookup)"),
            ("--vault", "Also inject every env-var-titled item of this vault (bulk source)"),
            ("--field", "Field used by the bulk source (default password)"))),
        ("status", "Show config, pass-cli, auth and references", cmd_status, ()),
        ("token", "Rotate the personal access token (verified before saving)", cmd_token, (
            ("--token", "New token (default: masked prompt)"),
            ("--no-verify", None))),
        ("set", "Map ENV_VAR to a pass://vault/item/field reference", cmd_set, (
            ("env_var", "Environment variable, e.g. OPENAI_API_KEY"),
            ("reference", "pass://vault/item/field"))),
        ("remove", "Remove a mapping", cmd_remove, (("env_var", "Environment variable to unmap"),)),
        ("sync", "Dry-run: resolve now and show what would apply", cmd_sync, ()),
        ("disable", "Turn both Proton Pass sources off", cmd_disable, ()),
    )
    for name, help_text, func, arguments in verbs:
        p = sub.add_parser(name, help=help_text, description=help_text)
        for flag, flag_help in arguments:
            if flag_help is None:
                p.add_argument(flag, action="store_true", help="Store without verifying (not recommended)")
            else:
                p.add_argument(flag, help=flag_help)
        p.set_defaults(func=func)
    parser.set_defaults(func=lambda args: (parser.print_help(), 0)[1])
