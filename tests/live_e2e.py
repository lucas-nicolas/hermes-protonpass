#!/usr/bin/env python3
"""Opt-in live E2E against a REAL Proton Pass account (not run in CI).

Needs a logged-in `pass-cli` and a sandbox vault you don't mind the test writing to:
    PP_E2E_VAULT=hermes python3 tests/live_e2e.py
Env: PP_E2E_VAULT (default hermes), PASS_CLI (default: PATH), HERMES_SRC (Hermes checkout,
default ~/.hermes/hermes-agent), PP_E2E_SHA (plugin commit to install, default this repo's HEAD).

Never prints secret values or tokens: only booleans, lengths, provenance, call counts.
Creates throwaway items + test tokens and always deletes them (finally:).
"""
import json, os, re, secrets, shutil, stat, subprocess, sys, tempfile, time
from pathlib import Path

PASS = os.environ.get("PASS_CLI") or shutil.which("pass-cli") or "pass-cli"
VAULT = os.environ.get("PP_E2E_VAULT", "hermes")
SHA = os.environ.get("PP_E2E_SHA") or subprocess.check_output(
    ["git", "-C", str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"], text=True).strip()
HERMES_SRC = os.environ.get("HERMES_SRC", str(Path.home() / ".hermes/hermes-agent"))
HERMES_PY = os.environ.get("HERMES_PY", str(Path(HERMES_SRC) / "venv/bin/python"))
ROOT = Path(tempfile.mkdtemp(prefix="pp-live-"))
RUN = secrets.token_hex(3)
ITEM_ENV = "HERMES_PP_E2E"            # env-var-shaped title -> bulk mode picks it up
ITEM_OTHER = "Hermes e2e other"       # not env-shaped -> bulk mode must ignore it
AGENT = f"hermes-e2e-agent-{RUN}"
PAT = f"hermes-e2e-pat-{RUN}"
DUMMY = "e2e-" + secrets.token_urlsafe(24)
DUMMY2 = "e2e-" + secrets.token_urlsafe(24)
results: list[tuple[str, bool, str]] = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""), flush=True)


def pc(*args, env=None, timeout=60):
    return subprocess.run([PASS, *args], capture_output=True, text=True, timeout=timeout,
                          stdin=subprocess.DEVNULL, env=env)


def find(obj, key):
    """All values for `key` anywhere in a JSON structure."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                out.append(v)
            out += find(v, key)
    elif isinstance(obj, list):
        for v in obj:
            out += find(v, key)
    return out


def extract_token(text):
    m = re.search(r"pst_[A-Za-z0-9]+::[A-Za-z0-9_\-+/=]+", text)
    return m.group(0) if m else None


def hermes(home, *args, timeout=300):
    env = {**os.environ, "HERMES_HOME": str(home)}
    return subprocess.run(["hermes", *args], capture_output=True, text=True, timeout=timeout,
                          stdin=subprocess.DEVNULL, env=env)


def make_home(label, cfg, token=None):
    home = ROOT / label / "hermes"
    home.mkdir(parents=True)
    calls = ROOT / label / "calls.log"
    wrapper = ROOT / label / "pass-cli"
    wrapper.write_text(f"#!/bin/sh\necho \"$1 $2\" >> '{calls}'\nexec '{PASS}' \"$@\"\n")
    wrapper.chmod(0o700)
    if token:
        envf = home / ".env"
        envf.write_text(f"PROTON_PASS_PERSONAL_ACCESS_TOKEN={token}\n")
        envf.chmod(0o600)
    r = hermes(home, "plugins", "install", "lucas-nicolas/hermes-protonpass", "--ref", SHA, "--enable")
    check(f"{label}: plugin installed @ {SHA[:7]}", r.returncode == 0, r.stderr.strip()[-120:] if r.returncode else "")
    for section in cfg.values():
        section.setdefault("binary_path", str(wrapper))
        section.setdefault("cache_ttl_seconds", 0)
    code = ("import json,sys\nfrom hermes_cli.config import load_config, save_config\n"
            "c=load_config(); c.setdefault('secrets',{}).update(json.loads(sys.argv[1])); save_config(c)")
    subprocess.run([HERMES_PY, "-c", code, json.dumps(cfg)], check=True,
                   env={**os.environ, "HERMES_HOME": str(home), "PYTHONPATH": HERMES_SRC})
    return home, calls


PROBE = r"""
import json, os, sys, io, contextlib
want = json.loads(sys.argv[1])
err = io.StringIO()
with contextlib.redirect_stderr(err):
    from hermes_cli.env_loader import load_hermes_dotenv, get_secret_source
    load_hermes_dotenv()
    from hermes_cli.plugins import discover_plugins
    discover_plugins()
out = {v: {"present": v in os.environ, "equals": os.environ.get(v) == d, "len": len(os.environ.get(v) or ""),
           "source": get_secret_source(v)} for v, d in want.items()}
lines = [l.strip() for l in err.getvalue().splitlines() if "Proton Pass" in l]
print(json.dumps({"vars": out, "startup": lines}))
"""


def probe(home, want):
    env = {**os.environ, "HERMES_HOME": str(home), "PYTHONPATH": HERMES_SRC}
    env.pop("PROTON_PASS_PERSONAL_ACCESS_TOKEN", None)
    r = subprocess.run([HERMES_PY, "-c", PROBE, json.dumps(want)], capture_output=True, text=True,
                       timeout=300, env=env, stdin=subprocess.DEVNULL)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        print("  probe failed:", (r.stderr or r.stdout)[-400:])
        return {"vars": {}, "startup": []}


def leaked(home, *needles):
    for p in home.rglob("*"):
        if p.is_file() and p.name != ".env":
            try:
                data = p.read_bytes()
            except OSError:
                continue
            if any(n.encode() in data for n in needles if n):
                return str(p.relative_to(home))
    return None


tokens: dict[str, str] = {}
pat_id = None
try:
    print(f"pass-cli: {pc('--version').stdout.strip()}   plugin: {SHA[:7]}   run: {RUN}")
    # ---------------------------------------------------------------- fixtures
    print("\n== fixtures (sandbox vault 'hermes')")
    r1 = pc("item", "create", "login", "--vault-name", VAULT, "--title", ITEM_ENV, "--username", "e2e", "--password", DUMMY)
    r2 = pc("item", "create", "login", "--vault-name", VAULT, "--title", ITEM_OTHER, "--username", "e2e", "--password", DUMMY2)
    check("created 2 throwaway items", r1.returncode == 0 and r2.returncode == 0, (r1.stderr + r2.stderr).strip()[-160:])
    raw = pc("item", "view", "--", f"pass://{VAULT}/{ITEM_ENV}/password")
    check("pass-cli item view (3-segment URI) prints exactly the raw field value",
          raw.returncode == 0 and raw.stdout.rstrip("\r\n") == DUMMY,
          f"exit={raw.returncode} len={len(raw.stdout.rstrip())} want={len(DUMMY)}")

    mapped = {"PP_E2E_MAPPED": f"pass://{VAULT}/{ITEM_ENV}/password"}

    # ---------------------------------------------------------- phase 1: own session
    print("\n== phase 1: own `pass-cli login` session, no token")
    home1, calls1 = make_home("own", {"protonpass": {"enabled": True, "env": dict(mapped)},
                                      "protonpass_vault": {"enabled": True, "vault": VAULT}})
    p = probe(home1, {"PP_E2E_MAPPED": DUMMY, ITEM_ENV: DUMMY, "HERMES_E2E_OTHER": DUMMY2})
    v = p["vars"]
    check("mapped ref resolved in fresh process", v.get("PP_E2E_MAPPED", {}).get("equals"), str(v.get("PP_E2E_MAPPED")))
    check("provenance = protonpass", v.get("PP_E2E_MAPPED", {}).get("source") == "protonpass")
    check("bulk: env-titled item injected, provenance = protonpass_vault",
          v.get(ITEM_ENV, {}).get("equals") and v.get(ITEM_ENV, {}).get("source") == "protonpass_vault", str(v.get(ITEM_ENV)))
    check("bulk: non-env-titled item ignored", not v.get("HERMES_E2E_OTHER", {}).get("present"))
    check("startup lines", any("applied" in l for l in p["startup"]), " | ".join(p["startup"]))
    check("own-session mode never logs in", "login" not in calls1.read_text().split(), calls1.read_text().split().count("login"))
    s = hermes(home1, "protonpass", "sync")
    check("`hermes protonpass sync` dry run lists both vars, no values",
          s.returncode == 0 and "PP_E2E_MAPPED" in s.stdout and ITEM_ENV in s.stdout and DUMMY not in s.stdout + s.stderr)
    check("no value written to disk (cache off)", leaked(home1, DUMMY) is None, leaked(home1, DUMMY) or "")

    # ---------------------------------------------------------- phase 2: AI-agent token
    print("\n== phase 2: AI-agent token (1d, vault 'hermes' only)")
    a = pc("agent", "create", AGENT, "--expiration", "1d", "--vault", VAULT)
    tokens["agent"] = extract_token(a.stdout)
    check("agent token created", a.returncode == 0 and tokens["agent"], a.stderr.strip()[-160:])
    home2, calls2 = make_home("agent", {"protonpass": {"enabled": True, "env": dict(mapped)},
                                        "protonpass_vault": {"enabled": True, "vault": VAULT}}, tokens["agent"])
    p = probe(home2, {"PP_E2E_MAPPED": DUMMY})
    v = p["vars"]
    check("agent token: mapped ref resolved", v.get("PP_E2E_MAPPED", {}).get("equals"), str(v.get("PP_E2E_MAPPED")))
    check("agent token: bulk refused with actionable hint",
          any("agent" in l.lower() and "mapped" in l.lower() for l in p["startup"]), " | ".join(p["startup"])[-300:])
    sess = list((home2 / "cache" / "protonpass").glob("*"))
    check("plugin-owned session dir created, 0700",
          len(sess) == 1 and stat.S_IMODE(sess[0].stat().st_mode) == 0o700, str([x.name for x in sess]))
    logins_before = calls2.read_text().split().count("login")
    probe(home2, {"PP_E2E_MAPPED": DUMMY})
    logins_after = calls2.read_text().split().count("login")
    check("session reused by a second Hermes process (no new login)", logins_after == logins_before,
          f"logins {logins_before} -> {logins_after}")
    time.sleep(3)
    mon = pc("agent", "monitor", AGENT, "--output", "json")
    reasons = sorted(set(str(x) for x in find(json.loads(mon.stdout or "{}"), "reason"))) if mon.returncode == 0 else []
    check("Proton audit log records Hermes' per-variable reason",
          any("Hermes startup: load PP_E2E_MAPPED" in r for r in reasons), f"reasons={reasons[:3]} exit={mon.returncode} {mon.stderr.strip()[-120:]}")
    check("token never written outside .env", leaked(home2, tokens["agent"]) is None, leaked(home2, tokens["agent"]) or "")
    check("token never on pass-cli argv", tokens["agent"] not in calls2.read_text())

    # ---------------------------------------------------------- phase 3: plain PAT
    print("\n== phase 3: personal access token (1d, viewer on 'hermes')")
    c = pc("pat", "create", "--name", PAT, "--expiration", "1d", "--output", "json")
    tokens["pat"] = extract_token(c.stdout)
    try:
        ids = find(json.loads(c.stdout), "pat_id") + find(json.loads(c.stdout), "id")
        pat_id = next((i for i in ids if isinstance(i, str)), None)
    except ValueError:
        pass
    g = pc("pat", "access", "grant", "--personal-access-token-name", PAT, "--vault-name", VAULT, "--role", "viewer")
    check("PAT created + granted viewer on vault", c.returncode == 0 and tokens["pat"] and g.returncode == 0,
          (c.stderr + g.stderr).strip()[-160:])
    home3, calls3 = make_home("pat", {"protonpass": {"enabled": True, "env": dict(mapped)},
                                      "protonpass_vault": {"enabled": True, "vault": VAULT}}, tokens["pat"])
    p = probe(home3, {"PP_E2E_MAPPED": DUMMY, ITEM_ENV: DUMMY, "HERMES_E2E_OTHER": DUMMY2})
    v = p["vars"]
    check("PAT: mapped ref resolved", v.get("PP_E2E_MAPPED", {}).get("equals"), str(v.get("PP_E2E_MAPPED")))
    check("PAT: bulk vault injected", v.get(ITEM_ENV, {}).get("equals") and v.get(ITEM_ENV, {}).get("source") == "protonpass_vault",
          str(v.get(ITEM_ENV)))
    check("PAT: non-env item ignored", not v.get("HERMES_E2E_OTHER", {}).get("present"))
    check("PAT: token never on argv / never outside .env",
          tokens["pat"] not in calls3.read_text() and leaked(home3, tokens["pat"]) is None)
    bad = hermes(home3, "protonpass", "token", "--token", "pst_" + "x" * 64 + "::BADKEY")
    check("`hermes protonpass token` rejects a bad token and keeps the old one",
          bad.returncode == 1 and tokens["pat"] in (home3 / ".env").read_text(), bad.stdout.strip()[-120:])
finally:
    print("\n== cleanup")
    if AGENT:
        pc("agent", "delete", AGENT)
    if pat_id:
        pc("pat", "delete", f"--personal-access-token-id={pat_id}")
    else:  # find it by name
        lst = pc("pat", "list", "--output", "json")
        try:
            for t in (json.loads(lst.stdout) if lst.stdout.strip() else []):
                if isinstance(t, dict) and t.get("name") == PAT:
                    pc("pat", "delete", f"--personal-access-token-id={t.get('pat_id') or t.get('id')}")
        except ValueError:
            pass
    for title in (ITEM_ENV, ITEM_OTHER):
        pc("item", "trash", "--vault-name", VAULT, "--item-title", title)
    trashed = pc("item", "list", "--filter-state", "trashed", "--output", "json", "--", VAULT)
    try:
        data = json.loads(trashed.stdout or "{}")
        for it in (data.get("items", data) if isinstance(data, dict) else data):
            title = it.get("title") or (it.get("content") or {}).get("title")  # plain list: top-level title
            if title in (ITEM_ENV, ITEM_OTHER):  # ids can start with "-": always use --flag=value
                pc("item", "delete", f"--share-id={it['share_id']}", f"--item-id={it['id']}")
    except (ValueError, IndexError, TypeError):
        pass
    left_items = pc("item", "list", "--filter-state", "active", "--output", "json", "--", VAULT).stdout
    left_trash = pc("item", "list", "--filter-state", "trashed", "--output", "json", "--", VAULT).stdout
    agents = pc("agent", "list", "--output", "json").stdout
    pats = pc("pat", "list", "--output", "json").stdout
    check("cleanup: test items gone (active + trash)", ITEM_ENV not in left_items + left_trash and ITEM_OTHER not in left_items + left_trash)
    check("cleanup: test agent + PAT deleted", AGENT not in agents and PAT not in pats)
    shutil.rmtree(ROOT, ignore_errors=True)
    check("cleanup: isolated HERMES_HOMEs removed", not ROOT.exists())
    fails = [n for n, ok, _ in results if not ok]
    print(f"\nRESULT: {len(results) - len(fails)}/{len(results)} passed" + (f"; FAILED: {fails}" if fails else ""))
    sys.exit(1 if fails else 0)
