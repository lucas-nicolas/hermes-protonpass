"""Proton Pass (``pass-cli``) secret sources for Hermes.

Two sources share one pass-cli session:

* ``protonpass`` (mapped): ``secrets.protonpass.env`` binds ENV_VAR -> ``pass://vault/item/field``;
  each ref is read with ``pass-cli item view -- <ref>``.
* ``protonpass_vault`` (bulk): every item in one vault whose *title* is a valid env-var name
  contributes its ``field`` (default ``password``), like a Bitwarden Secrets Manager project.

Auth: with a personal access token or AI-agent token (``PROTON_PASS_PERSONAL_ACCESS_TOKEN`` by
default) the plugin logs in non-interactively into a session dir it owns
(``<home>/cache/protonpass/<fp>``, 0700); the token is only ever passed through the ``login``
child's environment, never argv. Every read carries ``PROTON_PASS_AGENT_REASON`` so agent tokens
record *which Hermes variable* read an item in Proton's audit log. Without a token it uses the
user's existing ``pass-cli login`` session and never authenticates itself.
Fetches never raise or prompt; complete pulls are cached (values only, 0600) for ``cache_ttl_seconds``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Iterator, Optional

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource, is_valid_env_name, run_secret_cli

try:  # per-fetch env view (profile multiplexing); older Hermes reads os.environ directly
    from agent.secret_sources.base import get_source_environment
except ImportError:  # pragma: no cover
    def get_source_environment():
        return os.environ

DEFAULT_TOKEN_ENV = "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
DOCS_URL = "https://protonpass.github.io/pass-cli/"
CLI_TIMEOUT = 30.0
SESSION_MAX_AGE = 110 * 60  # PAT sessions live 2 h; re-login a little early
LOCK_TIMEOUT = 60.0
_LOGIN_MARKER = ".hermes-login"
# Passed through when set: pass-cli tuning knobs, never credentials.
_ALLOW_ENV = ("PROTON_PASS_KEY_PROVIDER", "PROTON_PASS_LINUX_KEYRING", "PROTON_PASS_DISABLE_TELEMETRY",
              "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "APPDATA", "LOCALAPPDATA")
# pass-cli 2.1.2: "This operation requires an authenticated client" / "there is no session" /
# "Error in personal access token login flow"; the rest cover expiry and HTTP auth codes.
_AUTH_MARKERS = ("authenticated client", "no session", "not logged", "login flow", "access token",
                 "session expired", "expired", "unauthor", "401", "403")
_NETWORK_MARKERS = ("network", "connection", "resolve host", "dns", "timed out reaching")
_LOG_LINE = re.compile(r"^\d{4}-\d\d-\d\dT\S+\s+(TRACE|DEBUG|INFO|WARN|ERROR)\b")
_MEMORY_CACHE: dict[str, tuple[float, dict[str, str]]] = {}


class PassCliError(RuntimeError):
    def __init__(self, message: str, kind: ErrorKind = ErrorKind.INTERNAL):
        super().__init__(message)
        self.kind = kind


def _classify(stderr: str, *echoed: str) -> ErrorKind:
    """Map pass-cli stderr to an ErrorKind. ``echoed`` (refs/vault names we passed) are removed
    first so an item called e.g. "expired card" can't masquerade as an auth failure."""
    for text in echoed:
        stderr = stderr.replace(text, "")
    low = stderr.lower()
    if any(m in low for m in _AUTH_MARKERS):
        return ErrorKind.AUTH_FAILED
    if any(m in low for m in _NETWORK_MARKERS):
        return ErrorKind.NETWORK
    return ErrorKind.INTERNAL


def _detail(proc) -> str:
    """Readable one-line stderr (pass-cli log lines dropped). Never stdout: it may hold secrets."""
    lines = [ln.strip() for ln in (proc.stderr or "").splitlines() if ln.strip() and not _LOG_LINE.match(ln)]
    return " ".join(lines)[:240] or f"exit {proc.returncode}"


def _fp(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _num(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# -- references -------------------------------------------------------------------------------


def validate_refs(env_map) -> tuple[dict[str, str], list[str]]:
    """Keep valid ENV_VAR -> ``pass://vault/item/field`` bindings (stripped); warn on the rest."""
    valid: dict[str, str] = {}
    warnings: list[str] = []
    for name, ref in (env_map if isinstance(env_map, dict) else {}).items():
        ref = ref.strip() if isinstance(ref, str) else ref
        parts = ref[len("pass://"):].split("/") if isinstance(ref, str) and ref.startswith("pass://") else []
        if not is_valid_env_name(str(name)):
            warnings.append(f"Skipping {name!r}: not a valid env-var name")
        elif len(parts) != 3 or not all(p.strip() for p in parts):
            warnings.append(f"Skipping {name!r}: expected pass://vault/item/field")
        elif any(ord(c) < 32 for c in ref):
            warnings.append(f"Skipping {name!r}: reference contains control characters")
        else:
            valid[str(name)] = ref
    return valid, warnings


# -- pass-cli session -----------------------------------------------------------------------


def find_pass_cli(binary_path: str = "") -> Optional[Path]:
    """Pinned ``binary_path`` is used verbatim (no PATH fallback); else ``pass-cli`` on PATH."""
    found = binary_path or shutil.which("pass-cli")
    if not found or not os.path.isfile(found) or not os.access(found, os.X_OK):
        return None
    return Path(found)


@contextlib.contextmanager
def _file_lock(path: Path, timeout: float = LOCK_TIMEOUT) -> Iterator[None]:
    """Cross-process exclusive lock so concurrent Hermes processes don't race one login."""
    fh = open(path, "a+b")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise PassCliError("timed out waiting for the Proton Pass session lock", ErrorKind.TIMEOUT)
                time.sleep(0.1)
        yield
    finally:
        fh.close()  # closing releases flock / msvcrt locks


class PassSession:
    """One authenticated pass-cli context: owned PAT session dir, or the user's own login."""

    def __init__(self, binary: Path, token: str, home_path: Path, key_provider: str = "fs"):
        self.binary, self.token = binary, token
        self.dir = Path(home_path) / "cache" / "protonpass" / _fp(token) if token else None
        self.key_provider = key_provider
        self._relogged = False

    def _env(self, *, with_token: bool = False, reason: str = "") -> dict[str, str]:
        source = get_source_environment()
        extra = {k: source[k] for k in _ALLOW_ENV if source.get(k)}
        extra.setdefault("PROTON_PASS_DISABLE_TELEMETRY", "1")
        if self.dir is not None:
            extra["PROTON_PASS_SESSION_DIR"] = str(self.dir)
            extra.setdefault("PROTON_PASS_KEY_PROVIDER", self.key_provider or "fs")
        elif source.get("PROTON_PASS_SESSION_DIR"):
            extra["PROTON_PASS_SESSION_DIR"] = source["PROTON_PASS_SESSION_DIR"]
        if with_token:
            extra[DEFAULT_TOKEN_ENV] = self.token
        if reason:  # required by agent tokens for audited reads; harmless otherwise
            extra["PROTON_PASS_AGENT_REASON"] = reason[:300]
        return extra

    def run(self, *args: str, with_token: bool = False, reason: str = ""):
        try:
            proc = run_secret_cli([str(self.binary), *args], timeout=CLI_TIMEOUT,
                                  extra_env=self._env(with_token=with_token, reason=reason))
        except RuntimeError as exc:
            kind = ErrorKind.TIMEOUT if "timed out" in str(exc) else ErrorKind.BINARY_MISSING
            raise PassCliError(str(exc), kind) from exc
        if self.token:  # defence in depth: pass-cli should never echo it
            proc.stderr = proc.stderr.replace(self.token, "<redacted>")
        return proc

    @contextlib.contextmanager
    def open(self) -> Iterator["PassSession"]:
        if self.dir is None:  # user's own session: never log in on their behalf
            yield self
            return
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(self.dir.parent, 0o700)
            os.chmod(self.dir, 0o700)
        with _file_lock(self.dir / ".lock"):
            marker = self.dir / _LOGIN_MARKER
            fresh = marker.exists() and time.time() - marker.stat().st_mtime < SESSION_MAX_AGE
            if not fresh:
                self.login()
            yield self

    def login(self) -> None:
        self.run("logout", "--force")  # clear a stale session; failure is fine
        proc = self.run("login", with_token=True)
        if proc.returncode != 0:
            detail = _detail(proc)
            raise PassCliError(f"pass-cli login with the personal access token failed: {detail}",
                               ErrorKind.AUTH_FAILED if _classify(detail) != ErrorKind.NETWORK else ErrorKind.NETWORK)
        (self.dir / _LOGIN_MARKER).touch()

    def call(self, *args: str, reason: str = ""):
        """Run a read; on an auth-looking failure re-login once (PAT mode) and retry."""
        proc = self.run(*args, reason=reason)
        if (proc.returncode != 0 and self.dir is not None and not self._relogged
                and _classify(proc.stderr, *args) == ErrorKind.AUTH_FAILED):
            self._relogged = True
            self.login()
            proc = self.run(*args, reason=reason)
        return proc


# -- cache --------------------------------------------------------------------------------


def _cache_path(home_path: Path, source: str) -> Path:
    return Path(home_path) / "cache" / f"{source}_cache.json"


def cache_get(home_path: Path, source: str, key: str, ttl: float) -> Optional[dict[str, str]]:
    if ttl <= 0:
        return None
    mem = _MEMORY_CACHE.get(f"{home_path}|{source}|{key}")
    if mem and time.time() - mem[0] < ttl:
        return dict(mem[1])
    try:
        data = json.loads(_cache_path(home_path, source).read_text("utf-8"))
        if data.get("key") == key and time.time() - float(data["fetched_at"]) < ttl \
                and isinstance(data.get("secrets"), dict):
            return {str(k): str(v) for k, v in data["secrets"].items()}
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def cache_put(home_path: Path, source: str, key: str, ttl: float, secrets: dict[str, str]) -> None:
    if ttl <= 0 or not secrets:
        return
    now = time.time()
    _MEMORY_CACHE[f"{home_path}|{source}|{key}"] = (now, dict(secrets))
    path = _cache_path(home_path, source)
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{source}_")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:  # mkstemp creates 0600
            json.dump({"key": key, "fetched_at": now, "secrets": secrets}, fh)
        os.replace(tmp, path)


def clear_caches(home_path: Optional[Path] = None) -> None:
    """Drop memory + disk caches (after token rotation)."""
    _MEMORY_CACHE.clear()
    if home_path is not None:
        for source in ("protonpass", "protonpass_vault"):
            with contextlib.suppress(OSError):
                _cache_path(home_path, source).unlink()


# -- fetch primitives ---------------------------------------------------------------------


def read_refs(session: PassSession, refs: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Resolve each ref; per-ref failures become warnings (never the stdout, which may hold secrets).
    If *every* ref failed for an authentication reason, raise one AUTH_FAILED error instead, so
    Hermes prints a single line plus its remediation hint rather than N identical warnings."""
    secrets: dict[str, str] = {}
    warnings: list[str] = []
    auth_failures: list[str] = []
    for name in sorted(refs):
        # 3-segment URI (pass-cli 2.1.x ignores --field with a 2-segment URI); `--` stops flag parsing
        proc = session.call("item", "view", "--", refs[name], reason=f"Hermes startup: load {name}")
        value = (proc.stdout or "").rstrip("\r\n")
        if proc.returncode != 0:
            warnings.append(f"{name}: pass-cli could not read {refs[name]!r}: {_detail(proc)}")
            if _classify(proc.stderr, refs[name]) == ErrorKind.AUTH_FAILED:
                auth_failures.append(_detail(proc))
        elif not value.strip():
            warnings.append(f"{name}: pass-cli returned an empty value for {refs[name]!r}")
        else:
            secrets[name] = value
    if refs and len(auth_failures) == len(refs):
        raise PassCliError(f"pass-cli is not authenticated: {auth_failures[0]}", ErrorKind.AUTH_FAILED)
    return secrets, warnings


def _item_field(item: dict, field: str):
    """Field value from one ``item list --output json`` entry: typed fields, then custom fields."""
    content = item.get("content") if isinstance(item.get("content"), dict) else {}
    typed = content.get("content")
    for body in (typed.values() if isinstance(typed, dict) else ()):
        if isinstance(body, dict) and isinstance(body.get(field), str):
            return body[field]
    for extra in content.get("extra_fields") or ():
        if isinstance(extra, dict) and extra.get("name") == field and isinstance(extra.get("content"), dict):
            for value in extra["content"].values():
                if isinstance(value, str):
                    return value
    return None


def read_vault(session: PassSession, vault: str, field: str) -> tuple[dict[str, str], list[str]]:
    """Items titled like env vars -> their ``field``. Raises PassCliError if the listing fails."""
    proc = session.call("item", "list", "--filter-state", "active", "--show-secrets", "--output", "json",
                        "--", vault, reason=f"Hermes startup: load vault {vault}")
    if proc.returncode != 0:
        detail = _detail(proc)
        if "agent" in detail.lower():
            detail += " (AI-agent tokens cannot list secrets: use mapped pass:// refs instead)"
        raise PassCliError(f"pass-cli could not list vault {vault!r}: {detail}", _classify(detail, vault))
    try:
        payload = json.loads(proc.stdout or "")
    except ValueError as exc:
        raise PassCliError(f"pass-cli returned non-JSON for vault {vault!r}") from exc
    items = payload.get("items") if isinstance(payload, dict) else payload
    secrets: dict[str, str] = {}
    warnings: list[str] = []
    for item in items if isinstance(items, list) else ():
        content = item.get("content") if isinstance(item, dict) else None
        title = content.get("title") if isinstance(content, dict) else None
        if not isinstance(title, str) or not is_valid_env_name(title):
            continue
        value = _item_field(item, field)
        if not value:
            warnings.append(f"{title}: item has no non-empty {field!r} field")
        elif title in secrets:
            warnings.append(f"{title}: duplicate item title in vault {vault!r}; keeping the first")
        else:
            secrets[title] = value
    return secrets, warnings


# -- sources -------------------------------------------------------------------------------


class _ProtonPassBase(SecretSource):
    label = "Proton Pass"
    _AUTH_HINT = ("Run `hermes protonpass token` to store a fresh personal access token, "
                  "or `pass-cli login` for an interactive session.")

    def token_env(self, cfg) -> str:
        cfg = cfg if isinstance(cfg, dict) else {}
        name = str(cfg.get("token_env") or DEFAULT_TOKEN_ENV).strip()
        return name if is_valid_env_name(name) else DEFAULT_TOKEN_ENV

    def override_existing(self, cfg) -> bool:  # explicit vault bindings beat stale .env lines
        return bool(cfg.get("override_existing", True)) if isinstance(cfg, dict) else True

    def protected_env_vars(self, cfg) -> frozenset:
        return frozenset({self.token_env(cfg)})

    def remediation(self, kind, cfg) -> str:
        if kind in (ErrorKind.AUTH_FAILED, ErrorKind.AUTH_EXPIRED):
            return self._AUTH_HINT
        if kind == ErrorKind.BINARY_MISSING:
            return f"Install pass-cli ({DOCS_URL}) or set secrets.{self.name}.binary_path."
        if kind == ErrorKind.NOT_CONFIGURED:
            return "Run `hermes protonpass setup`."
        return super().remediation(kind, cfg)

    def _session(self, cfg: dict, home_path: Path, result: FetchResult) -> Optional[PassSession]:
        binary_path = str(cfg.get("binary_path") or "")
        binary = find_pass_cli(binary_path)
        result.binary_path = binary
        if binary is None:
            result.error = (f"secrets.{self.name}.binary_path ({binary_path!r}) is not an executable pass-cli"
                            if binary_path else f"pass-cli not found on PATH; install it from {DOCS_URL}")
            result.error_kind = ErrorKind.BINARY_MISSING
            return None
        token = str(get_source_environment().get(self.token_env(cfg)) or "").strip()
        return PassSession(binary, token, home_path, str(cfg.get("key_provider") or "fs"))

    def _cached_fetch(self, cfg: dict, home_path: Path, result: FetchResult, material: str, pull) -> FetchResult:
        session = self._session(cfg, home_path, result)
        if session is None:
            return result
        ttl = _num(cfg.get("cache_ttl_seconds", 300), 300.0)
        auth = session.token or f"cli-session:{get_source_environment().get('PROTON_PASS_SESSION_DIR', '')}"
        key = _fp(f"{_fp(auth)}|{material}")
        cached = cache_get(home_path, self.name, key, ttl)
        if cached is not None:
            result.secrets = cached
            return result
        try:
            with session.open():
                secrets, warnings, complete = pull(session)
        except PassCliError as exc:
            result.error, result.error_kind = str(exc), exc.kind
            return result
        result.secrets = secrets
        result.warnings.extend(warnings)
        if complete:  # never freeze a partial/transient failure in for the TTL
            cache_put(home_path, self.name, key, ttl, secrets)
        return result


class ProtonPassSource(_ProtonPassBase):
    """Mapped: explicit ENV_VAR -> pass://vault/item/field bindings."""

    name = "protonpass"
    shape = "mapped"
    # Refs are Proton's native pass://, validated in validate_refs(). The registry-level
    # scheme claim is left unset on purpose: the catalog-listed `pass` (password-store) source
    # already owns scheme "pass", and Hermes drops the second claimant entirely.
    scheme = None

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "env": {"description": "Map of ENV_VAR -> pass://vault/item/field", "default": {}},
            "token_env": {"description": "Env var holding the personal access token (unset = use your "
                                         "own pass-cli login)", "default": DEFAULT_TOKEN_ENV},
            "binary_path": {"description": "Pin pass-cli (empty = PATH)", "default": ""},
            "key_provider": {"description": "PROTON_PASS_KEY_PROVIDER for the owned PAT session", "default": "fs"},
            "cache_ttl_seconds": {"description": "Cache TTL; 0 disables memory+disk cache", "default": 300},
            "override_existing": {"description": "Resolved values overwrite .env/shell values", "default": True},
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        try:
            cfg = cfg if isinstance(cfg, dict) else {}
            refs, warnings = validate_refs(cfg.get("env"))
            result.warnings.extend(warnings)
            refs.pop(self.token_env(cfg), None)  # never fetch over the bootstrap token
            if not refs:
                if not warnings:
                    result.error = "secrets.protonpass.env is empty; add ENV_VAR: pass://vault/item/field entries"
                    result.error_kind = ErrorKind.NOT_CONFIGURED
                return result
            material = "\n".join(f"{k}={refs[k]}" for k in sorted(refs))

            def pull(session):
                secrets, read_warnings = read_refs(session, refs)
                return secrets, read_warnings, not read_warnings

            return self._cached_fetch(cfg, home_path, result, material, pull)
        except Exception as exc:  # contract: fetch never raises
            result.error, result.error_kind = f"unexpected Proton Pass error: {exc}", ErrorKind.INTERNAL
            return result


class ProtonPassVaultSource(_ProtonPassBase):
    """Bulk: one vault's env-var-titled items, Bitwarden-project style. Yields to mapped sources."""

    name = "protonpass_vault"
    label = "Proton Pass vault"
    shape = "bulk"

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "vault": {"description": "Vault name or share ID to inject", "default": ""},
            "field": {"description": "Item field used as the value", "default": "password"},
            "token_env": {"description": "Env var holding the personal access token", "default": DEFAULT_TOKEN_ENV},
            "binary_path": {"description": "Pin pass-cli (empty = PATH)", "default": ""},
            "cache_ttl_seconds": {"description": "Cache TTL; 0 disables", "default": 300},
            "override_existing": {"description": "Resolved values overwrite .env/shell values", "default": True},
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        try:
            cfg = cfg if isinstance(cfg, dict) else {}
            vault = str(cfg.get("vault") or "").strip()
            field = str(cfg.get("field") or "password").strip()
            if not vault:
                result.error = "secrets.protonpass_vault.vault is empty; set the vault to inject"
                result.error_kind = ErrorKind.NOT_CONFIGURED
                return result
            token_env = self.token_env(cfg)

            def pull(session):
                secrets, warnings = read_vault(session, vault, field)
                secrets.pop(token_env, None)
                return secrets, warnings, True  # item-level notes are not transient failures

            return self._cached_fetch(cfg, home_path, result, f"vault={vault}|field={field}", pull)
        except Exception as exc:
            result.error, result.error_kind = f"unexpected Proton Pass error: {exc}", ErrorKind.INTERNAL
            return result
