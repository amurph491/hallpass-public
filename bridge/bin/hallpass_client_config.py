#!/usr/bin/env python3
"""Register the Hallpass stdio bridge in supported user-level MCP configs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from typing import Mapping
sys.dont_write_bytecode = True  # this directory is a verified install: a __pycache__ in it would fail upgrade and uninstall

CLIENTS = ("codex", "claude", "antigravity")
LEGACY_SERVER_NAME = "hallpass-slack"  # the one fixed name every registration used before per-agent names
TOOL_NAME = "slack_search_messages"
SERVER_NAME_HELP = "hallpass- followed by 1-24 lowercase letters, digits, or inner hyphens (for example hallpass-research)"
ENV_API = "HALLPASS_AGENT_API_URL"
ENV_CREDENTIAL_FILE = "HALLPASS_AGENT_CREDENTIAL_FILE"


class ConfigFailure(Exception):
    """Safe user-facing error. Never include credential contents or config bodies."""


def _load_script(module_name: str, filename: str, message: str):
    """Load a sibling script by path: the helpers install as a flat bin/ directory, not a package."""
    script = Path(__file__).absolute().with_name(filename)
    if module_name == "hallpass_endpoint":
        existing = sys.modules.get(module_name)
        if existing is not None and getattr(existing, "__file__", None) == str(script):
            return existing  # one shared instance keeps exception classes identical across helpers
    try:
        loader = importlib.machinery.SourceFileLoader(module_name, str(script))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        if spec is None or spec.loader is None:
            raise ConfigFailure(message)
        module = importlib.util.module_from_spec(spec)
        if module_name == "hallpass_endpoint":
            sys.modules[module_name] = module
        spec.loader.exec_module(module)
    except (OSError, ImportError, SyntaxError):
        raise ConfigFailure(message) from None
    return module


endpoint_rules = _load_script("hallpass_endpoint", "hallpass_endpoint.py", "the endpoint helper is missing or invalid; reinstall Hallpass.")
DEFAULT_ENDPOINT = endpoint_rules.DEFAULT_ENDPOINT
API_URL = DEFAULT_ENDPOINT  # legacy name for the local default


class RegistrationState(Enum):
    REGISTERED = "registered"
    NOT_REGISTERED = "not_registered"
    CONFLICT = "conflict"
    MALFORMED = "malformed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class RegistrationStatus:
    state: RegistrationState
    message: str

    @property
    def registered(self) -> bool:
        return self.state is RegistrationState.REGISTERED


def canonical_agent_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise ConfigFailure("agent ID must be a canonical lowercase UUID.") from None
    if str(parsed) != value:
        raise ConfigFailure("agent ID must be a canonical lowercase UUID.")
    return value


def validate_server_name(value: object) -> str:
    """Accept only `hallpass-<slug>`. The value is never echoed: it is untrusted and may carry terminal escapes."""
    if not isinstance(value, str) or _load_importer().SERVER_NAME_PATTERN.fullmatch(value) is None:
        raise ConfigFailure(f"the server name must be {SERVER_NAME_HELP}.")
    return value


def default_server_name(agent_id: str) -> str:
    """`hallpass-` plus the first 8 hex characters of the agent UUID. Display metadata; it does not identify the agent."""
    return f"hallpass-{canonical_agent_id(agent_id)[:8]}"


def resolve_server_name(agent_id: str, client: str, name: str | None, environ: Mapping[str, str]) -> tuple[str, str | None]:
    """The server name to act on and the name recorded for this agent and client (None if none).

    `--name` wins, then the recorded name, then the default. The name only labels a client config entry: it never
    selects an agent, tenant, or credential.
    """
    agent_id = canonical_agent_id(agent_id)
    if name is not None:
        validate_server_name(name)
    importer = _load_importer()
    try:
        recorded = importer.stored_server_name(agent_id, client, environ)
    except Exception as error:
        if error.__class__.__name__ == "ImportFailure":
            raise ConfigFailure(str(error)) from None
        raise
    return (name or recorded or default_server_name(agent_id)), recorded


def _home(environ: Mapping[str, str]) -> Path:
    value = environ.get("HOME")
    if not value or not Path(value).is_absolute() or ".." in Path(value).parts:
        raise ConfigFailure("HOME must be set to an absolute path without parent segments.")
    return Path(value)


def _data_root(environ: Mapping[str, str]) -> Path:
    configured = environ.get("XDG_DATA_HOME")
    if configured:
        root = Path(configured)
        if not root.is_absolute() or ".." in root.parts:
            raise ConfigFailure("XDG_DATA_HOME must be an absolute path without parent segments.")
        return root
    return _home(environ) / ".local" / "share"


def credential_path(agent_id: str, client: str, environ: Mapping[str, str]) -> Path:
    return _data_root(environ) / "hallpass" / "credentials" / agent_id / f"{client}.credential"


def _load_importer():
    return _load_script("hallpass_credential_import_for_setup", "hallpass-credential-import", "credential verifier is unavailable.")


def _endpoint_for(agent_id: str, client: str, url: str | None, environ: Mapping[str, str]) -> tuple[str, bool]:
    """The endpoint this credential was imported for, and whether it was recorded.

    Credentials imported before endpoints were recorded fall back to the local default. `--url` may only confirm the
    recorded endpoint: a credential is never sent somewhere it was not verified against.
    """
    importer = _load_importer()
    try:
        recorded = importer.stored_endpoint(agent_id, client, environ)
    except Exception as error:
        if error.__class__.__name__ == "ImportFailure":
            raise ConfigFailure(str(error)) from None
        raise
    endpoint = recorded if recorded is not None else DEFAULT_ENDPOINT
    if url is not None:
        try:
            requested = endpoint_rules.normalize_endpoint(url)
        except endpoint_rules.EndpointError as error:
            raise ConfigFailure(f"--url is not acceptable: {error}") from None
        if requested != endpoint:
            raise ConfigFailure(
                f"--url {requested} differs from the endpoint this credential was imported for ({endpoint}); "
                f"re-import it with `hallpass credential import --agent {agent_id} --client {client} --url {requested} --rotate`."
            )
    return endpoint, recorded is not None


def _verify_credential(agent_id: str, client: str, environ: Mapping[str, str], endpoint: str) -> Path:
    path = credential_path(agent_id, client, environ)
    try:
        importer = _load_importer()
        root = _data_root(environ).absolute()
        current = Path(root.anchor)
        for component in root.parts[1:]:
            current = current / component
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ConfigFailure("credential storage directory is unsafe.")
            importer._check_directory(current, private=False, allow_root_owner=current != root)
        root_info = root.lstat()
        if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) & 0o022:
            raise ConfigFailure("credential data directory ownership or permissions are unsafe.")
        for directory in (root / "hallpass", root / "hallpass" / "credentials", root / "hallpass" / "credentials" / agent_id):
            directory_info = directory.lstat()
            if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode):
                raise ConfigFailure("credential storage directory is unsafe.")
            importer._check_directory(directory, private=True)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ConfigFailure("credential file is missing or unsafe; import it again for this agent and client.")
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ConfigFailure("credential file permissions are unsafe; import it again for this agent and client.")
            if info.st_size > endpoint_rules.MAX_PROFILE_BYTES:
                raise ConfigFailure("credential file is invalid; import it again for this agent and client.")
            content = os.read(fd, endpoint_rules.MAX_PROFILE_BYTES + 1)
        finally:
            os.close(fd)
        profile = endpoint_rules.parse_profile(content)
        if profile is None:
            raise ConfigFailure("credential file is invalid; import it again for this agent and client.")
        value = profile.credential
        importer.validate_credential(value)
        if profile.endpoint != endpoint:
            raise ConfigFailure(
                f"the credential file is bound to {profile.endpoint}, not {endpoint}; no client config was changed. "
                f"Re-import it with `hallpass credential import --agent {agent_id} --client {client} --url {endpoint} --rotate`."
            )
        authenticated_agent = importer.authenticated_agent_id(value, endpoint)
        if authenticated_agent != agent_id:
            raise ConfigFailure("credential authenticated as a different agent; no client config was changed.")
    except ConfigFailure:
        raise
    except FileNotFoundError:
        raise ConfigFailure(
            f"credential file is missing; run `hallpass credential import --agent {agent_id} --client {client}` first."
        ) from None
    except PermissionError:
        raise ConfigFailure("permission denied reading the credential file; no client config was changed.") from None
    except (OSError, UnicodeDecodeError):
        raise ConfigFailure("credential file cannot be read safely; import it again for this agent and client.") from None
    except Exception as error:
        if error.__class__.__name__ == "ImportFailure":
            # The verifier exposes only fixed, credential-free diagnostics.
            raise ConfigFailure(str(error)) from None
        raise  # unexpected: main reports the type and (opt-in) frames, never the message
    return path.resolve(strict=True)


def _validate_launcher(launcher: Path) -> Path:
    try:
        path = Path(os.path.abspath(launcher))
        current = Path(path.anchor)
        for component in path.parts[1:]:
            current = current / component
            if current.is_symlink():
                raise ConfigFailure("Hallpass bridge package path contains a symlink.")
        info = path.lstat()
    except ConfigFailure:
        raise
    except OSError:
        raise ConfigFailure("Hallpass bridge launcher is missing; install or repair the bridge bundle.") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022 or not os.access(path, os.X_OK):
        raise ConfigFailure("Hallpass bridge launcher is unsafe or not executable.")
    package_root = path.parent.parent
    for directory in (package_root, path.parent):
        try:
            directory_info = directory.lstat()
        except OSError:
            raise ConfigFailure("Hallpass bridge package path is missing or unsafe.") from None
        if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != os.getuid() or stat.S_IMODE(directory_info.st_mode) & 0o022:
            raise ConfigFailure("Hallpass bridge package directory is unsafe.")
    lib = package_root / "lib"
    try:
        lib_info = lib.lstat()
        jars = list(lib.glob("*.jar"))
        if stat.S_ISLNK(lib_info.st_mode) or not stat.S_ISDIR(lib_info.st_mode) or not jars:
            raise ConfigFailure("Hallpass bridge runtime is missing; install or repair the complete bridge bundle.")
        if lib_info.st_uid != os.getuid() or stat.S_IMODE(lib_info.st_mode) & 0o022:
            raise ConfigFailure("Hallpass bridge runtime directory is unsafe.")
        for jar in jars:
            jar_info = jar.lstat()
            if stat.S_ISLNK(jar_info.st_mode) or not stat.S_ISREG(jar_info.st_mode) or jar_info.st_uid != os.getuid() or stat.S_IMODE(jar_info.st_mode) & 0o022:
                raise ConfigFailure("Hallpass bridge runtime contains an unsafe file.")
    except ConfigFailure:
        raise
    except OSError:
        raise ConfigFailure("Hallpass bridge runtime is missing or unsafe.") from None
    return path


def _expected(launcher: Path, credential: Path, endpoint: str) -> dict[str, object]:
    return {
        "command": str(launcher),
        "args": [],
        "env": {ENV_API: endpoint, ENV_CREDENTIAL_FILE: str(credential)},
    }


def _claude_file(environ: Mapping[str, str]) -> Path:
    if environ.get("CLAUDE_CONFIG_DIR"):
        raise ConfigFailure("CLAUDE_CONFIG_DIR overrides are unsupported; configure the standard user file at ~/.claude.json.")
    return _home(environ) / ".claude.json"


def _antigravity_file(environ: Mapping[str, str]) -> Path:
    return _home(environ) / ".gemini" / "config" / "mcp_config.json"


def _read_json_config(path: Path) -> tuple[dict, bool, int]:
    if path.is_symlink():
        raise ConfigFailure("client config is a symlink; refusing to edit it.")
    if not path.exists():
        return {}, False, 0o600
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ConfigFailure("client config is unsafe; refusing to edit it.")
        raw = path.read_text(encoding="utf-8")
        value = {} if raw == "" else json.loads(raw)
    except ConfigFailure:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ConfigFailure("client config is malformed or unreadable; repair it before setup.") from None
    if not isinstance(value, dict):
        raise ConfigFailure("client config must contain a JSON object; repair it before setup.")
    return value, True, stat.S_IMODE(info.st_mode)


def _write_json_atomic(path: Path, value: dict, *, existed: bool, environ: Mapping[str, str]) -> None:
    parent = path.parent
    try:
        _ensure_config_directory(parent, environ)
        original = path.read_bytes() if existed else None
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(value, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            # Detect concurrent edits before replacing the original.
            if existed and path.read_bytes() != original:
                raise ConfigFailure("client config changed during setup; no config was replaced.")
            os.replace(temporary, path)
            try:
                directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                # Replacement already committed as one valid file. Report the
                # uncertain durability without claiming that the original remains.
                raise ConfigFailure("client config was updated, but its saved state could not be confirmed; inspect it before retrying.") from None
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except ConfigFailure:
        raise
    except OSError:
        raise ConfigFailure("could not safely update client config; the original file was preserved.") from None


def _ensure_config_directory(directory: Path, environ: Mapping[str, str]) -> None:
    absolute = directory.absolute()
    home = _home(environ)
    if absolute != home and home not in absolute.parents:
        raise ConfigFailure("client config path must remain under HOME.")
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ConfigFailure("client config directory contains an unsafe path component.")
        if current == home:
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise ConfigFailure("HOME must be owned by the current user and not group- or other-writable.")
        elif current in home.parents:
            if info.st_uid not in (os.getuid(), 0) or (info.st_mode & 0o002 and not info.st_mode & stat.S_ISVTX):
                raise ConfigFailure("client config path has an unsafe parent directory.")
        elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ConfigFailure("client config directory must be user-owned and not group- or other-writable.")




class _ReadProblem(Exception):
    """The current registration could not be read; carries the safe status to report."""

    def __init__(self, status: RegistrationStatus) -> None:
        super().__init__(status.message)
        self.status = status


def _json_current(client: str, name: str, environ: Mapping[str, str]) -> object | None:
    path = _claude_file(environ) if client == "claude" else _antigravity_file(environ)
    try:
        document, _exists, _mode = _read_json_config(path)
    except ConfigFailure as error:
        raise _ReadProblem(RegistrationStatus(RegistrationState.MALFORMED, str(error))) from None
    entries = document.get("mcpServers", {})
    if not isinstance(entries, dict):
        raise _ReadProblem(RegistrationStatus(RegistrationState.MALFORMED, "mcpServers must be an object; repair the client config."))
    return entries.get(name)


def _codex_current(name: str, environ: Mapping[str, str]) -> tuple[dict | None, bool]:
    """The entry named `name` as Codex reports it, and whether it is enabled; (None, False) when absent."""
    unavailable = RegistrationStatus(RegistrationState.UNAVAILABLE, "Codex could not read its MCP config; check Codex CLI and config permissions.")
    executable = shutil.which("codex", path=environ.get("PATH"))
    if not executable:
        raise _ReadProblem(RegistrationStatus(RegistrationState.UNAVAILABLE, "Codex CLI is unavailable; install it before setup, doctor, or remove."))
    try:
        result = subprocess.run(
            [executable, "mcp", "get", name, "--json"], env=dict(environ), cwd=_home(environ),
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise _ReadProblem(unavailable) from None
    if result.returncode:
        if "No MCP server named" in result.stderr:
            return None, False
        raise _ReadProblem(unavailable)
    try:
        value = json.loads(result.stdout)
        transport = value["transport"]
        entry = {"type": transport.get("type"), "command": transport["command"], "args": transport.get("args", []), "env": transport.get("env", {})}
        return entry, value.get("enabled") is True
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
        raise _ReadProblem(RegistrationStatus(RegistrationState.MALFORMED, "Codex returned malformed registration data; inspect its MCP config.")) from None


def _current_entry(client: str, name: str, environ: Mapping[str, str]) -> tuple[object | None, bool]:
    if client == "codex":
        return _codex_current(name, environ)
    return _json_current(client, name, environ), True


def _installed_launcher(environ: Mapping[str, str]) -> Path:
    sibling = Path(__file__).absolute().with_name("hallpass-bridge")
    if sibling.exists() and (sibling.parent.parent / "lib").is_dir():
        return sibling
    return _data_root(environ) / "hallpass" / "bridge" / "bin" / "hallpass-bridge"


def _owned_entry_agent(client: str, entry: object, environ: Mapping[str, str]) -> str | None:
    """The agent an exact Hallpass registration in `client` belongs to, or None if `entry` is anything else.

    "Exact" means the entry setup writes, for any valid endpoint (including the legacy loopback default): the installed
    launcher, no arguments, exactly the endpoint and credential-file variables, and a credential file path of the form
    `<data>/hallpass/credentials/<agent>/<client>.credential`. The agent comes from that path, never from the entry's name.
    """
    if not isinstance(entry, dict):
        return None
    try:
        env = entry.get("env", {})
        if not isinstance(env, dict) or set(env) != {ENV_API, ENV_CREDENTIAL_FILE}:
            return None
        endpoint, credential_value = env[ENV_API], env[ENV_CREDENTIAL_FILE]
        if not isinstance(endpoint, str) or not isinstance(credential_value, str):
            return None
        if endpoint_rules.normalize_endpoint(endpoint) != endpoint:
            return None
        root = (_data_root(environ) / "hallpass" / "credentials").absolute()
        credential = Path(credential_value)
        if credential.parent.parent != root or credential.name != f"{client}.credential":
            return None
        agent_id = canonical_agent_id(credential.parent.name)
        expected = _expected(_installed_launcher(environ), credential, endpoint)
        expected_entry = ({"type": "stdio", **expected} if client in ("claude", "codex") else expected)
        if entry == expected_entry and str(credential) == str(credential.resolve(strict=False)):
            return agent_id
        return None
    except (ConfigFailure, endpoint_rules.EndpointError, OSError, TypeError, AttributeError):
        return None


def registration_status(
    client: str, agent_id: str, launcher: Path, environ=os.environ, endpoint: str | None = None, name: str | None = None
) -> RegistrationStatus:
    """Compare the client's entry named `name` with the one setup would write for this agent's recorded endpoint.

    `name` defaults to the recorded server name, then to the agent's default name.
    """
    if client not in CLIENTS:
        return RegistrationStatus(RegistrationState.MALFORMED, "client must be codex, claude, or antigravity.")
    try:
        agent_id = canonical_agent_id(agent_id)
        name, _recorded = resolve_server_name(agent_id, client, name, environ)
        launcher_path = _validate_launcher(Path(launcher))
        if endpoint is None:
            endpoint, _recorded_endpoint = _endpoint_for(agent_id, client, None, environ)
        else:
            try:
                endpoint = endpoint_rules.normalize_endpoint(endpoint)
            except endpoint_rules.EndpointError as error:
                raise ConfigFailure(f"endpoint is not acceptable: {error}") from None
        credential = credential_path(agent_id, client, environ).resolve(strict=False)
        expected = _expected(launcher_path, credential, endpoint)
    except ConfigFailure as error:
        return RegistrationStatus(RegistrationState.MALFORMED, str(error))
    try:
        current, enabled = _current_entry(client, name, environ)
    except _ReadProblem as problem:
        return problem.status
    except ConfigFailure as error:
        return RegistrationStatus(RegistrationState.MALFORMED, str(error))
    if current is None:
        return RegistrationStatus(RegistrationState.NOT_REGISTERED, "Hallpass is not registered in this client.")
    wanted = {"type": "stdio", **expected} if client in ("claude", "codex") else expected
    if current == wanted and enabled:
        return RegistrationStatus(RegistrationState.REGISTERED, f"Hallpass bridge is registered for this agent as {name}.")
    owner = _owned_entry_agent(client, current, environ)
    if owner is not None and owner != agent_id:
        return RegistrationStatus(
            RegistrationState.CONFLICT, f"{name} is already registered for a different Hallpass agent; inspect it before changing the client config."
        )
    return RegistrationStatus(
        RegistrationState.CONFLICT, f"A different server already uses {name} (or it is disabled); inspect it before changing the client config."
    )


# --- What is already registered: a safe summary, and how to remove it by hand -------------------------------------

_BEARER_LIKE = re.compile(r"ac1\.[A-Za-z0-9_.-]*")


def _display(value: object, limit: int = 200) -> str:
    """Printable, bounded text that cannot carry a bearer or terminal escapes."""
    if not isinstance(value, str):
        return "<not a string>"
    text = _BEARER_LIKE.sub("<redacted>", value)
    text = "".join(character if character.isprintable() else "?" for character in text)
    return text if len(text) <= limit else text[:limit] + "..."


def describe_entry(entry: object, enabled: bool = True) -> str:
    """Summarize an existing entry. Only the command, endpoint, and credential file path are shown.

    Every other environment value, and every argument, is withheld: any of them could be a secret (an inline
    HALLPASS_AGENT_CREDENTIAL, a token). Credential file contents are never read.
    """
    if not isinstance(entry, dict):
        return "  (the entry is not a recognizable server definition)"
    env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
    lines = [f"  command: {_display(entry['command']) if 'command' in entry else '<not set>'}"]
    args = entry.get("args")
    if isinstance(args, list) and args:
        lines.append(f"  arguments: {len(args)} (not shown)")
    endpoint = env.get(ENV_API)
    if ENV_API not in env:
        lines.append(f"  {ENV_API}: <not set>")
    else:
        try:
            shown = endpoint_rules.normalize_endpoint(endpoint)
        except endpoint_rules.EndpointError:
            shown = "<redacted>"  # not a valid endpoint: it might hold user info or something worse
        lines.append(f"  {ENV_API}: {shown}")
    lines.append(f"  {ENV_CREDENTIAL_FILE}: {_display(env[ENV_CREDENTIAL_FILE]) if ENV_CREDENTIAL_FILE in env else '<not set>'}")
    for name in sorted(str(key) for key in env if key not in (ENV_API, ENV_CREDENTIAL_FILE)):
        lines.append(f"  {_display(name, 60)}: <redacted>")
    others = sorted(str(key) for key in entry if key not in ("command", "args", "env", "type"))
    if others:
        lines.append(f"  other fields (values not shown): {', '.join(_display(name, 40) for name in others)}")
    if not enabled:
        lines.append("  enabled: no")
    return "\n".join(lines)


def manual_removal(client: str, name: str, environ: Mapping[str, str]) -> str:
    """How to remove the entry `name` by hand. `name` is a validated server name or the legacy one."""
    if client == "codex":
        return f"codex mcp remove {name}"
    if client == "claude":
        return f"claude mcp remove {name} --scope user"
    try:
        location = str(_antigravity_file(environ))
    except ConfigFailure:
        location = "~/.gemini/config/mcp_config.json"
    return f'edit {location} and delete the "{name}" key under "mcpServers"'


def _existing_guidance(client: str, name: str, entry: object, enabled: bool, environ: Mapping[str, str]) -> str:
    return (
        f"The existing {name} entry in {client}:\n{describe_entry(entry, enabled)}\n"
        f"To remove it yourself: {manual_removal(client, name, environ)}"
    )


def _mutate_json(client: str, name: str, add: bool, expected: dict[str, object], environ: Mapping[str, str]) -> None:
    path, key = (_claude_file(environ), "mcpServers") if client == "claude" else (_antigravity_file(environ), "mcpServers")
    document, existed, mode = _read_json_config(path)
    entries = document.setdefault(key, {})
    if not isinstance(entries, dict):
        raise ConfigFailure(f"{key} must be an object; repair the client config.")
    if add:
        entries[name] = expected
    else:
        entries.pop(name, None)
        if not entries:
            document.pop(key, None)
    _write_json_atomic(path, document, existed=existed, environ=environ)


def _run_codex(action: str, name: str, launcher: Path | None, expected: dict[str, object] | None, environ: Mapping[str, str]) -> None:
    executable = shutil.which("codex", path=environ.get("PATH"))
    if not executable:
        raise ConfigFailure("Codex CLI is unavailable; install it before setup or remove.")
    command = [executable, "mcp", action, name]
    if action == "add":
        assert launcher is not None and expected is not None
        env = expected["env"]
        command += ["--env", f"{ENV_API}={env[ENV_API]}", "--env", f"{ENV_CREDENTIAL_FILE}={env[ENV_CREDENTIAL_FILE]}", "--", str(launcher)]
    try:
        result = subprocess.run(command, env=dict(environ), cwd=_home(environ), capture_output=True, text=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigFailure(f"Codex could not {action} the Hallpass entry; inspect Codex MCP config and retry.") from None
    if result.returncode:
        raise ConfigFailure(f"Codex could not {action} the Hallpass entry; inspect Codex MCP config and retry.")


def _remove_entry(client: str, name: str, environ: Mapping[str, str]) -> None:
    if client == "codex":
        # Codex CLI is the supported user-level config editor.
        _run_codex("remove", name, None, None, environ)
    else:
        _mutate_json(client, name, False, {}, environ)


def _remove_if_owned_by(client: str, name: str, agent_id: str, environ: Mapping[str, str]) -> str:
    """Remove the entry `name` only if it is an exact Hallpass registration for this agent and client.

    Returns a one-line outcome for the user. Anything that is not ours is left in place.
    """
    try:
        entry, _enabled = _current_entry(client, name, environ)
    except _ReadProblem as problem:
        return (
            f"Could not check {name} in {client} ({problem.status.message}); it was left in place. "
            f"To remove it yourself: {manual_removal(client, name, environ)}"
        )
    if entry is None:
        return f"{name} is no longer present in {client}."
    if _owned_entry_agent(client, entry, environ) != agent_id:
        return f"{name} in {client} is not an exact Hallpass registration for this agent, so it was left in place."
    try:
        _remove_entry(client, name, environ)
    except ConfigFailure as failure:
        return f"Could not remove {name} from {client} ({failure}). To remove it yourself: {manual_removal(client, name, environ)}"
    return f"Removed the old {name} entry for this agent from {client}."


def _migrate_legacy(client: str, agent_id: str, name: str, environ: Mapping[str, str]) -> str | None:
    """Remove a legacy `hallpass-slack` entry, but only an exact Hallpass registration for this same agent and client."""
    try:
        entry, _enabled = _current_entry(client, LEGACY_SERVER_NAME, environ)
    except _ReadProblem:
        return None  # the registration under the new name succeeded; a legacy entry that cannot be read is left alone
    if entry is None or _owned_entry_agent(client, entry, environ) != agent_id:
        return None  # absent, or not an exact registration for this agent: another agent's legacy entry is left alone
    try:
        _remove_entry(client, LEGACY_SERVER_NAME, environ)
    except ConfigFailure as failure:
        return (
            f"Could not remove the legacy {LEGACY_SERVER_NAME} entry for this agent from {client} ({failure}). "
            f"To remove it yourself: {manual_removal(client, LEGACY_SERVER_NAME, environ)}"
        )
    return (
        f"Migrated: removed the legacy {LEGACY_SERVER_NAME} entry for this agent from {client}.\n"
        f"The tool is now `mcp__{name}__{TOOL_NAME}` in Claude Code, and permission rules written for "
        f"`mcp__{LEGACY_SERVER_NAME}__*` need updating to `mcp__{name}__*`."
    )


def _record_name(agent_id: str, client: str, name: str, environ: Mapping[str, str]) -> None:
    importer = _load_importer()
    try:
        importer.record_server_name(agent_id, client, name, environ)
    except Exception as error:
        if error.__class__.__name__ == "ImportFailure":
            raise ConfigFailure(f"{client} was updated, but {error}") from None
        raise


def _forget_name(agent_id: str, client: str, environ: Mapping[str, str]) -> None:
    importer = _load_importer()
    try:
        importer.delete_server_name(agent_id, client, environ)
    except Exception as error:
        if error.__class__.__name__ == "ImportFailure":
            raise ConfigFailure(f"the registration was removed, but {error}") from None
        raise


def setup(
    client: str,
    agent_id: str,
    launcher: Path,
    environ=os.environ,
    *,
    url: str | None = None,
    replace: bool = False,
    name: str | None = None,
) -> RegistrationStatus:
    if client not in CLIENTS:
        raise ConfigFailure("client must be codex, claude, or antigravity.")
    agent_id = canonical_agent_id(agent_id)
    name, recorded = resolve_server_name(agent_id, client, name, environ)
    launcher_path = _validate_launcher(Path(launcher))
    endpoint, _recorded = _endpoint_for(agent_id, client, url, environ)
    credential = _verify_credential(agent_id, client, environ, endpoint)
    current = registration_status(client, agent_id, launcher_path, environ, endpoint, name)
    replacing: tuple[object | None, bool] | None = None
    if current.state is RegistrationState.CONFLICT:
        try:
            entry, enabled = _current_entry(client, name, environ)
        except _ReadProblem as problem:
            raise ConfigFailure(problem.status.message) from None
        if not replace:
            raise ConfigFailure(
                f"{current.message} Nothing was changed in {client}.\n"
                f"{_existing_guidance(client, name, entry, enabled, environ)}\n"
                f"To register this agent under a different name, use --name hallpass-<name>. "
                f"To replace that entry with this agent's registration, re-run with --replace."
            )
        replacing = (entry, enabled)
    elif current.state in (RegistrationState.MALFORMED, RegistrationState.UNAVAILABLE):
        raise ConfigFailure(current.message)
    already = current.state is RegistrationState.REGISTERED
    if not already:
        expected = _expected(launcher_path, credential, endpoint)
        if replacing is not None:
            print(f"Replacing the existing {name} entry in {client}:\n{describe_entry(*replacing)}")
        if client == "codex":
            if replacing is not None:
                _run_codex("remove", name, None, None, environ)
                try:
                    _run_codex("add", name, launcher_path, expected, environ)
                except ConfigFailure:
                    raise ConfigFailure(
                        f"The previous {name} entry was removed from codex, but adding the new registration failed, "
                        f"so codex now has no {name} entry (the removed entry is summarized above). "
                        f"Run `hallpass setup codex --agent {agent_id} --name {name}` to register it again."
                    ) from None
            else:
                _run_codex("add", name, launcher_path, expected, environ)
        elif client == "claude":
            _mutate_json(client, name, True, {"type": "stdio", **expected}, environ)
        else:
            _mutate_json(client, name, True, expected, environ)

    # The registration under `name` is in place. Record it first: if that fails, the old entries are still there and a
    # retry converges. What follows is cleanup, and any problem with it is reported rather than hidden.
    if recorded != name:
        _record_name(agent_id, client, name, environ)
    if recorded is not None and recorded != name:
        print(f"Renaming {recorded} to {name} for this agent in {client}.")
        print(_remove_if_owned_by(client, recorded, agent_id, environ))
    if name != LEGACY_SERVER_NAME and recorded != LEGACY_SERVER_NAME:
        note = _migrate_legacy(client, agent_id, name, environ)
        if note is not None:
            print(note)
    verb = "already registered" if already else "registered"
    return RegistrationStatus(
        RegistrationState.REGISTERED,
        f"Hallpass bridge {verb} for agent {agent_id} in {client} as {name} (endpoint {endpoint}).",
    )


def remove(client: str, environ=os.environ, *, agent_id: str | None = None, name: str | None = None) -> RegistrationStatus:
    """Remove one Hallpass registration from `client`. The credential and endpoint files are never touched.

    With an agent: that agent's entry (`name`, else the recorded name, else the default), and only if it is an exact
    Hallpass registration for that same agent; its server name record is deleted. Without an agent: the legacy
    `hallpass-slack` entry, as before per-agent names.
    """
    if client not in CLIENTS:
        raise ConfigFailure("client must be codex, claude, or antigravity.")
    recorded: str | None = None
    if agent_id is None:
        if name is not None:
            raise ConfigFailure("--name needs --agent: the agent identifies which registration is removed.")
        target = LEGACY_SERVER_NAME
    else:
        agent_id = canonical_agent_id(agent_id)
        target, recorded = resolve_server_name(agent_id, client, name, environ)
    removed = f"Removed only the Hallpass MCP registration {target} from {client}. Its credential file and server-side grant remain active."
    not_registered = RegistrationStatus(RegistrationState.NOT_REGISTERED, f"{target} is not registered in {client}; no client config changed.")
    try:
        entry, enabled = _current_entry(client, target, environ)
    except _ReadProblem as problem:
        raise ConfigFailure(f"{problem.status.message} No client config changed.") from None
    if entry is None:
        if agent_id is not None and recorded == target:
            _forget_name(agent_id, client, environ)
        return not_registered
    owner = _owned_entry_agent(client, entry, environ)
    if owner is None or (agent_id is not None and owner != agent_id):
        reason = "an exact Hallpass registration" if owner is None else "registered for this agent"
        raise ConfigFailure(
            f"{target} is not {reason}; it was preserved.\n{_existing_guidance(client, target, entry, enabled, environ)}"
        )
    _remove_entry(client, target, environ)
    if agent_id is not None and recorded == target:
        _forget_name(agent_id, client, environ)
    return RegistrationStatus(RegistrationState.NOT_REGISTERED, removed)


def connect(
    client: str,
    agent_id: str,
    launcher: Path,
    environ=os.environ,
    *,
    url: str | None = None,
    rotate: bool = False,
    replace: bool = False,
    name: str | None = None,
) -> int:
    """Import (or reuse) the credential, register the bridge, then run doctor; stop at the first failing step."""
    if client not in CLIENTS:
        raise ConfigFailure("client must be codex, claude, or antigravity.")
    agent_id = canonical_agent_id(agent_id)
    name, _recorded_name = resolve_server_name(agent_id, client, name, environ)  # a bad --name fails before any prompt
    try:
        endpoint = endpoint_rules.resolve_endpoint(url, environ)
    except endpoint_rules.EndpointError as error:
        raise ConfigFailure(f"endpoint URL is not acceptable: {error}") from None
    importer = _load_importer()
    try:
        exists = importer.credential_exists(agent_id, client, environ)
    except importer.ImportFailure as error:
        raise ConfigFailure(str(error)) from None
    if exists and not rotate:
        recorded, _ = _endpoint_for(agent_id, client, None, environ)
        if recorded != endpoint:
            raise ConfigFailure(
                f"the credential for this agent and client was imported for {recorded}, not {endpoint}; "
                f"re-run with --rotate to import a credential for {endpoint}."
            )
        print(f"[1/3] Credential: reusing the one already imported for this agent and client ({endpoint}).")
    else:
        print(f"[1/3] Credential: importing for {endpoint}.")
        try:
            destination = importer.import_credential(agent_id, client, rotate=exists, endpoint=endpoint, environ=environ)
        except importer.ImportFailure as error:
            raise ConfigFailure(str(error)) from None
        print(f"Credential verified for agent {agent_id} against {endpoint} and saved to {destination}")
    print(f"[2/3] Client registration as {name}.")
    print(setup(client, agent_id, launcher, environ, url=endpoint, replace=replace, name=name).message)
    print("[3/3] Doctor.")
    doctor = _load_script("hallpass_doctor_for_connect", "hallpass-doctor", "the doctor helper is missing or invalid; reinstall Hallpass.")
    return doctor.run(client, agent_id, environ=environ, url=endpoint, name=name)


class _SafeParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        print("hallpass: invalid client registration arguments.", file=sys.stderr)
        self.print_usage(sys.stderr)
        raise SystemExit(2)


_URL_HELP = "agent API endpoint: https://HOST[:PORT], or numeric-loopback http"
_NAME_HELP = (
    f"MCP server name: {SERVER_NAME_HELP}. Default: the recorded name, else hallpass-<first 8 hex of the agent ID>. "
    "It labels the client entry only; it never selects an agent or credential"
)


def main(argv: list[str] | None = None) -> int:
    parser = _SafeParser(prog="hallpass")
    commands = parser.add_subparsers(dest="action", required=True)
    setup_parser = commands.add_parser("setup", help="register the bridge for an imported credential")
    setup_parser.add_argument("client", choices=CLIENTS)
    setup_parser.add_argument("--agent", required=True)
    setup_parser.add_argument("--url", metavar="URL", help=f"{_URL_HELP}; must equal the endpoint recorded at import")
    setup_parser.add_argument("--name", metavar="NAME", help=f"{_NAME_HELP}. A different name renames this agent's entry")
    setup_parser.add_argument("--replace", action="store_true", help="replace a different existing entry under the same name (its summary is printed first)")
    remove_parser = commands.add_parser(
        "remove",
        help="remove an Hallpass registration from a client",
        description=(
            "With --agent, remove that agent's registration (the recorded name, else the default, else --name) and its "
            f"server name record. Without --agent, remove the legacy {LEGACY_SERVER_NAME} entry, as before per-agent "
            "names. Credential and endpoint files are left alone."
        ),
    )
    remove_parser.add_argument("--client", required=True, choices=CLIENTS)
    remove_parser.add_argument("--agent", metavar="UUID", help=f"the agent whose registration to remove; omit it to remove the legacy {LEGACY_SERVER_NAME} entry")
    remove_parser.add_argument("--name", metavar="NAME", help="the server name to remove (needs --agent). Default: the recorded name")
    connect_parser = commands.add_parser("connect", help="import the credential, register the bridge, and run doctor")
    connect_parser.add_argument("client", choices=CLIENTS)
    connect_parser.add_argument("--agent", required=True)
    connect_parser.add_argument("--url", metavar="URL", help=f"{_URL_HELP}. Default: ${ENV_API}, then {DEFAULT_ENDPOINT}")
    connect_parser.add_argument("--name", metavar="NAME", help=_NAME_HELP)
    connect_parser.add_argument("--rotate", action="store_true", help="import a new credential even if one exists")
    connect_parser.add_argument("--replace", action="store_true", help="replace a different existing entry under the same name")
    args = parser.parse_args(argv)
    try:
        launcher = Path(__file__).with_name("hallpass-bridge")
        if args.action == "connect":
            return connect(args.client, args.agent, launcher, url=args.url, rotate=args.rotate, replace=args.replace, name=args.name)
        if args.action == "setup":
            result = setup(args.client, args.agent, launcher, url=args.url, replace=args.replace, name=args.name)
        else:
            result = remove(args.client, agent_id=args.agent, name=args.name)
    except ConfigFailure as error:
        print(f"hallpass: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # Never print the exception's text: it can carry values. Its type and frames are opt-in (HALLPASS_DEBUG=1).
        endpoint_rules.report_unexpected(error, "client configuration operation failed unexpectedly; inspect the client config and retry.")
        return 1
    print(result.message)
    if args.action == "remove" and result.state is RegistrationState.NOT_REGISTERED:
        print("Credential file and server-side credential/grant were left unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
