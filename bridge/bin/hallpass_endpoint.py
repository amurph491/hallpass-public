#!/usr/bin/env python3
"""Shared Hallpass agent endpoint rules, fixed-path client, and safe diagnostics.

The endpoint rule is the same one the Scala bridge enforces in
`BridgeConfig.parseEndpoint`, the installer, the server, and the admin UI apply;
`bridge/tests/endpoint_vectors.json` pins every implementation to identical
results:

  * `https://` to one exact host (a DNS name with at least two labels, or an IP
    literal) with an optional port, verified with the platform trust store; or
  * `http://` only to a numeric loopback literal (127.x.x.x or ::1).

No user info, query, fragment, or path other than empty or `/` is accepted.

The one canonical representation is `scheme://host[:port]`: the host is
lowercase, an IPv6 literal is bracketed and compressed (RFC 5952; IPv4-mapped
forms are rejected), and the port is omitted when it is the scheme's default
(80 for http, 443 for https). Every implementation must produce exactly this
text, because it is compared for equality when a credential is bound to an
endpoint. The client never follows redirects, so a bearer cannot be steered to
another host.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import traceback
from typing import Mapping, NamedTuple
sys.dont_write_bytecode = True  # this directory is a verified install: a __pycache__ in it would fail upgrade and uninstall

DEFAULT_ENDPOINT = "http://127.0.0.1:8081"
DEFAULT_PORTS = {"http": 80, "https": 443}
ENV_ENDPOINT = "HALLPASS_AGENT_API_URL"
REQUEST_TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 4096
DEBUG_HINT = "Set HALLPASS_DEBUG=1 for details."

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DNS_NAME = re.compile(rf"{_LABEL}(?:\.{_LABEL})+")
_URL = re.compile(r"(https?)://([^/?#@]*)/?")
_AUTHORITY = re.compile(r"(?:\[([^\]\[]*)\]|([^\]\[:]*))(?::([0-9]*))?")


class EndpointError(ValueError):
    """The endpoint violates the rule. The message never repeats the rejected value (it may hold a secret)."""


class Endpoint(NamedTuple):
    scheme: str
    host: str  # IPv6 literals without brackets
    port: int | None

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port is None else f"{host}:{self.port}"

    @property
    def normalized(self) -> str:
        return f"{self.scheme}://{self.authority}"

    @property
    def is_loopback(self) -> bool:
        return _loopback_literal(self.host)


_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_IPV4 = re.compile(rf"{_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}")


def _ipv4(host: str) -> ipaddress.IPv4Address | None:
    if not _IPV4.fullmatch(host):  # a dotted quad spelled once: no leading zeros, exactly four octets
        return None
    try:
        return ipaddress.IPv4Address(host)
    except ValueError:
        return None


def _ipv6(host: str) -> ipaddress.IPv6Address | None:
    # No dots: IPv4-embedded spellings (::ffff:1.2.3.4) have several textual forms and are not accepted.
    if not re.fullmatch(r"[0-9A-Fa-f:]+", host):
        return None
    try:
        address = ipaddress.IPv6Address(host)
    except ValueError:
        return None
    return None if address.ipv4_mapped is not None else address


def _loopback_literal(host: str) -> bool:
    v4 = _ipv4(host)
    if v4 is not None:
        return v4.is_loopback
    v6 = _ipv6(host)
    return v6 is not None and v6.is_loopback


def _is_dns_or_ip_host(host: str) -> bool:
    if _ipv6(host) is not None:
        return True
    if len(host) > 253 or _DNS_NAME.fullmatch(host) is None:
        return False
    if re.fullmatch(r"[0-9.]+", host):
        return _ipv4(host) is not None  # all-numeric names must be a real IPv4 literal
    return host.rsplit(".", 1)[1][0].isalpha()  # a top label starts with a letter


def parse_endpoint(value: object) -> Endpoint:
    if not isinstance(value, str) or not value.isascii() or not value.isprintable() or " " in value:
        raise EndpointError("endpoint URL is not valid.")
    url = _URL.fullmatch(value)
    if url is None:
        raise EndpointError("endpoint URL is not valid.")
    scheme, authority_text = url.group(1), url.group(2)
    authority = _AUTHORITY.fullmatch(authority_text)
    if authority is None:
        raise EndpointError("endpoint URL is not valid.")
    bracketed, plain, port_text = authority.groups()
    host = bracketed if bracketed is not None else plain
    if bracketed is not None:
        address = _ipv6(host)
        if address is None:
            raise EndpointError("endpoint URL is not valid.")
        host = address.compressed
    else:
        host = host.lower()
    port: int | None = None
    if port_text is not None:  # "" is a colon with nothing after it, which is not a port
        if not port_text or len(port_text) > 5 or not 0 < int(port_text) <= 65535:
            raise EndpointError("endpoint URL is not valid.")
        port = int(port_text)
        if port == DEFAULT_PORTS[scheme]:
            port = None
    endpoint = Endpoint(scheme, host, port)
    if scheme == "http":
        if not endpoint.is_loopback:
            raise EndpointError("http endpoints are accepted only for numeric loopback addresses (127.x.x.x or ::1); use https for a hosted endpoint.")
    elif not _is_dns_or_ip_host(host):
        raise EndpointError("https endpoints must name one exact host (a DNS name with at least two labels, or an IP address).")
    return endpoint


def normalize_endpoint(value: object) -> str:
    return parse_endpoint(value).normalized


PROFILE_HEADER = "hallpass-agent-profile/1"
MAX_PROFILE_BYTES = 1024


class Profile(NamedTuple):
    """One credential and the endpoint it was verified against, stored and replaced as one file.

    `recorded` is False for a bare credential written before profiles existed: it was only ever verified against the
    local default endpoint, so that is its implied binding.
    """

    endpoint: str
    credential: str
    recorded: bool


def render_profile(endpoint: str, credential: str) -> str:
    return f"{PROFILE_HEADER}\nendpoint={normalize_endpoint(endpoint)}\ncredential={credential}\n"


def parse_profile(raw: bytes) -> Profile | None:
    """Parse a stored profile (or a legacy bare credential); None means the file is not one. The credential's own
    format is checked by the caller."""
    if len(raw) > MAX_PROFILE_BYTES or not raw.endswith(b"\n") or b"\r" in raw:
        return None
    try:
        lines = raw[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError:
        return None
    if len(lines) == 1 and lines[0].startswith("ac1."):
        return Profile(DEFAULT_ENDPOINT, lines[0], False)
    if len(lines) != 3 or lines[0] != PROFILE_HEADER:
        return None
    if not lines[1].startswith("endpoint=") or not lines[2].startswith("credential="):
        return None
    endpoint_text, credential = lines[1][len("endpoint="):], lines[2][len("credential="):]
    try:
        if normalize_endpoint(endpoint_text) != endpoint_text:
            return None  # a stored endpoint must already be canonical
    except EndpointError:
        return None
    return Profile(endpoint_text, credential, True)


def resolve_endpoint(explicit: str | None, environ: Mapping[str, str] = os.environ) -> str:
    """`--url` wins over the environment, which wins over the local default."""
    if explicit is not None:
        return normalize_endpoint(explicit)
    configured = environ.get(ENV_ENDPOINT)
    if configured:
        return normalize_endpoint(configured)
    return DEFAULT_ENDPOINT


def endpoint_repair_hint(endpoint: str) -> str:
    """Where to look when the endpoint does not answer; only loopback endpoints are the local Compose stack."""
    if parse_endpoint(endpoint).is_loopback:
        return f"verify the local stack is running at {endpoint} (`docker compose up -d`) and retry"
    return f"verify {endpoint} is reachable from this machine and retry"


class RequestFailure(Exception):
    """A fixed-path request failed. Carries no response body, header text, or credential."""

    def __init__(self, kind: str, status: int | None = None, retry_after: int | None = None) -> None:
        super().__init__(kind)
        self.kind = kind
        self.status = status
        self.retry_after = retry_after


def _retry_after(value: str | None) -> int | None:
    if value is not None and re.fullmatch(r"[0-9]{1,7}", value.strip()):
        return int(value.strip())
    return None


def open_connection(endpoint: Endpoint, timeout: float) -> http.client.HTTPConnection:
    if endpoint.scheme == "https":
        # Certificate and hostname verification are on: create_default_context() uses CERT_REQUIRED and check_hostname.
        return http.client.HTTPSConnection(endpoint.host, endpoint.port, context=ssl.create_default_context(), timeout=timeout)
    return http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout)


def get_json(
    endpoint: str,
    path: str,
    credential: str,
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> object:
    """GET one fixed path with a bearer, without redirects. Any non-200 is a failure; the body is bounded."""
    parsed = parse_endpoint(endpoint)
    connection = open_connection(parsed, timeout)
    try:
        connection.request(
            "GET",
            path,
            headers={"Authorization": f"Bearer {credential}", "Accept": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        if response.status != 200:
            retry = _retry_after(response.getheader("Retry-After")) if response.status == 429 else None
            raise RequestFailure("rate_limited" if response.status == 429 else "status", response.status, retry)
        declared = response.getheader("Content-Length")
        if declared is not None:
            try:
                if int(declared) < 0 or int(declared) > max_bytes:
                    raise RequestFailure("too_large")
            except ValueError:
                raise RequestFailure("bad_length") from None
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise RequestFailure("too_large")
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RequestFailure("malformed") from None
    except RequestFailure:
        raise
    except ssl.SSLCertVerificationError:
        raise RequestFailure("tls_verify") from None
    except ssl.SSLError:
        raise RequestFailure("tls") from None
    except (OSError, http.client.HTTPException, TimeoutError):
        raise RequestFailure("unavailable") from None
    finally:
        connection.close()


def describe_failure(failure: RequestFailure, subject: str) -> str | None:
    """Endpoint-independent wording shared by import and doctor; None means the caller words it (status, unavailable)."""
    if failure.kind == "rate_limited":
        wait = f" Wait {failure.retry_after} seconds" if failure.retry_after is not None else " Wait a little"
        return f"the server is rate-limiting requests from this address.{wait} before retrying."
    if failure.kind == "tls_verify":
        return "the server's TLS certificate could not be verified (untrusted, expired, or not valid for this host); no credential was sent."
    if failure.kind == "tls":
        return "the TLS connection to the server failed."
    if failure.kind == "too_large":
        return f"{subject} response exceeded the allowed size."
    if failure.kind == "bad_length":
        return f"{subject} response had an invalid length."
    if failure.kind == "malformed":
        return f"{subject} response was malformed."
    return None


def debug_enabled() -> bool:
    return os.environ.get("HALLPASS_DEBUG") == "1"


def _chain(error: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    return chain


def report_unexpected(error: BaseException, message: str, stream=None) -> None:
    """Print a fixed message for an unexpected exception.

    With HALLPASS_DEBUG=1 also print each exception's type and traceback frames
    (file, line, function, source line), following chained causes. Never print
    str(error), its args, local variables, HTTP bodies, or config contents:
    any of them can contain a bearer credential.
    """
    stream = stream if stream is not None else sys.stderr
    if not debug_enabled():
        print(f"hallpass: {message} {DEBUG_HINT}", file=stream)
        return
    print(f"hallpass: {message}", file=stream)
    for index, item in enumerate(_chain(error)):
        kind = type(item)
        label = "unexpected exception" if index == 0 else "caused by"
        detail = f" (errno {item.errno})" if isinstance(item, OSError) and isinstance(item.errno, int) else ""
        print(f"  {label}: {kind.__module__}.{kind.__qualname__}{detail}", file=stream)
        for frame in traceback.extract_tb(item.__traceback__):
            print(f'    File "{frame.filename}", line {frame.lineno}, in {frame.name}', file=stream)
            if frame.line:
                print(f"      {frame.line}", file=stream)
