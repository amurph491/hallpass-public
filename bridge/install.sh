#!/bin/sh
# Hallpass bridge installer (POSIX sh; Linux and macOS).
#
#   curl -fsSL <origin>/downloads/install.sh | sh -s -- --from <origin>/downloads \
#       [--url AGENT_API_URL] [--agent UUID --client codex|claude|antigravity] [--name hallpass-NAME]
#
# Resolves one release from --from, downloads bridge.tar.gz and SHA256SUMS from
# that release's immutable URL, checks the archive against SHA256SUMS, checks its
# own manifest with `hallpass verify`, then installs it (or upgrades an older
# install) under ${XDG_DATA_HOME:-$HOME/.local/share}/hallpass.
#
# Release resolution: an instance serves <from>/RELEASE, naming its current
# release, and every file of that release under <from>/releases/<name>/. The
# installer reads RELEASE once and fetches everything through that immutable URL,
# so a deployment that swaps "current" mid-install cannot mix two releases. An
# origin without RELEASE (a GitHub release download, a static directory) is used
# as it is: it is already one immutable release.
# With --agent and --client it finishes by running `hallpass connect`, which
# prompts for the agent credential on the terminal (/dev/tty), so this works
# under `curl | sh`.
#
# Trust: the files are fetched over the transport you name in --from. HTTPS
# authenticates the host that serves them; SHA256SUMS is served from the same
# place, so it detects damage in transit, not a compromised host. There is no
# detached signature yet. The installer never asks for, sends, or stores a
# credential; it never uses sudo.
#
# Options:
#   --from URL       downloads origin: https://host[:port][/path], or http:// to a
#                    numeric loopback address (127.x.x.x, [::1]). Required.
#   --url URL        agent API endpoint passed to `hallpass connect` (same rule, no path)
#   --agent UUID     agent id to connect (requires --client)
#   --client NAME    codex, claude, or antigravity (requires --agent)
#   --name NAME      MCP server name passed to `hallpass connect`: hallpass-NAME (requires --agent)
#   --prefix DIR     install under DIR (absolute) instead of the default
#   --repair         replace a damaged or modified bridge with this release (also
#                    --force). Credentials, client configuration and every file
#                    outside <prefix>/bridge are kept; files inside it that are
#                    not part of the package are never deleted.
#   --no-wrapper     do not write ~/.local/bin/hallpass
#   -h, --help       show this text
#
# HALLPASS_DEBUG=1 traces every command (set -x).

# The whole script is one function called on the last line, so a truncated
# download cannot run a partial script, and `sh` has read all of stdin before
# any child process runs.
main() {
  set -eu
  if [ "${HALLPASS_DEBUG:-}" = 1 ]; then set -x; fi

  from=
  agent_url=
  agent=
  client=
  server_name=
  prefix=
  repair=0
  wrapper=1
  tmp=

  while [ "$#" -gt 0 ]; do
    case $1 in
      --from|--url|--agent|--client|--name|--prefix)
        [ "$#" -ge 2 ] || die "$1 requires a value."
        case $1 in
          --from) from=$2 ;;
          --url) agent_url=$2 ;;
          --agent) agent=$2 ;;
          --client) client=$2 ;;
          --name) server_name=$2 ;;
          --prefix) prefix=$2 ;;
        esac
        shift 2
        ;;
      --from=*|--url=*|--agent=*|--client=*|--name=*|--prefix=*)
        die "write ${1%%=*} VALUE with a space, not an equals sign."
        ;;
      --repair|--force) repair=1; shift ;;
      --no-wrapper) wrapper=0; shift ;;
      -h|--help) usage; return 0 ;;
      *) die "unknown option: $1 (see --help)." ;;
    esac
  done

  [ -n "$from" ] || die "--from is required, for example: --from https://admin.example.com/downloads"
  from=$(normalize_endpoint '--from' "$from" path)
  if [ -n "$agent_url" ]; then agent_url=$(normalize_endpoint '--url' "$agent_url" nopath); fi
  if [ -n "$agent" ] || [ -n "$client" ]; then
    [ -n "$agent" ] && [ -n "$client" ] || die "--agent and --client must be given together."
    valid_uuid "$agent" || die "--agent must be a UUID like 123e4567-e89b-12d3-a456-426614174000."
    case $client in codex|claude|antigravity) ;; *) die "--client must be codex, claude, or antigravity." ;; esac
  elif [ -n "$agent_url" ]; then
    say "Note: --url is only used when --agent and --client are also given; it is shown in the next-step command."
  fi
  if [ -n "$server_name" ]; then
    valid_server_name "$server_name" || die "--name must be hallpass- followed by 1-24 lowercase letters, digits, or inner hyphens, like hallpass-research."
    [ -n "$agent" ] || die "--name is only used with --agent and --client."
  fi

  [ -n "${HOME:-}" ] || die "HOME is not set."
  if [ -z "$prefix" ]; then prefix=${XDG_DATA_HOME:-$HOME/.local/share}/hallpass; fi
  case $prefix in
    /*) ;;
    *) die "the install prefix must be an absolute path." ;;
  esac
  case $prefix in
    *[\"\$\`\\]*) die "the install prefix must not contain quotes, dollar signs, backticks or backslashes." ;;
  esac

  check_prerequisites

  tmp=$(mktemp -d "${TMPDIR:-/tmp}/hallpass-install.XXXXXXXX") || die "could not create a temporary directory."
  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  release_base=$(resolve_release "$from")
  say "Downloading the bridge from $release_base"
  fetch "$release_base" SHA256SUMS
  fetch "$release_base" bridge.tar.gz
  verify_download

  say "Unpacking"
  mkdir "$tmp/extract"
  check_archive_members "$tmp/bridge.tar.gz"
  tar -xzf "$tmp/bridge.tar.gz" -C "$tmp/extract" </dev/null
  new_root=$tmp/extract/bridge
  [ -d "$new_root" ] && [ ! -L "$new_root" ] || die "the archive does not contain a bridge/ directory."
  new_cli=$new_root/bin/hallpass
  [ -x "$new_cli" ] || die "the archive is missing bin/hallpass."
  if ! output=$("$new_cli" verify 2>&1 </dev/null); then
    printf '%s\n' "$output" >&2
    die "the extracted bridge failed its own manifest verification; nothing was installed."
  fi
  new_version=$(cat "$new_root/VERSION")

  target=$prefix/bridge
  installed_version=
  if [ -e "$target" ] || [ -L "$target" ]; then
    installed_version=$(cat "$target/VERSION" 2>/dev/null || true)
    [ -n "$installed_version" ] || installed_version=unknown
  fi

  if [ -z "$installed_version" ]; then
    say "Installing $new_version into $prefix"
    "$new_cli" bridge install --prefix "$prefix" </dev/null
  elif [ "$repair" -eq 1 ]; then
    say "Installed version: $installed_version"
    say "New version:       $new_version"
    say "Repairing (credentials and client configuration are kept)"
    "$new_cli" bridge repair --prefix "$prefix" </dev/null
  elif [ "$installed_version" = "$new_version" ]; then
    say "Installed version: $installed_version"
    say "New version:       $new_version"
    # The same version label says nothing about the files on disk: verify them before claiming success.
    if ! output=$("$new_cli" bridge check --prefix "$prefix" 2>&1 </dev/null); then
      printf '%s\n' "$output" >&2
      die "the installed bridge is $installed_version but its files do not verify. Run this command again with --repair to replace it; credentials and client configuration are kept."
    fi
    say "Already up to date; the installed files verify."
  else
    say "Installed version: $installed_version"
    say "New version:       $new_version"
    say "Upgrading"
    if ! "$new_cli" bridge upgrade --prefix "$prefix" </dev/null; then
      die "the upgrade did not complete and the installed bridge was left as it was. If it was modified or damaged, run this command again with --repair; credentials and client configuration are kept."
    fi
  fi

  installed_cli=$target/bin/hallpass
  [ -x "$installed_cli" ] || die "the installed CLI is missing at $installed_cli."
  if [ "$wrapper" -eq 1 ]; then write_wrapper "$installed_cli"; fi

  # The temporary directory is not needed past this point, and exec would skip the EXIT trap.
  cleanup
  trap - EXIT HUP INT TERM

  if [ -n "$agent" ]; then
    set -- connect "$client" --agent "$agent"
    if [ -n "$agent_url" ]; then set -- "$@" --url "$agent_url"; fi
    if [ -n "$server_name" ]; then set -- "$@" --name "$server_name"; fi
    say "Connecting $client to agent $agent"
    exec "$installed_cli" "$@"
  fi

  say ""
  say "Installed Hallpass bridge $(cat "$target/VERSION")."
  say "Next, connect an agent (the Hallpass admin UI shows the exact command), or run:"
  next="$(shquote "$installed_cli") connect <codex|claude|antigravity> --agent <AGENT_UUID>"
  if [ -n "$agent_url" ]; then next="$next --url $(shquote "$agent_url")"; fi
  say "  $next"
}

usage() {
  cat <<'EOF'
Usage: install.sh --from ORIGIN [--url AGENT_API_URL] [--agent UUID --client NAME] [--name hallpass-NAME] [options]

  --from URL       downloads origin: https://host[:port][/path], or http:// to a
                   numeric loopback address (127.x.x.x, [::1]). Required.
  --url URL        agent API endpoint passed to `hallpass connect` (same rule, no path)
  --agent UUID     agent id to connect (requires --client)
  --client NAME    codex, claude, or antigravity (requires --agent)
  --name NAME      MCP server name for `hallpass connect`: hallpass-NAME, 1-24 lowercase
                   letters, digits, or inner hyphens (requires --agent)
  --prefix DIR     install under DIR (absolute) instead of
                   ${XDG_DATA_HOME:-$HOME/.local/share}/hallpass
  --repair         replace a damaged or modified bridge with this release (also
                   --force); credentials and client configuration are kept
  --no-wrapper     do not write ~/.local/bin/hallpass
  -h, --help       show this text

Set HALLPASS_DEBUG=1 to trace every command.
EOF
}

say() { printf '%s\n' "$*"; }

warn() { printf 'install: %s\n' "$*" >&2; }

die() {
  printf 'install: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "${tmp:-}" ] && [ -d "$tmp" ]; then rm -rf -- "$tmp"; fi
  tmp=
}

# Single-quote a value for display in a command the user may paste.
shquote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# hallpass-<slug>: a slug of 1-24 lowercase letters, digits, and inner hyphens (the same rule as `hallpass --name`).
# The character list is spelled out because a-z ranges depend on the locale in some shells.
valid_server_name() {
  case $1 in
    hallpass-?*) ;;
    *) return 1 ;;
  esac
  slug=${1#hallpass-}
  case $slug in
    -*|*-|*[!abcdefghijklmnopqrstuvwxyz0123456789-]*) return 1 ;;
  esac
  [ "${#slug}" -le 24 ]
}

valid_uuid() {
  case $1 in
    ????????-????-????-????-????????????) ;;
    *) return 1 ;;
  esac
  case $1 in
    *[!0-9a-fA-F-]*) return 1 ;;
  esac
  return 0
}

# canonical_ipv6 TEXT: the RFC 5952 form of an IPv6 literal (no brackets), or a failure. Hex digits and colons
# only (no IPv4-embedded spellings), and an IPv4-mapped address is refused, so each address has one spelling.
canonical_ipv6() {
  printf '%s\n' "$1" | tr 'A-F' 'a-f' | awk '
    function group_ok(g) { return g ~ /^[0-9a-f][0-9a-f]?[0-9a-f]?[0-9a-f]?$/ }
    function join(from, to,   out, i) {
      out = ""
      for (i = from; i <= to; i++) out = out (i > from ? ":" : "") v[i]
      return out
    }
    {
      s = $0
      if (s !~ /^[0-9a-f:]+$/) exit 1
      idx = index(s, "::")
      if (idx == 0) {
        if (split(s, g, ":") != 8) exit 1
        for (i = 1; i <= 8; i++) { if (!group_ok(g[i])) exit 1; v[i] = g[i] }
      } else {
        left = substr(s, 1, idx - 1)
        right = substr(s, idx + 2)
        if (index(right, "::") > 0) exit 1
        nl = (left == "") ? 0 : split(left, lg, ":")
        nr = (right == "") ? 0 : split(right, rg, ":")
        if (nl + nr > 7) exit 1
        for (i = 1; i <= nl; i++) { if (!group_ok(lg[i])) exit 1; v[i] = lg[i] }
        for (i = 1; i <= 8 - nl - nr; i++) v[nl + i] = "0"
        for (i = 1; i <= nr; i++) { if (!group_ok(rg[i])) exit 1; v[8 - nr + i] = rg[i] }
      }
      for (i = 1; i <= 8; i++) { sub(/^0+/, "", v[i]); if (v[i] == "") v[i] = "0" }
      if (v[1] == "0" && v[2] == "0" && v[3] == "0" && v[4] == "0" && v[5] == "0" && v[6] == "ffff") exit 1
      best = 0; start = 0; i = 1
      while (i <= 8) {
        if (v[i] == "0") {
          j = i
          while (j <= 8 && v[j] == "0") j++
          if (j - i > best) { best = j - i; start = i }
          i = j
        } else i++
      }
      if (best < 2) print join(1, 8)
      else print join(1, start - 1) "::" join(start + best, 8)
    }'
}

# strict_ipv4 TEXT: four decimal octets, each 0-255 without leading zeros.
strict_ipv4() {
  printf '%s\n' "$1" | awk -F. '
    NF != 4 { exit 1 }
    { for (i = 1; i <= 4; i++) if ($i !~ /^(0|[1-9][0-9]?[0-9]?)$/ || $i + 0 > 255) exit 1 }'
}

# valid_dns_name TEXT (lowercase): at least two labels of 1-63 letters, digits and inner hyphens, a top label
# that starts with a letter, and at most 253 characters overall.
valid_dns_name() {
  printf '%s\n' "$1" | awk -F. '
    length($0) > 253 || NF < 2 { exit 1 }
    { for (i = 1; i <= NF; i++) if (length($i) > 63 || $i !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) exit 1 }
    $NF !~ /^[a-z]/ { exit 1 }'
}

# normalize_endpoint LABEL VALUE path|nopath
# Prints the canonical scheme://host[:port][/path]: https:// to one exact host (a DNS name with two or more
# labels, an IPv4 address, or a bracketed IPv6 literal) with an optional port, or http:// only to a numeric
# loopback literal. No userinfo, query, fragment, or (for nopath) path. The host is lowercase, an IPv6 literal is
# compressed, and a port that is the scheme's default is dropped. This is the rule the bridge, the CLI, the
# server and the admin UI apply too; bridge/tests/endpoint_vectors.json pins them to the same results.
normalize_endpoint() {
  _label=$1
  _value=$2
  _mode=$3
  case $_value in
    https://*) _scheme=https; _default_port=443; _rest=${_value#https://} ;;
    http://*) _scheme=http; _default_port=80; _rest=${_value#http://} ;;
    *) die "$_label must start with https:// (or http:// to a loopback address such as http://127.0.0.1:8081)." ;;
  esac
  [ -n "$_rest" ] || die "$_label has no host."
  case $_rest in
    *[!]A-Za-z0-9._~:/[-]*) die "$_label must not contain user info, a query, a fragment, spaces, or other special characters." ;;
  esac
  _authority=${_rest%%/*}
  _path=${_rest#"$_authority"}
  [ -n "$_authority" ] || die "$_label has no host."

  case $_authority in
    \[*\]|\[*\]:*)
      _host=${_authority%%]*}]
      _port=${_authority#"$_host"}
      _port=${_port#:}
      ;;
    \[*) die "$_label has an unterminated IPv6 literal." ;;
    *:*:*) die "$_label has more than one colon; write IPv6 addresses in brackets." ;;
    *:*) _host=${_authority%%:*}; _port=${_authority#*:} ;;
    *) _host=$_authority; _port= ;;
  esac
  case $_authority in
    *:) die "$_label has an empty port." ;;
  esac
  if [ -n "$_port" ]; then
    case $_port in
      *[!0-9]*) die "$_label has a non-numeric port." ;;
    esac
    [ "${#_port}" -le 5 ] || die "$_label has an invalid port."
    _port=$(printf '%s' "$_port" | sed 's/^0*//')
    [ -n "$_port" ] && [ "$_port" -le 65535 ] || die "$_label has an invalid port."
    if [ "$_port" -eq "$_default_port" ]; then _port=; fi
  fi

  _host=$(printf '%s' "$_host" | tr 'A-Z' 'a-z')
  case $_host in
    \[*\])
      _inner=${_host#\[}
      _inner=${_inner%\]}
      _inner=$(canonical_ipv6 "$_inner") || die "$_label has an invalid IPv6 literal."
      _host="[$_inner]"
      if [ "$_scheme" = http ] && [ "$_host" != '[::1]' ]; then
        die "$_label may use http:// only for a numeric loopback address (127.0.0.1 or [::1]); use https:// for a host name."
      fi
      ;;
    *[!0-9.]*)
      if [ "$_scheme" = http ]; then
        die "$_label may use http:// only for a numeric loopback address (127.0.0.1 or [::1]); use https:// for a host name."
      fi
      case $_host in
        *.*) valid_dns_name "$_host" || die "$_label has an invalid host name." ;;
        *) die "$_label must name a host with a domain (for example admin.example.com)." ;;
      esac
      ;;
    *)
      strict_ipv4 "$_host" || die "$_label is not a valid IPv4 address."
      if [ "$_scheme" = http ]; then
        case $_host in
          127.*) ;;
          *) die "$_label may use http:// only for a numeric loopback address (127.0.0.1 or [::1]); use https:// for a host name." ;;
        esac
      fi
      ;;
  esac

  if [ "$_mode" = nopath ]; then
    case $_path in
      ''|/) _path= ;;
      *) die "$_label must be just scheme://host[:port], with no path." ;;
    esac
  else
    case $_path in
      */) _path=${_path%/} ;;
    esac
    case $_path in
      *//*|*/./*|*/../*|*/.|*/..) die "$_label has an invalid path." ;;
    esac
  fi
  if [ -n "$_port" ]; then _authority=$_host:$_port; else _authority=$_host; fi
  printf '%s://%s%s\n' "$_scheme" "$_authority" "$_path"
}

# --- prerequisites ------------------------------------------------------------

os_name() { uname -s 2>/dev/null || echo unknown; }

java_hint() {
  case $(os_name) in
    Darwin)
      say "  Install Java 17 or newer:  brew install openjdk@21"
      say "  Then put it on PATH, as Homebrew's note says, for example:"
      say "    echo 'export PATH=\"\$(brew --prefix openjdk@21)/bin:\$PATH\"' >> ~/.zshrc"
      ;;
    Linux)
      _ids=
      if [ -r /etc/os-release ]; then
        _ids=$(sed -n 's/^ID=//p;s/^ID_LIKE=//p' /etc/os-release | tr -d '"' | tr '\n' ' ')
      fi
      case " $_ids " in
        *" debian "*|*" ubuntu "*) say "  Install Java 17 or newer:  sudo apt install openjdk-21-jre-headless" ;;
        *" fedora "*|*" rhel "*|*" centos "*) say "  Install Java 17 or newer:  sudo dnf install java-21-openjdk-headless" ;;
        *" arch "*) say "  Install Java 17 or newer:  sudo pacman -S jre21-openjdk-headless" ;;
        *" alpine "*) say "  Install Java 17 or newer:  sudo apk add openjdk21-jre-headless" ;;
        *) say "  Install a Java 17 or newer runtime (for example from https://adoptium.net/) and put java on PATH." ;;
      esac
      ;;
    *) say "  Install a Java 17 or newer runtime (for example from https://adoptium.net/) and put java on PATH." ;;
  esac
}

# Prints the major Java version, or nothing when java is missing or unusable.
java_major() {
  command -v java >/dev/null 2>&1 || return 0
  _text=$(java -version 2>&1 </dev/null | sed -n '1p') || return 0
  _numbers=$(printf '%s\n' "$_text" | sed -nE 's/.*version "([0-9]+)(\.([0-9]+))?.*/\1 \3/p')
  _major=${_numbers%% *}
  _minor=${_numbers#* }
  case $_major in
    ''|*[!0-9]*) return 0 ;;
    1) case $_minor in ''|*[!0-9]*) return 0 ;; *) printf '%s\n' "$_minor" ;; esac ;;
    *) printf '%s\n' "$_major" ;;
  esac
}

check_prerequisites() {
  _missing=0
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl is required."
    _missing=1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 (3.9 or newer) is required."
    case $(os_name) in
      Darwin) say "  Install it with:  xcode-select --install   (or: brew install python)" ;;
      *) say "  Install it with your package manager, for example: sudo apt install python3" ;;
    esac
    _missing=1
  elif ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' </dev/null 2>/dev/null; then
    warn "python3 is older than 3.9."
    _missing=1
  fi
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    warn "sha256sum or shasum is required to verify the download."
    _missing=1
  fi
  _java=$(java_major)
  if [ -z "$_java" ] || [ "$_java" -lt 17 ]; then
    if [ -z "$_java" ]; then warn "Java 17 or newer is required, and none was found on PATH."; else warn "Java 17 or newer is required; found Java $_java."; fi
    java_hint
    _missing=1
  fi
  if [ "$_missing" -ne 0 ]; then die "install the missing requirements above and run this again. Nothing was downloaded or changed."; fi
}

# --- download and verify --------------------------------------------------------

# resolve_release ORIGIN: prints the base URL every file of one release is fetched from. Reads ORIGIN/RELEASE
# once. When it names a release, the base is ORIGIN/releases/NAME, an immutable URL: a deployment that moves
# "current" while the install runs cannot change what these two requests return. No RELEASE file (404) means
# ORIGIN is itself one release, so it is used as it is. Any other answer is a failure.
resolve_release() {
  _origin=$1
  case $_origin in
    https://*) _proto='=https' ;;
    *) _proto='=http' ;;
  esac
  _code=$(curl --silent --show-error --proto "$_proto" --tlsv1.2 --max-redirs 0 \
    --connect-timeout 15 --max-time 60 --max-filesize 65536 \
    --output "$tmp/RELEASE" --write-out '%{http_code}' "$_origin/RELEASE" </dev/null) \
    || die "could not reach $_origin/RELEASE."
  case $_code in
    200)
      _name=$(sed -n '1p' "$tmp/RELEASE")
      case $_name in
        ''|*[!A-Za-z0-9._+-]*) die "$_origin/RELEASE does not name a release." ;;
      esac
      [ "${#_name}" -le 160 ] || die "$_origin/RELEASE does not name a release."
      printf '%s/releases/%s\n' "$_origin" "$_name"
      ;;
    404) printf '%s\n' "$_origin" ;;
    *) die "$_origin/RELEASE answered HTTP $_code; expected 200 or 404 (redirects are not followed)." ;;
  esac
}

# fetch ORIGIN NAME: a single request that never follows a redirect. The protocol
# is pinned to the scheme the operator wrote, so an https origin cannot be
# downgraded and a loopback http origin cannot be pointed elsewhere.
fetch() {
  _origin=$1
  _name=$2
  case $_origin in
    https://*) _proto='=https' ;;
    *) _proto='=http' ;;
  esac
  # --fail covers 4xx and 5xx only. A 3xx is not followed (--max-redirs 0) and would leave an empty
  # or unrelated body, so only a plain 200 counts.
  _code=$(curl --fail --silent --show-error --proto "$_proto" --tlsv1.2 --max-redirs 0 \
    --connect-timeout 15 --max-time 300 --max-filesize 209715200 \
    --output "$tmp/$_name" --write-out '%{http_code}' "$_origin/$_name" </dev/null) \
    || die "could not download $_origin/$_name."
  [ "$_code" = 200 ] || die "$_origin/$_name answered HTTP $_code; expected 200 (redirects are not followed)."
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | sed 's/[[:space:]].*//'
  else
    shasum -a 256 "$1" | sed 's/[[:space:]].*//'
  fi
}

verify_download() {
  _expected=$(awk '$2 == "bridge.tar.gz" || $2 == "*bridge.tar.gz" { print $1 }' "$tmp/SHA256SUMS")
  case $_expected in
    ''|*[!0-9a-f]*) die "SHA256SUMS has no valid entry for bridge.tar.gz." ;;
  esac
  [ "${#_expected}" -eq 64 ] || die "SHA256SUMS has no valid entry for bridge.tar.gz."
  _actual=$(sha256_of "$tmp/bridge.tar.gz")
  [ "$_actual" = "$_expected" ] || die "bridge.tar.gz does not match SHA256SUMS; nothing was installed."
  say "Checksum OK ($_expected)"
}

# The archive must contain only regular files and directories under bridge/.
check_archive_members() {
  tar -tzf "$1" </dev/null | awk '
    /^\// || /(^|\/)\.\.(\/|$)/ { bad = 1 }
    !/^bridge(\/|$)/ { bad = 1 }
    END { exit bad ? 1 : 0 }' || die "the archive has entries outside bridge/; refusing to unpack it."
  tar -tvzf "$1" </dev/null | awk '
    substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" { bad = 1 }
    END { exit bad ? 1 : 0 }' || die "the archive contains links or special files; refusing to unpack it."
}

# --- wrapper --------------------------------------------------------------------

write_wrapper() {
  _cli=$1
  _bin=$HOME/.local/bin
  _wrapper=$_bin/hallpass
  _marker='# hallpass-bridge-wrapper-v1'
  if [ -L "$_wrapper" ] || { [ -e "$_wrapper" ] && ! grep -q "^$_marker\$" "$_wrapper" 2>/dev/null; }; then
    warn "not replacing $_wrapper, which this installer did not create. Run the CLI at $_cli instead."
    return 0
  fi
  mkdir -p "$_bin"
  _staged=$_bin/.hallpass.$$
  {
    printf '#!/bin/sh\n%s\nexec "%s" "$@"\n' "$_marker" "$_cli"
  } > "$_staged"
  chmod 755 "$_staged"
  mv -f "$_staged" "$_wrapper"
  case ":$PATH:" in
    *":$_bin:"*) ;;
    *)
      warn "$_bin is not on your PATH, so 'hallpass' will not be found yet."
      case ${SHELL:-} in
        */zsh) _rc='~/.zshrc' ;;
        */bash) _rc='~/.bashrc' ;;
        *) _rc='your shell profile' ;;
      esac
      say "  Add it with:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> $_rc"
      ;;
  esac
}

main "$@"
