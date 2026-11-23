#!/usr/bin/env python3
"""Exercise three independent MCP bridges, optionally crossing Windows WSL interop.

Run from WSL after: sbt -batch bridge/stageRuntimeClasspath
No real Hallpass or Slack credentials are used.
"""

import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOL = {
    "name": "slack_search_messages",
    "description": "Search messages in the authorized Slack workspace.",
    "inputSchema": {
        "type": "object",
        "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 1000}},
        "required": ["query"],
        "additionalProperties": False,
    },
}
TOKENS = {name: "ac1." + name * 16 + "." + name.lower() * 43 for name in "ABC"}


class FakeAgentApi(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), FakeHandler)
        self.allowed = set(TOKENS)
        self.observed = []
        self.calls = []
        self.arguments = []
        self.lock = threading.Lock()


class FakeHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def identity(self):
        authorization = self.headers.get("Authorization", "")
        return next((name for name, token in TOKENS.items() if authorization == "Bearer " + token), None)

    def do_GET(self):
        identity = self.identity()
        with self.server.lock:
            self.server.observed.append((identity, self.path))
            allowed = identity in self.server.allowed
        if self.path != "/api/agent/tools":
            self.respond(404, {})
        elif identity is None:
            self.respond(401, {})
        else:
            self.respond(200, {"tools": [TOOL] if allowed else []})

    def do_POST(self):
        identity = self.identity()
        with self.server.lock:
            allowed = identity in self.server.allowed
            if allowed:
                self.server.calls.append(identity)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.path != f"/api/agent/tools/{TOOL['name']}/call":
            self.respond(404, {})
        elif not allowed:
            self.respond(403, {})
        else:
            # The call contract: a JSON object with exactly one key, "arguments", that is itself an object.
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            if not (isinstance(body, dict) and set(body) == {"arguments"} and isinstance(body["arguments"], dict)):
                self.respond(400, {"error": "invalid_request"})
                return
            with self.server.lock:
                self.server.arguments.append(body["arguments"])
            self.respond(200, {"content": "fake-result", "correlationId": "smoke-" + identity})


class McpClient:
    def __init__(self, command, env=None):
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, bufsize=0,
        )
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.next_id = 1
        self.transcript = []
        self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "hallpass-cross-platform-smoke", "version": "1"},
        })
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def send(self, value):
        self.process.stdin.write((json.dumps(value) + "\n").encode())
        self.process.stdin.flush()

    def request(self, method, params=None):
        request_id = self.next_id
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if not self.selector.select(max(0, deadline - time.monotonic())):
                break
            line = self.process.stdout.readline()
            if not line:
                raise AssertionError(f"MCP process exited before {method}: {self.process.poll()}")
            self.transcript.append(line)
            response = json.loads(line)
            if response.get("id") == request_id:
                if "error" in response:
                    raise AssertionError(f"MCP {method} returned an error: {response['error']}")
                return response["result"]
        raise AssertionError(f"MCP {method} timed out")

    def tools(self):
        return [tool["name"] for tool in self.request("tools/list")["tools"]]

    def close(self):
        self.process.terminate()
        try:
            _, stderr = self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            _, stderr = self.process.communicate(timeout=5)
        self.selector.close()
        return stderr


def wait_for_tools(client, expected):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        if client.tools() == expected:
            return
        time.sleep(0.2)
    raise AssertionError(f"Tool visibility did not become {expected}")


def assert_rejected_credential_fails_fast(launcher, root, port):
    """A credential the API rejects must stop the bridge at startup with one clear stderr line and no MCP output."""
    token = "ac1." + "D" * 16 + "." + "d" * 43
    credential_file = root / "rejected"
    endpoint = f"http://127.0.0.1:{port}"
    credential_file.write_text(f"hallpass-agent-profile/1\nendpoint={endpoint}\ncredential={token}\n")
    os.chmod(credential_file, 0o600)
    env = os.environ.copy()
    env.update({"HALLPASS_AGENT_API_URL": endpoint, "HALLPASS_AGENT_CREDENTIAL_FILE": str(credential_file)})
    result = subprocess.run([str(launcher)], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    stderr = result.stderr.decode()
    assert result.returncode != 0, "bridge must exit non-zero when its credential is rejected"
    assert result.stdout == b"", "bridge must not write to the MCP channel when it refuses to start"
    assert "rejected" in stderr and endpoint in stderr and "hallpass doctor" in stderr, stderr
    assert len(stderr.strip().splitlines()) == 1, stderr
    assert token not in stderr, "bridge wrote a bearer to stderr"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows-antigravity", action="store_true", help="launch client C through Windows wsl.exe")
    parser.add_argument("--distro", help="WSL distribution used by --windows-antigravity")
    parser.add_argument("--launcher", type=Path, help="absolute path to an installed bridge launcher")
    args = parser.parse_args()
    if args.windows_antigravity and not shutil.which("wsl.exe"):
        raise SystemExit("wsl.exe is required for --windows-antigravity")
    if args.launcher and not args.launcher.is_absolute():
        raise SystemExit("--launcher must be an absolute path")
    launcher = args.launcher or Path(__file__).resolve().parents[1] / "bin" / "hallpass-bridge"
    if not launcher.is_file() or not os.access(launcher, os.X_OK):
        raise SystemExit(f"Bridge launcher is missing or not executable: {launcher}")
    server = FakeAgentApi()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    clients = {}
    try:
        with tempfile.TemporaryDirectory(prefix="hallpass-bridge-smoke-") as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            for name, token in TOKENS.items():
                credential_file = root / name
                credential_file.write_text(
                    f"hallpass-agent-profile/1\nendpoint=http://127.0.0.1:{server.server_port}\ncredential={token}\n"
                )
                os.chmod(credential_file, 0o600)
                settings = [f"HALLPASS_AGENT_API_URL=http://127.0.0.1:{server.server_port}",
                            f"HALLPASS_AGENT_CREDENTIAL_FILE={credential_file}"]
                if name == "C" and args.windows_antigravity:
                    command = ["wsl.exe"]
                    if args.distro:
                        command += ["--distribution", args.distro]
                    command += ["--exec", "/usr/bin/env", *settings, str(launcher)]
                    clients[name] = McpClient(command)
                else:
                    env = os.environ.copy()
                    env.update(dict(setting.split("=", 1) for setting in settings))
                    clients[name] = McpClient([str(launcher)], env)
            for client in clients.values():
                assert client.tools() == [TOOL["name"]], "authorized tool missing from first MCP listing"
            for name, client in clients.items():
                result = client.request("tools/call", {"name": TOOL["name"], "arguments": {"query": "smoke"}})
                assert "fake-result" in json.dumps(result), name
            with server.lock:
                assert sorted(server.calls) == ["A", "B", "C"]
                assert server.arguments == [{"query": "smoke"}] * 3, "arguments must be forwarded unchanged"
                server.allowed.remove("C")
                server.calls.clear()
            wait_for_tools(clients["C"], [])
            for name in ("A", "B"):
                result = clients[name].request("tools/call", {"name": TOOL["name"], "arguments": {"query": "still allowed"}})
                assert "fake-result" in json.dumps(result), name
            with server.lock:
                assert sorted(server.calls) == ["A", "B"]
                assert {name for name, _ in server.observed} == {"A", "B", "C"}
            # An old registration still names the previous server. The credential file binds it to the new one, so the
            # real bridge process must refuse to start and must never present the credential to the old URL.
            previous = FakeAgentApi()
            threading.Thread(target=previous.serve_forever, daemon=True).start()
            try:
                stale_env = os.environ.copy()
                stale_env["HALLPASS_AGENT_API_URL"] = f"http://127.0.0.1:{previous.server_port}"
                stale_env["HALLPASS_AGENT_CREDENTIAL_FILE"] = str(root / "A")
                stale = subprocess.run([str(launcher)], env=stale_env, input=b"", capture_output=True, timeout=30)
                assert stale.returncode != 0, "bridge started with an endpoint its credential file is not bound to"
                assert b"configuration is invalid" in stale.stderr, stale.stderr
                assert TOKENS["A"].encode() not in stale.stdout + stale.stderr
                assert previous.observed == [], "the credential was presented to an endpoint it is not bound to"
            finally:
                previous.shutdown()
                previous.server_close()
            assert_rejected_credential_fails_fast(launcher, root, server.server_port)
            transport = "Windows wsl.exe stdio" if args.windows_antigravity else "direct WSL stdio"
            print(f"PASS: three distinct bridge credentials; {transport}; isolated revocation; endpoint binding; rejected credential fails fast")
    finally:
        output = b""
        for client in clients.values():
            output += b"".join(client.transcript) + client.close()
        for token in TOKENS.values():
            if token.encode() in output:
                raise AssertionError("Bridge wrote a bearer to MCP stdout or stderr")
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
