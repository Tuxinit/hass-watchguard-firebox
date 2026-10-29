"""Test the SSH client against a fake Fireware CLI server (asyncssh)."""
import asyncio

import asyncssh
import pytest

from custom_components.watchguard_firebox.api import (
    FireboxAuthError,
    FireboxClient,
    FireboxHostKeyError,
)
from custom_components.watchguard_firebox.parsers import parse_arp, parse_sysinfo

from .conftest import OUTPUTS

pytestmark = pytest.mark.enable_socket


def _body(cmd: str) -> str:
    # fixtures contain the prompt/echo lines; strip them like a real CLI body
    lines = OUTPUTS[cmd].splitlines()
    return "\r\n".join(l for l in lines if not l.startswith("WG#"))


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == "good"


async def _handle(process: asyncssh.SSHServerProcess):
    process.stdout.write("\r\nWelcome\r\nWG#")
    buf = ""
    try:
        while True:
            data = await process.stdin.read(1)
            if not data:
                break
            if data in "\r\n":
                cmd, buf = buf.strip(), ""
                if not cmd:
                    continue
                if cmd == "exit":
                    break
                process.stdout.write(cmd + "\r\n")  # echo
                body = _body(cmd) if cmd in OUTPUTS else "% Error: invalid input"
                process.stdout.write(body + "\r\nWG#")
            else:
                buf += data
    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged, ConnectionError):
        pass
    process.exit(0)


@pytest.fixture
async def server(socket_enabled):
    key = asyncssh.generate_private_key("ssh-ed25519")
    srv = await asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=[key], process_factory=_handle,
        encoding="utf-8",
    )
    port = srv.sockets[0].getsockname()[1]
    yield port, key.get_fingerprint("sha256")
    srv.close()
    await srv.wait_closed()


async def test_run_commands_and_tofu(server):
    port, fp = server
    client = FireboxClient("127.0.0.1", port, "ha", "good")
    out = await client.run(["show sysinfo", "show arp", "show bogus"])
    assert client.host_key_fingerprint == fp
    assert parse_sysinfo(out["show sysinfo"])["system_name"] == "JURASSIC-T25"
    assert len(parse_arp(out["show arp"])) == 9
    assert "WG#" not in out["show arp"]
    assert "Error" in out["show bogus"]
    # session is reused
    out2 = await client.run(["show sysinfo"])
    assert parse_sysinfo(out2["show sysinfo"])["uptime"] > 0
    await client.close()


async def test_host_key_mismatch(server):
    port, _ = server
    client = FireboxClient("127.0.0.1", port, "ha", "good", "SHA256:not-the-key")
    with pytest.raises(FireboxHostKeyError):
        await client.run(["show sysinfo"])
    await client.close()


async def test_bad_password(server):
    port, _ = server
    client = FireboxClient("127.0.0.1", port, "ha", "bad")
    with pytest.raises(FireboxAuthError):
        await client.run(["show sysinfo"])
    await client.close()
