"""SSH client for the WatchGuard Fireware CLI (port 4118).

The Fireware CLI is an interactive shell (no exec channel), so the client
opens one PTY session, waits for the prompt (e.g. ``WG#`` or ``WG>``),
sends commands one by one and reads until the prompt comes back.

The session is kept open between polls to avoid a login (and a log line on
the Firebox) every scan interval; it is re-opened transparently on error.

Host key: trust on first use. The fingerprint seen during setup is stored in
the config entry, and any later mismatch aborts the connection.
"""

from __future__ import annotations

import asyncio
import logging
import re

import asyncssh

from .parsers import clean

_LOGGER = logging.getLogger(__name__)

_PROMPT_RE = re.compile(r"(?m)^[A-Za-z0-9_.\-]+(?:\([^)]*\))?[#>]\s?$")
_MORE_RE = re.compile(r"-+\s*more\s*-+|--more--", re.IGNORECASE)

CONNECT_TIMEOUT = 15
COMMAND_TIMEOUT = 30


class FireboxError(Exception):
    """Base error."""


class FireboxConnectionError(FireboxError):
    """Cannot reach the Firebox."""


class FireboxAuthError(FireboxError):
    """Bad credentials."""


class FireboxHostKeyError(FireboxError):
    """The SSH host key changed since setup."""


class FireboxClient:
    """Persistent CLI session to a Firebox."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        host_key_fingerprint: str | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._expected_fp = host_key_fingerprint
        self._conn: asyncssh.SSHClientConnection | None = None
        self._proc: asyncssh.SSHClientProcess | None = None
        self._lock = asyncio.Lock()
        self.host_key_fingerprint: str | None = None

    # ------------------------------------------------------------------ #

    async def _open(self) -> None:
        try:
            self._conn = await asyncio.wait_for(
                asyncssh.connect(
                    self._host,
                    port=self._port,
                    username=self._username,
                    password=self._password,
                    known_hosts=None,  # verified below against the stored fingerprint
                    client_keys=None,
                    agent_path=None,
                    preferred_auth=("keyboard-interactive", "password"),
                    keepalive_interval=60,
                ),
                CONNECT_TIMEOUT,
            )
        except asyncssh.PermissionDenied as err:
            raise FireboxAuthError(str(err)) from err
        except (OSError, asyncssh.Error, TimeoutError) as err:
            raise FireboxConnectionError(f"{self._host}:{self._port}: {err}") from err

        key = self._conn.get_server_host_key()
        fingerprint = key.get_fingerprint("sha256") if key else None
        self.host_key_fingerprint = fingerprint
        if self._expected_fp and fingerprint != self._expected_fp:
            self._conn.close()
            self._conn = None
            raise FireboxHostKeyError(
                f"Host key mismatch for {self._host}: expected {self._expected_fp}, got {fingerprint}"
            )

        try:
            self._proc = await self._conn.create_process(
                term_type="vt100", term_size=(512, 1000), encoding="utf-8", errors="replace"
            )
            await self._read_until_prompt()
        except (OSError, asyncssh.Error, TimeoutError) as err:
            await self.close()
            raise FireboxConnectionError(f"CLI session failed: {err}") from err

    async def _read_until_prompt(self) -> str:
        assert self._proc is not None
        buf = ""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + COMMAND_TIMEOUT
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for CLI prompt")
            chunk = await asyncio.wait_for(self._proc.stdout.read(65536), remaining)
            if not chunk:
                raise FireboxConnectionError("CLI session closed by the Firebox")
            buf += chunk
            text = clean(buf)
            if _MORE_RE.search(text.splitlines()[-1] if text else ""):
                buf = _MORE_RE.sub("", buf)
                self._proc.stdin.write(" ")
                continue
            if _PROMPT_RE.search(text.rstrip("\n").splitlines()[-1] if text.strip() else ""):
                return text

    async def _exec(self, command: str) -> str:
        assert self._proc is not None
        self._proc.stdin.write(command + "\n")
        out = await self._read_until_prompt()
        lines = out.splitlines()
        # drop echoed command and trailing prompt
        if lines and command in lines[0]:
            lines = lines[1:]
        while lines and (not lines[-1].strip() or _PROMPT_RE.match(lines[-1].strip())):
            lines = lines[:-1]
        return "\n".join(lines)

    # ------------------------------------------------------------------ #

    async def run(self, commands: list[str]) -> dict[str, str]:
        """Run commands in the persistent session, reconnecting once on failure."""
        async with self._lock:
            for attempt in (1, 2):
                try:
                    if self._proc is None:
                        await self._open()
                    return {cmd: await self._exec(cmd) for cmd in commands}
                except (FireboxAuthError, FireboxHostKeyError):
                    raise
                except (FireboxConnectionError, OSError, asyncssh.Error, TimeoutError) as err:
                    await self._close_unlocked()
                    if attempt == 2:
                        if isinstance(err, FireboxConnectionError):
                            raise
                        raise FireboxConnectionError(str(err)) from err
                    _LOGGER.debug("CLI session lost (%s), reconnecting", err)
        raise FireboxConnectionError("unreachable")

    async def _close_unlocked(self) -> None:
        if self._proc is not None:
            try:
                self._proc.stdin.write("exit\n")
            except Exception:  # noqa: BLE001
                pass
            self._proc.close()
            self._proc = None
        if self._conn is not None:
            self._conn.close()
            try:
                await asyncio.wait_for(self._conn.wait_closed(), 5)
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    async def close(self) -> None:
        """Close the session."""
        await self._close_unlocked()
