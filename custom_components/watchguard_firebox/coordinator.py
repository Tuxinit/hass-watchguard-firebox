"""Data update coordinator for the WatchGuard Firebox integration.

Two polling rhythms over the same CLI session:
- fast (scan interval, default 30 s): sysinfo, interfaces, ARP, DHCP,
  management sessions, locked-out accounts;
- slow (hourly): licences, upgrade history, signature update settings, VLANs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import (
    FireboxAuthError,
    FireboxClient,
    FireboxError,
    FireboxHostKeyError,
)
from .const import (
    CMD_ARP,
    CMD_DHCP,
    CMD_FEATURES,
    CMD_INTERFACE,
    CMD_LOCKED_OUT,
    CMD_LOGIN_USER,
    CMD_SIGNATURE,
    CMD_SYSINFO,
    CMD_UPGRADE,
    CMD_VLAN,
    CONF_POLL_DHCP,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    SLOW_POLL_INTERVAL,
)
from .parsers import (
    ArpEntry,
    DhcpLease,
    Feature,
    FireboxInterface,
    LoginSession,
    UpgradeRecord,
    Vlan,
    is_cli_error,
    parse_arp,
    parse_dhcp_leases,
    parse_features,
    parse_interfaces,
    parse_locked_out,
    parse_login_users,
    parse_signature_update,
    parse_sysinfo,
    parse_upgrade_history,
    parse_vlans,
)

_LOGGER = logging.getLogger(__name__)

type FireboxConfigEntry = ConfigEntry[FireboxCoordinator]

FAST_COMMANDS = [CMD_SYSINFO, CMD_INTERFACE, CMD_ARP, CMD_LOGIN_USER, CMD_LOCKED_OUT]
SLOW_COMMANDS = [CMD_FEATURES, CMD_UPGRADE, CMD_SIGNATURE, CMD_VLAN]


@dataclass(slots=True)
class SlowData:
    """Hourly snapshot."""

    edition: str | None = None
    features: dict[str, Feature] | None = None
    upgrades: list[UpgradeRecord] | None = None
    signature: dict | None = None
    vlans: dict[int, Vlan] = field(default_factory=dict)


@dataclass(slots=True)
class FireboxData:
    """One polling snapshot."""

    sysinfo: dict
    interfaces: dict[int, FireboxInterface]
    arp: list[ArpEntry]
    dhcp: list[DhcpLease] | None
    boot_time: datetime | None
    sessions: list[LoginSession] | None
    locked_out: int | None
    slow: SlowData
    own_ip: str | None
    own_user: str
    # MAC -> last time it was seen with a complete ARP entry (kept across polls)
    last_seen: dict[str, datetime] = field(default_factory=dict)

    @property
    def leases_by_mac(self) -> dict[str, DhcpLease]:
        return {lease.mac: lease for lease in self.dhcp or []}

    @property
    def arp_by_mac(self) -> dict[str, ArpEntry]:
        return {e.mac: e for e in self.arp if e.mac}

    def vlan_name(self, arp_interface: str) -> str:
        """'vlan5' -> 'JURASSIC DOMO' when known."""
        if arp_interface.startswith("vlan") and arp_interface[4:].isdigit():
            vlan = self.slow.vlans.get(int(arp_interface[4:]))
            if vlan:
                return vlan.name
        return arp_interface

    @property
    def other_sessions(self) -> list[LoginSession]:
        """Management sessions other than the one Home Assistant holds."""
        return [
            s
            for s in self.sessions or []
            if not (s.user == self.own_user and s.ip == self.own_ip)
        ]


class FireboxCoordinator(DataUpdateCoordinator[FireboxData]):
    """Poll the Firebox CLI."""

    config_entry: FireboxConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: FireboxConfigEntry, client: FireboxClient
    ) -> None:
        scan = entry.options.get("scan_interval", DEFAULT_SCAN_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan),
        )
        self.client = client
        self._last_seen: dict[str, datetime] = {}
        self._unsupported: set[str] = set()
        self._slow = SlowData()
        self._slow_at: datetime | None = None

    def _ok(self, out: dict[str, str], cmd: str) -> str | None:
        """Return command output, or None (and stop polling it) if refused."""
        text = out.get(cmd)
        if text is None:
            return None
        if is_cli_error(text):
            _LOGGER.warning("`%s` refused by the Firebox (role too limited?), disabling it", cmd)
            self._unsupported.add(cmd)
            return None
        return text

    async def _async_update_data(self) -> FireboxData:
        now = dt_util.utcnow()
        commands = list(FAST_COMMANDS)
        if self.config_entry.options.get(CONF_POLL_DHCP, True):
            commands.append(CMD_DHCP)
        slow_due = self._slow_at is None or now - self._slow_at >= timedelta(
            seconds=SLOW_POLL_INTERVAL
        )
        if slow_due:
            commands += SLOW_COMMANDS
        commands = [c for c in commands if c not in self._unsupported]

        try:
            out = await self.client.run(commands)
        except (FireboxAuthError, FireboxHostKeyError) as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except FireboxError as err:
            raise UpdateFailed(f"Firebox unreachable: {err}") from err

        sysinfo = parse_sysinfo(out[CMD_SYSINFO])
        if sysinfo.get("serial_number") is None:
            raise UpdateFailed("Unexpected `show sysinfo` output")

        # ---- slow data
        if slow_due:
            self._slow_at = now
            if (text := self._ok(out, CMD_FEATURES)) is not None:
                parsed = parse_features(text)
                self._slow.edition = parsed["edition"]
                self._slow.features = parsed["features"]
            if (text := self._ok(out, CMD_UPGRADE)) is not None:
                tz = dt_util.get_default_time_zone()
                records = parse_upgrade_history(text)
                for r in records:
                    if r.time is not None:
                        r.time = r.time.replace(tzinfo=tz)
                self._slow.upgrades = records
            if (text := self._ok(out, CMD_SIGNATURE)) is not None:
                self._slow.signature = parse_signature_update(text)
            if (text := self._ok(out, CMD_VLAN)) is not None:
                self._slow.vlans = parse_vlans(text)

        # ---- fast data
        dhcp = None
        if (text := self._ok(out, CMD_DHCP)) is not None:
            dhcp = parse_dhcp_leases(text)
        sessions = None
        if (text := self._ok(out, CMD_LOGIN_USER)) is not None:
            sessions = parse_login_users(text)
        locked = None
        if (text := self._ok(out, CMD_LOCKED_OUT)) is not None:
            locked = parse_locked_out(text)

        arp = parse_arp(out[CMD_ARP])
        for entry in arp:
            if entry.mac:
                self._last_seen[entry.mac] = now

        uptime = sysinfo.get("uptime")
        boot_time = None
        if uptime is not None:
            boot_time = (now - timedelta(seconds=uptime)).replace(second=0, microsecond=0)
            # keep boot time stable across polls (avoid a state change every 30 s)
            if self.data and self.data.boot_time and abs(
                (self.data.boot_time - boot_time).total_seconds()
            ) < 120:
                boot_time = self.data.boot_time

        return FireboxData(
            sysinfo=sysinfo,
            interfaces=parse_interfaces(out[CMD_INTERFACE]),
            arp=arp,
            dhcp=dhcp,
            boot_time=boot_time,
            sessions=sessions,
            locked_out=locked,
            slow=self._slow,
            own_ip=self.client.local_ip,
            own_user=self.client.username,
            last_seen=self._last_seen,
        )
