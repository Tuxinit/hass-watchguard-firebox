"""Data update coordinator for the WatchGuard Firebox integration."""

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
    CMD_INTERFACE,
    CMD_SYSINFO,
    CONF_POLL_DHCP,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .parsers import (
    ArpEntry,
    DhcpLease,
    FireboxInterface,
    is_cli_error,
    parse_arp,
    parse_dhcp_leases,
    parse_interfaces,
    parse_sysinfo,
)

_LOGGER = logging.getLogger(__name__)

type FireboxConfigEntry = ConfigEntry[FireboxCoordinator]


@dataclass(slots=True)
class FireboxData:
    """One polling snapshot."""

    sysinfo: dict
    interfaces: dict[int, FireboxInterface]
    arp: list[ArpEntry]
    dhcp: list[DhcpLease] | None
    boot_time: datetime | None
    # MAC -> last time it was seen with a complete ARP entry (kept across polls)
    last_seen: dict[str, datetime] = field(default_factory=dict)

    @property
    def leases_by_mac(self) -> dict[str, DhcpLease]:
        return {lease.mac: lease for lease in self.dhcp or []}

    @property
    def arp_by_mac(self) -> dict[str, ArpEntry]:
        return {e.mac: e for e in self.arp if e.mac}


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
        self._dhcp_supported = True

    async def _async_update_data(self) -> FireboxData:
        commands = [CMD_SYSINFO, CMD_INTERFACE, CMD_ARP]
        poll_dhcp = self.config_entry.options.get(CONF_POLL_DHCP, True) and self._dhcp_supported
        if poll_dhcp:
            commands.append(CMD_DHCP)

        try:
            out = await self.client.run(commands)
        except (FireboxAuthError, FireboxHostKeyError) as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except FireboxError as err:
            raise UpdateFailed(f"Firebox unreachable: {err}") from err

        sysinfo = parse_sysinfo(out[CMD_SYSINFO])
        if sysinfo.get("serial_number") is None:
            raise UpdateFailed("Unexpected `show sysinfo` output")

        dhcp: list[DhcpLease] | None = None
        if poll_dhcp:
            if is_cli_error(out[CMD_DHCP]):
                _LOGGER.warning(
                    "`show dhcp lease` refused by the Firebox (role too limited?), disabling DHCP polling"
                )
                self._dhcp_supported = False
            else:
                dhcp = parse_dhcp_leases(out[CMD_DHCP])

        now = dt_util.utcnow()
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
            last_seen=self._last_seen,
        )
