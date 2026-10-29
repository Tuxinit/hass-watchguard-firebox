"""Presence detection from the Firebox ARP table (like hass-pfsense).

A tracked device is "home" when its MAC was seen with a complete ARP entry
within the last ``consider_home`` seconds (sliding window).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from homeassistant.components.device_tracker import ScannerEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import CONF_CONSIDER_HOME, CONF_TRACKED_MACS, DEFAULT_CONSIDER_HOME
from .coordinator import FireboxConfigEntry, FireboxCoordinator

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: FireboxConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    macs = {m.lower() for m in entry.options.get(CONF_TRACKED_MACS, [])}
    consider_home = entry.options.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME)
    async_add_entities(
        FireboxScanner(coordinator, mac, consider_home) for mac in sorted(macs)
    )


class FireboxScanner(CoordinatorEntity[FireboxCoordinator], ScannerEntity):
    """A device tracked through the Firebox ARP table."""

    _attr_translation_key = "tracked_device"

    def __init__(
        self, coordinator: FireboxCoordinator, mac: str, consider_home: int
    ) -> None:
        super().__init__(coordinator)
        self._mac = mac
        self._consider_home = timedelta(seconds=consider_home)
        self._attr_unique_id = f"{coordinator.config_entry.unique_id}_tracker_{mac}"

    @property
    def entity_registry_enabled_default(self) -> bool:
        # The user explicitly picked this device: enable it even if away now.
        return True

    @property
    def mac_address(self) -> str:
        return self._mac

    @property
    def name(self) -> str:
        lease = self.coordinator.data.leases_by_mac.get(self._mac)
        if lease and lease.hostname:
            return lease.hostname
        return self._mac

    @property
    def hostname(self) -> str | None:
        lease = self.coordinator.data.leases_by_mac.get(self._mac)
        return lease.hostname if lease else None

    @property
    def ip_address(self) -> str | None:
        arp = self.coordinator.data.arp_by_mac.get(self._mac)
        if arp:
            return arp.ip
        lease = self.coordinator.data.leases_by_mac.get(self._mac)
        return lease.ip if lease else None

    @property
    def is_connected(self) -> bool:
        seen = self.coordinator.data.last_seen.get(self._mac)
        return seen is not None and dt_util.utcnow() - seen <= self._consider_home

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self.coordinator.data
        attrs: dict[str, Any] = {}
        if (seen := data.last_seen.get(self._mac)) is not None:
            attrs["last_seen"] = seen.isoformat()
        if (arp := data.arp_by_mac.get(self._mac)) is not None:
            attrs["interface"] = arp.interface
        if (lease := data.leases_by_mac.get(self._mac)) is not None:
            attrs["dhcp_interface"] = lease.interface
            if lease.end:
                attrs["lease_end"] = lease.end.isoformat()
        return attrs
