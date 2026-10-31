"""Base entities for the WatchGuard Firebox integration.

Entities are spread over three devices so that the Home Assistant UI groups
them by theme:

- the Firebox itself ("status"): CPU, memory, firmware, licences, upgrades;
- "<name> Security", linked via the Firebox: subscriptions, admin sessions,
  threat counters (syslog), country map;
- "<name> Interfaces", linked via the Firebox: link status, VLANs, ARP, DHCP.
"""

from __future__ import annotations

from typing import Literal

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER
from .coordinator import FireboxCoordinator

Group = Literal["status", "security", "interfaces"]


def firebox_device_info(entry: ConfigEntry, sysinfo: dict, group: Group) -> DeviceInfo:
    """DeviceInfo for one of the three Firebox devices."""
    serial = entry.unique_id
    name = sysinfo.get("system_name") or entry.title
    model = f"Firebox {sysinfo['model']}" if sysinfo.get("model") else "Firebox"
    if group == "status":
        return DeviceInfo(
            identifiers={(DOMAIN, serial)},
            manufacturer=MANUFACTURER,
            model=model,
            name=name,
            serial_number=sysinfo.get("serial_number"),
            sw_version=sysinfo.get("version"),
            configuration_url=f"https://{entry.data[CONF_HOST]}:8080",
        )
    return DeviceInfo(
        identifiers={(DOMAIN, f"{serial}_{group}")},
        manufacturer=MANUFACTURER,
        model=model,
        translation_key=group,
        translation_placeholders={"name": name},
        via_device=(DOMAIN, serial),
    )


class FireboxEntity(CoordinatorEntity[FireboxCoordinator]):
    """Entity fed by the CLI coordinator."""

    _attr_has_entity_name = True

    def __init__(
        self, coordinator: FireboxCoordinator, key: str, group: Group = "status"
    ) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_{key}"
        self._attr_device_info = firebox_device_info(entry, coordinator.data.sysinfo, group)


class FireboxPushEntity(Entity):
    """Entity fed by the syslog receiver (push, no polling)."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator: FireboxCoordinator, key: str) -> None:
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_{key}"
        self._attr_device_info = firebox_device_info(
            entry, coordinator.data.sysinfo, "security"
        )
