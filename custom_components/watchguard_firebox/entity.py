"""Base entities for the WatchGuard Firebox integration.

All entities belong to one device (the Firebox). Home Assistant's device page
only has fixed blocks (sensors, diagnostic...), so thematic grouping is done in
the dashboard (dashboards/firebox.yaml).
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


def firebox_device_info(entry: ConfigEntry, sysinfo: dict, group: Group = "status") -> DeviceInfo:
    """DeviceInfo of the Firebox (single device; `group` is informational only)."""
    model = f"Firebox {sysinfo['model']}" if sysinfo.get("model") else "Firebox"
    return DeviceInfo(
        identifiers={(DOMAIN, entry.unique_id)},
        manufacturer=MANUFACTURER,
        model=model,
        name=sysinfo.get("system_name") or entry.title,
        serial_number=sysinfo.get("serial_number"),
        sw_version=sysinfo.get("version"),
        configuration_url=f"https://{entry.data[CONF_HOST]}:8080",
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
