"""Base entity for the WatchGuard Firebox integration."""

from __future__ import annotations

from homeassistant.const import CONF_HOST
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER
from .coordinator import FireboxCoordinator


class FireboxEntity(CoordinatorEntity[FireboxCoordinator]):
    """Entity attached to the Firebox device."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: FireboxCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        info = coordinator.data.sysinfo
        self._attr_unique_id = f"{entry.unique_id}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id)},
            manufacturer=MANUFACTURER,
            model=f"Firebox {info.get('model')}" if info.get("model") else "Firebox",
            name=info.get("system_name") or entry.title,
            serial_number=info.get("serial_number"),
            sw_version=info.get("version"),
            configuration_url=f"https://{entry.data[CONF_HOST]}:8080",
        )
