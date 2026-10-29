"""Binary sensors (interface link status) for the WatchGuard Firebox integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import FireboxConfigEntry, FireboxCoordinator
from .entity import FireboxEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: FireboxConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    known: set[int] = set()

    @callback
    def _add_new() -> None:
        new = [i for i in coordinator.data.interfaces if i not in known]
        if new:
            known.update(new)
            async_add_entities(FireboxInterfaceSensor(coordinator, i) for i in new)

    _add_new()
    entry.async_on_unload(coordinator.async_add_listener(_add_new))


class FireboxInterfaceSensor(FireboxEntity, BinarySensorEntity):
    """Link status of one Firebox interface."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "interface"

    def __init__(self, coordinator: FireboxCoordinator, index: int) -> None:
        super().__init__(coordinator, f"interface_{index}")
        self._index = index
        iface = coordinator.data.interfaces[index]
        self._attr_translation_placeholders = {"name": iface.name}
        # Disabled interfaces: entity disabled by default
        self._attr_entity_registry_enabled_default = iface.enabled

    @property
    def _iface(self):
        return self.coordinator.data.interfaces.get(self._index)

    @property
    def available(self) -> bool:
        return super().available and self._iface is not None

    @property
    def is_on(self) -> bool | None:
        iface = self._iface
        return iface.up if iface else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        iface = self._iface
        if iface is None:
            return None
        return {
            "index": iface.index,
            "enabled": iface.enabled,
            "address": iface.address,
            "type": iface.type,
            "mtu": iface.mtu,
            "ip_assignment": iface.assignment,
        }
