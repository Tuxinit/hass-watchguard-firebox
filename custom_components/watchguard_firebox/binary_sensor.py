"""Binary sensors (interface link status) for the WatchGuard Firebox integration."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from homeassistant.const import EntityCategory
from homeassistant.util import dt as dt_util

from .const import LICENSE_WARNING_DAYS
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
    async_add_entities(
        [
            FireboxLicenseExpiringSensor(coordinator),
            FireboxSignatureAutoUpdateSensor(coordinator),
            FireboxUpgradeFailedSensor(coordinator),
        ]
    )


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


class FireboxLicenseExpiringSensor(FireboxEntity, BinarySensorEntity):
    """On when a security subscription expires within LICENSE_WARNING_DAYS."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_translation_key = "license_expiring"

    def __init__(self, coordinator: FireboxCoordinator) -> None:
        super().__init__(coordinator, "license_expiring")

    def _expiring(self) -> list[str] | None:
        feats = self.coordinator.data.slow.features
        if feats is None:
            return None
        limit = dt_util.utcnow() + timedelta(days=LICENSE_WARNING_DAYS)
        return sorted(
            f.name
            for f in feats.values()
            if f.enabled and f.expiration is not None and f.expiration <= limit
        )

    @property
    def is_on(self) -> bool | None:
        exp = self._expiring()
        return None if exp is None else bool(exp)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"expiring": self._expiring() or [], "warning_days": LICENSE_WARNING_DAYS}


class FireboxSignatureAutoUpdateSensor(FireboxEntity, BinarySensorEntity):
    """On when automatic signature update is disabled for any service."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_translation_key = "signature_auto_update"

    def __init__(self, coordinator: FireboxCoordinator) -> None:
        super().__init__(coordinator, "signature_auto_update")

    @property
    def is_on(self) -> bool | None:
        sig = self.coordinator.data.slow.signature
        if not sig or not sig["auto"]:
            return None
        return not all(sig["auto"].values())

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        sig = self.coordinator.data.slow.signature
        if not sig:
            return None
        return {"interval_hours": sig["interval_hours"], **{f"auto_{k}": v for k, v in sig["auto"].items()}}


class FireboxUpgradeFailedSensor(FireboxEntity, BinarySensorEntity):
    """On when the last Fireware upgrade did not succeed."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_translation_key = "upgrade_failed"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: FireboxCoordinator) -> None:
        super().__init__(coordinator, "upgrade_failed")

    @property
    def is_on(self) -> bool | None:
        ups = self.coordinator.data.slow.upgrades
        return None if not ups else not ups[-1].success
