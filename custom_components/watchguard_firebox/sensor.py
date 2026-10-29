"""Sensors for the WatchGuard Firebox integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfInformation
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import FireboxConfigEntry, FireboxCoordinator, FireboxData
from .entity import FireboxEntity

PARALLEL_UPDATES = 0


def _mem_pct(d: FireboxData) -> float | None:
    s = d.sysinfo
    if s.get("memory_total_kb") and s.get("memory_used_kb") is not None:
        return round(s["memory_used_kb"] * 100 / s["memory_total_kb"], 1)
    return None


def _kb(key: str) -> Callable[[FireboxData], Any]:
    return lambda d: d.sysinfo.get(key)


@dataclass(frozen=True, kw_only=True)
class FireboxSensorDescription(SensorEntityDescription):
    """Describe a Firebox sensor."""

    value_fn: Callable[[FireboxData], Any]
    attrs_fn: Callable[[FireboxData], dict[str, Any]] | None = None


SENSORS: tuple[FireboxSensorDescription, ...] = (
    FireboxSensorDescription(
        key="cpu_1min",
        translation_key="cpu_1min",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.sysinfo.get("cpu_1min"),
    ),
    FireboxSensorDescription(
        key="cpu_5min",
        translation_key="cpu_5min",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=lambda d: d.sysinfo.get("cpu_5min"),
    ),
    FireboxSensorDescription(
        key="cpu_15min",
        translation_key="cpu_15min",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=lambda d: d.sysinfo.get("cpu_15min"),
    ),
    FireboxSensorDescription(
        key="memory_used_percent",
        translation_key="memory_used_percent",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_mem_pct,
    ),
    FireboxSensorDescription(
        key="memory_free",
        translation_key="memory_free",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.KIBIBYTES,
        suggested_unit_of_measurement=UnitOfInformation.MEBIBYTES,
        suggested_display_precision=0,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=_kb("memory_free_kb"),
    ),
    FireboxSensorDescription(
        key="memory_used",
        translation_key="memory_used",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.KIBIBYTES,
        suggested_unit_of_measurement=UnitOfInformation.MEBIBYTES,
        suggested_display_precision=0,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=_kb("memory_used_kb"),
    ),
    FireboxSensorDescription(
        key="boot_time",
        translation_key="boot_time",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.boot_time,
    ),
    FireboxSensorDescription(
        key="firmware",
        translation_key="firmware",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.sysinfo.get("version"),
    ),
    FireboxSensorDescription(
        key="arp_entries",
        translation_key="arp_entries",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: sum(1 for e in d.arp if e.mac),
        attrs_fn=lambda d: {"incomplete": sum(1 for e in d.arp if not e.mac)},
    ),
    FireboxSensorDescription(
        key="dhcp_leases",
        translation_key="dhcp_leases",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: None if d.dhcp is None else len(d.dhcp),
        attrs_fn=lambda d: _leases_per_interface(d),
    ),
)


def _leases_per_interface(d: FireboxData) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for lease in d.dhcp or []:
        counts[lease.interface] = counts.get(lease.interface, 0) + 1
    return {"per_interface": counts}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: FireboxConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(FireboxSensor(coordinator, desc) for desc in SENSORS)


class FireboxSensor(FireboxEntity, SensorEntity):
    """A Firebox sensor."""

    entity_description: FireboxSensorDescription

    def __init__(
        self, coordinator: FireboxCoordinator, description: FireboxSensorDescription
    ) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator.data)
