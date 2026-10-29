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

from homeassistant.core import callback
from homeassistant.util import dt as dt_util

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
    FireboxSensorDescription(
        key="license_expiration",
        translation_key="license_expiration",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda d: _next_expiry(d)[0],
        attrs_fn=lambda d: _license_attrs(d),
    ),
    FireboxSensorDescription(
        key="last_upgrade",
        translation_key="last_upgrade",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: _last_upgrade(d).time if _last_upgrade(d) else None,
        attrs_fn=lambda d: _upgrade_attrs(d),
    ),
    FireboxSensorDescription(
        key="admin_sessions",
        translation_key="admin_sessions",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: None if d.sessions is None else len(d.other_sessions),
        attrs_fn=lambda d: {
            "sessions": [
                {"user": s.user, "domain": s.domain, "role": s.role, "ip": s.ip, "elapsed_s": s.elapsed}
                for s in d.other_sessions
            ],
            "total_including_home_assistant": len(d.sessions or []),
        },
    ),
    FireboxSensorDescription(
        key="locked_out_users",
        translation_key="locked_out_users",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: d.locked_out,
    ),
)


def _next_expiry(d: FireboxData):
    """(earliest expiration, [feature names expiring then])."""
    feats = d.slow.features
    if not feats:
        return None, []
    dated = [f for f in feats.values() if f.enabled and f.expiration is not None]
    if not dated:
        return None, []
    first = min(f.expiration for f in dated)
    return first, sorted(f.name for f in dated if f.expiration == first)


def _license_attrs(d: FireboxData) -> dict[str, Any]:
    first, names = _next_expiry(d)
    attrs: dict[str, Any] = {"edition": d.slow.edition, "next_expiring": names}
    if first is not None:
        attrs["days_remaining"] = (first - dt_util.utcnow()).days
    attrs["features"] = {
        f.name: f.expiration.isoformat() if f.expiration else "never"
        for f in (d.slow.features or {}).values()
        if f.enabled
    }
    return attrs


def _last_upgrade(d: FireboxData):
    ups = d.slow.upgrades
    return ups[-1] if ups else None


def _upgrade_attrs(d: FireboxData) -> dict[str, Any] | None:
    last = _last_upgrade(d)
    if last is None:
        return None
    return {
        "version": last.version,
        "build": last.build,
        "action": last.action,
        "status": last.status,
        "comment": last.comment,
    }


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

    known: set[int] = set()

    @callback
    def _add_vlans() -> None:
        new = [v for v in coordinator.data.slow.vlans if v not in known]
        if new:
            known.update(new)
            async_add_entities(FireboxVlanDevicesSensor(coordinator, v) for v in new)

    _add_vlans()
    entry.async_on_unload(coordinator.async_add_listener(_add_vlans))


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


class FireboxVlanDevicesSensor(FireboxEntity, SensorEntity):
    """Number of devices active on a VLAN (complete ARP entries)."""

    _attr_translation_key = "vlan_devices"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: FireboxCoordinator, vlan_id: int) -> None:
        super().__init__(coordinator, f"vlan_{vlan_id}_devices")
        self._vlan_id = vlan_id
        vlan = coordinator.data.slow.vlans[vlan_id]
        self._attr_translation_placeholders = {"name": vlan.name}

    @property
    def available(self) -> bool:
        return super().available and self._vlan_id in self.coordinator.data.slow.vlans

    @property
    def native_value(self) -> int:
        iface = f"vlan{self._vlan_id}"
        return sum(1 for e in self.coordinator.data.arp if e.mac and e.interface == iface)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        data = self.coordinator.data
        vlan = data.slow.vlans.get(self._vlan_id)
        if vlan is None:
            return None
        leases = [l for l in data.dhcp or [] if l.interface == vlan.name]
        return {
            "vlan_id": vlan.id,
            "zone": vlan.zone,
            "address": vlan.address,
            "members": vlan.members,
            "dhcp_leases": len(leases),
        }
