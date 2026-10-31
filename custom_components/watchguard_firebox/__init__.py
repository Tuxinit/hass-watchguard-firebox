"""The WatchGuard Firebox integration."""

from __future__ import annotations

from pathlib import Path

from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .api import FireboxClient
from .const import (
    CONF_HOST_KEY,
    DOMAIN,
    FLAGS_URL,
    CONF_SYSLOG_ENABLED,
    CONF_SYSLOG_PORT,
    CONF_SYSLOG_SOURCES,
    DEFAULT_PORT,
    DEFAULT_SYSLOG_PORT,
)
from .coordinator import FireboxConfigEntry, FireboxCoordinator

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.DEVICE_TRACKER,
    Platform.GEO_LOCATION,
    Platform.SENSOR,
]


def _migrate_v03_devices(hass: HomeAssistant, entry: FireboxConfigEntry) -> None:
    """v0.3.0 split entities over 3 devices; fold them back into one.

    Removes the "<name> Security" / "<name> Interfaces" devices and strips the
    "securite_/security_/interfaces_" prefix that v0.3.0 put in entity_ids.
    """
    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)
    serial = entry.unique_id
    parent = dev_reg.async_get_device(identifiers={(DOMAIN, serial)})
    for group in ("security", "interfaces"):
        device = dev_reg.async_get_device(identifiers={(DOMAIN, f"{serial}_{group}")})
        if device is None:
            continue
        for ent in er.async_entries_for_device(ent_reg, device.id, include_disabled_entities=True):
            domain, object_id = ent.entity_id.split(".", 1)
            new_object_id = object_id
            for prefix in ("_securite_", "_security_", "_interfaces_"):
                if prefix in object_id:
                    head, tail = object_id.split(prefix, 1)
                    if prefix == "_interfaces_" and domain == "binary_sensor" and not tail.startswith("interface_"):
                        tail = f"interface_{tail}"
                    new_object_id = f"{head}_{tail}"
                    break
            new_entity_id = f"{domain}.{new_object_id}"
            updates: dict = {}
            if parent is not None:
                updates["device_id"] = parent.id
            if new_entity_id != ent.entity_id and ent_reg.async_get(new_entity_id) is None:
                updates["new_entity_id"] = new_entity_id
            if updates:
                ent_reg.async_update_entity(ent.entity_id, **updates)
        dev_reg.async_remove_device(device.id)


async def _async_register_static(hass: HomeAssistant) -> None:
    """Serve the bundled flag images (once per HA instance)."""
    key = f"{DOMAIN}_static_registered"
    if hass.data.get(key) or getattr(hass, "http", None) is None:
        return
    from homeassistant.components.http import StaticPathConfig

    await hass.http.async_register_static_paths(
        [StaticPathConfig(FLAGS_URL, str(Path(__file__).parent / "flags"), True)]
    )
    hass.data[key] = True


async def async_setup_entry(hass: HomeAssistant, entry: FireboxConfigEntry) -> bool:
    """Set up a Firebox from a config entry."""
    client = FireboxClient(
        entry.data[CONF_HOST],
        entry.data.get(CONF_PORT, DEFAULT_PORT),
        entry.data[CONF_USERNAME],
        entry.data[CONF_PASSWORD],
        entry.data.get(CONF_HOST_KEY),
    )
    coordinator = FireboxCoordinator(hass, entry, client)
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        await client.close()
        raise

    entry.runtime_data = coordinator
    _migrate_v03_devices(hass, entry)

    if entry.options.get(CONF_SYSLOG_ENABLED, False):
        from .syslog import FireboxSyslogReceiver

        sources = {
            ip.strip()
            for ip in str(entry.options.get(CONF_SYSLOG_SOURCES, entry.data[CONF_HOST])).split(",")
            if ip.strip()
        }
        receiver = FireboxSyslogReceiver(
            hass,
            entry.entry_id,
            entry.options.get(CONF_SYSLOG_PORT, DEFAULT_SYSLOG_PORT),
            sources,
        )
        await receiver.async_start()
        coordinator.syslog = receiver
        await _async_register_static(hass)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: FireboxConfigEntry) -> bool:
    """Unload a config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        coordinator = entry.runtime_data
        if coordinator.syslog is not None:
            await coordinator.syslog.async_stop()
        await coordinator.client.close()
    return unloaded


async def _async_reload(hass: HomeAssistant, entry: FireboxConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)
