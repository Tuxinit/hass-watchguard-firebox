"""The WatchGuard Firebox integration."""

from __future__ import annotations

from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import HomeAssistant

from .api import FireboxClient
from .const import (
    CONF_HOST_KEY,
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
