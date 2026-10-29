"""Diagnostics for the WatchGuard Firebox integration."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .coordinator import FireboxConfigEntry

TO_REDACT = {CONF_PASSWORD, CONF_USERNAME, "serial_number", "mac", "unique_id"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: FireboxConfigEntry
) -> dict[str, Any]:
    data = entry.runtime_data.data
    return {
        "entry": async_redact_data(
            {"data": dict(entry.data), "options": dict(entry.options)}, TO_REDACT
        ),
        "sysinfo": async_redact_data(data.sysinfo, TO_REDACT),
        "interfaces": [asdict(i) for i in data.interfaces.values()],
        "arp_count": len(data.arp),
        "dhcp_count": None if data.dhcp is None else len(data.dhcp),
        "dhcp_interfaces": sorted({lease.interface for lease in data.dhcp or []}),
    }
