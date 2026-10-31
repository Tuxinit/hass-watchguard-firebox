"""Country map: one geo_location entity per country seen over the last 24 h.

Displayed by the standard Map card with
``geo_location_sources: [watchguard_firebox]``.
"""

from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Any

from homeassistant.components.geo_location import GeolocationEvent
from homeassistant.const import UnitOfLength
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util.location import distance

from .const import DOMAIN
from .coordinator import FireboxConfigEntry
from .syslog import FireboxSyslogReceiver

PARALLEL_UPDATES = 0


@lru_cache(maxsize=1)
def _countries() -> dict[str, list]:
    return json.loads((Path(__file__).parent / "countries.json").read_text(encoding="utf-8"))


def _flag(cca2: str) -> str:
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cca2.upper() if "A" <= c <= "Z")


def country_info(iso3: str, language: str = "fr") -> dict[str, Any] | None:
    row = _countries().get(iso3.upper())
    if row is None:
        return None
    lat, lon, cca2, name_en, name_fr = row
    return {
        "lat": lat,
        "lon": lon,
        "cca2": cca2,
        "name": name_fr if language == "fr" else name_en,
        "flag": _flag(cca2),
    }


async def async_setup_entry(
    hass: HomeAssistant,
    entry: FireboxConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    receiver = coordinator.syslog
    if receiver is None:
        return
    language = "fr" if (hass.config.language or "").startswith("fr") else "en"
    entities: dict[str, FireboxCountryEvent] = {}

    @callback
    def _sync() -> None:
        window = receiver.window_countries()
        new = []
        for iso in window:
            if iso not in entities and country_info(iso) is not None:
                ent = FireboxCountryEvent(hass, entry.entry_id, receiver, iso, language)
                entities[iso] = ent
                new.append(ent)
        if new:
            async_add_entities(new)
        for iso in [i for i in entities if i not in window]:
            ent = entities.pop(iso)
            hass.async_create_task(ent.async_remove(force_remove=True))

    _sync()
    entry.async_on_unload(receiver.async_add_listener(_sync))


class FireboxCountryEvent(GeolocationEvent):
    """Traffic with one country over the last 24 h."""

    _attr_should_poll = False
    _attr_source = DOMAIN
    _attr_unit_of_measurement = UnitOfLength.KILOMETERS
    _attr_icon = "mdi:earth"

    def __init__(
        self,
        hass: HomeAssistant,
        entry_id: str,
        receiver: FireboxSyslogReceiver,
        iso3: str,
        language: str,
    ) -> None:
        self._receiver = receiver
        self._iso3 = iso3
        info = country_info(iso3, language)
        assert info is not None
        self._info = info
        # Transient entities: no unique_id (kept out of the entity registry),
        # stable entity_id so that cards/automations can target a country.
        self.entity_id = f"geo_location.firebox_{iso3.lower()}"
        self._attr_latitude = info["lat"]
        self._attr_longitude = info["lon"]
        self._attr_distance = round(
            distance(hass.config.latitude, hass.config.longitude, info["lat"], info["lon"]) / 1000
        )

    def _counts(self) -> tuple[int, int]:
        return self._receiver.window_countries().get(self._iso3, (0, 0))

    @property
    def name(self) -> str:
        blocked, allowed = self._counts()
        label = f"{self._info['flag']} {self._info['name']}"
        if blocked and allowed:
            return f"{label} · {blocked} ⛔ / {allowed} ✓"
        if blocked:
            return f"{label} · {blocked} ⛔"
        return f"{label} · {allowed} ✓"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        blocked, allowed = self._counts()
        return {
            "iso3": self._iso3,
            "country": self._info["name"],
            "blocked_24h": blocked,
            "allowed_24h": allowed,
        }

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._receiver.async_add_listener(self.async_write_ha_state))
