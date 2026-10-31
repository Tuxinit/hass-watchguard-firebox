"""Syslog receiver: threat counters, 24 h window per country, events.

The Firebox sends its log messages over UDP to Home Assistant. Only datagrams
from the allowed source IPs are accepted (UDP syslog is trivially spoofable).

State is persisted in .storage so that counters and the 24 h map survive a
Home Assistant restart.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import time
from typing import Any

from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .syslog_parser import CATEGORIES, THREAT_CATEGORIES, FireboxLogEvent, parse_line

_LOGGER = logging.getLogger(__name__)

EVENT_THREAT = f"{DOMAIN}_threat"
STORAGE_VERSION = 1
WINDOW_HOURS = 24
NOTIFY_INTERVAL = timedelta(seconds=5)
MAX_EVENTS_PER_MINUTE = 30
RECENT_THREATS = 20
SAMPLES = 20


@dataclass(slots=True)
class _Bucket:
    hour: int  # epoch hour
    categories: dict[str, int] = field(default_factory=dict)
    # country ISO3 -> [blocked, allowed]
    countries: dict[str, list[int]] = field(default_factory=dict)


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: FireboxSyslogReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._receiver.handle_datagram(data, addr[0])

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("Syslog socket error: %s", exc)


class FireboxSyslogReceiver:
    """UDP syslog listener + statistics."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry_id: str,
        port: int,
        allowed_sources: set[str],
    ) -> None:
        self.hass = hass
        self.port = port
        self.allowed_sources = allowed_sources
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry_id}.syslog"
        )
        self._transport: asyncio.DatagramTransport | None = None
        self._listeners: list[CALLBACK_TYPE] = []
        self._dirty = False
        self._unsub_tick: CALLBACK_TYPE | None = None
        self._event_times: deque[float] = deque()

        self.listening = False
        self.error: str | None = None
        self.totals: dict[str, int] = {c: 0 for c in CATEGORIES}
        self.totals["allowed"] = 0
        self.buckets: deque[_Bucket] = deque()
        self.last_threat: dict[str, Any] | None = None
        self.recent_threats: deque[dict[str, Any]] = deque(maxlen=RECENT_THREATS)
        self.last_received: datetime | None = None
        self.lines_received = 0
        self.lines_rejected = 0
        self.rejected_sources: dict[str, int] = {}
        self.lines_unparsed = 0
        self.unparsed_samples: deque[str] = deque(maxlen=SAMPLES)
        self.events_dropped = 0

    # ------------------------------------------------------------------ #
    # lifecycle

    async def async_start(self) -> None:
        stored = await self._store.async_load()
        if stored:
            self._restore(stored)
        loop = asyncio.get_running_loop()
        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: _Protocol(self), local_addr=("0.0.0.0", self.port)
            )
        except OSError as err:
            self.error = f"Cannot listen on UDP {self.port}: {err}"
            _LOGGER.error("%s", self.error)
        else:
            self.listening = True
            _LOGGER.info("Listening for Firebox syslog on UDP %s", self.port)
        self._unsub_tick = async_track_time_interval(self.hass, self._tick, NOTIFY_INTERVAL)

    async def async_stop(self) -> None:
        if self._unsub_tick:
            self._unsub_tick()
            self._unsub_tick = None
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self.listening = False
        await self._store.async_save(self._dump())

    # ------------------------------------------------------------------ #
    # listeners (entities)

    @callback
    def async_add_listener(self, update_callback: CALLBACK_TYPE) -> Callable[[], None]:
        self._listeners.append(update_callback)

        def _remove() -> None:
            self._listeners.remove(update_callback)

        return _remove

    @callback
    def _tick(self, _now: datetime | None = None) -> None:
        self._expire()
        if not self._dirty:
            return
        self._dirty = False
        for listener in list(self._listeners):
            listener()
        self._store.async_delay_save(self._dump, 60)

    # ------------------------------------------------------------------ #
    # ingestion

    @callback
    def handle_datagram(self, data: bytes, source: str) -> None:
        if self.allowed_sources and source not in self.allowed_sources:
            self.lines_rejected += 1
            if source not in self.rejected_sources:
                _LOGGER.warning(
                    "Syslog from %s ignored: not in allowed sources %s. If this is the "
                    "Firebox, add %s to 'Allowed syslog source IP(s)' in the integration options",
                    source, sorted(self.allowed_sources), source,
                )
            self.rejected_sources[source] = self.rejected_sources.get(source, 0) + 1
            if len(self.rejected_sources) > 20:
                self.rejected_sources.pop(next(iter(self.rejected_sources)))
            self._dirty = True
            return
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.strip():
                self.handle_line(line)

    @callback
    def handle_line(self, line: str) -> None:
        self.lines_received += 1
        self.last_received = dt_util.utcnow()
        self._dirty = True
        event = parse_line(line)
        if event is None:
            self.lines_unparsed += 1
            self.unparsed_samples.append(line[:500])
            return
        cat = event.category
        if cat is None:
            return
        self.totals[cat] = self.totals.get(cat, 0) + 1
        bucket = self._bucket()
        bucket.categories[cat] = bucket.categories.get(cat, 0) + 1

        country = event.remote_country
        if country:
            counts = bucket.countries.setdefault(country, [0, 0])
            counts[1 if cat == "allowed" else 0] += 1

        if cat in THREAT_CATEGORIES:
            self._record_threat(event)

    def _record_threat(self, event: FireboxLogEvent) -> None:
        info = {
            "time": dt_util.utcnow().isoformat(),
            "category": event.category,
            "msg_id": event.msg_id,
            "action": event.action,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "remote_ip": event.remote_ip,
            "country": event.remote_country,
            "detail": event.detail,
            "policy": event.policy,
        }
        self.last_threat = info
        self.recent_threats.appendleft(info)
        now = time.monotonic()
        while self._event_times and now - self._event_times[0] > 60:
            self._event_times.popleft()
        if len(self._event_times) >= MAX_EVENTS_PER_MINUTE:
            self.events_dropped += 1
            return
        self._event_times.append(now)
        self.hass.bus.async_fire(EVENT_THREAT, info)

    # ------------------------------------------------------------------ #
    # 24 h window

    def _bucket(self) -> _Bucket:
        hour = int(time.time() // 3600)
        if not self.buckets or self.buckets[-1].hour != hour:
            self.buckets.append(_Bucket(hour=hour))
            self._expire()
        return self.buckets[-1]

    def _expire(self) -> None:
        oldest = int(time.time() // 3600) - WINDOW_HOURS + 1
        changed = False
        while self.buckets and self.buckets[0].hour < oldest:
            self.buckets.popleft()
            changed = True
        if changed:
            self._dirty = True

    def window_categories(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for b in self.buckets:
            for cat, n in b.categories.items():
                out[cat] = out.get(cat, 0) + n
        return out

    def window_countries(self) -> dict[str, tuple[int, int]]:
        """ISO3 -> (blocked, allowed) over the last 24 h."""
        out: dict[str, list[int]] = {}
        for b in self.buckets:
            for iso, (blocked, allowed) in b.countries.items():
                acc = out.setdefault(iso, [0, 0])
                acc[0] += blocked
                acc[1] += allowed
        return {k: (v[0], v[1]) for k, v in out.items()}

    def threats_24h(self) -> int:
        return sum(n for c, n in self.window_categories().items() if c in THREAT_CATEGORIES)

    # ------------------------------------------------------------------ #
    # persistence

    def _dump(self) -> dict[str, Any]:
        return {
            "totals": self.totals,
            "buckets": [
                {"hour": b.hour, "categories": b.categories, "countries": b.countries}
                for b in self.buckets
            ],
            "last_threat": self.last_threat,
            "recent_threats": list(self.recent_threats),
        }

    def _restore(self, data: dict[str, Any]) -> None:
        for k, v in (data.get("totals") or {}).items():
            if isinstance(v, int):
                self.totals[k] = v
        for b in data.get("buckets") or []:
            try:
                self.buckets.append(
                    _Bucket(
                        hour=int(b["hour"]),
                        categories={k: int(v) for k, v in b["categories"].items()},
                        countries={k: [int(v[0]), int(v[1])] for k, v in b["countries"].items()},
                    )
                )
            except (KeyError, TypeError, ValueError, IndexError):
                continue
        self.last_threat = data.get("last_threat")
        for t in reversed(data.get("recent_threats") or []):
            self.recent_threats.appendleft(t)
        self._expire()

    def diagnostics(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "listening": self.listening,
            "error": self.error,
            "allowed_sources": sorted(self.allowed_sources),
            "lines_received": self.lines_received,
            "lines_rejected": self.lines_rejected,
            "rejected_sources": self.rejected_sources,
            "lines_unparsed": self.lines_unparsed,
            "events_dropped": self.events_dropped,
            "unparsed_samples": list(self.unparsed_samples),
            "totals": self.totals,
            "window_categories": self.window_categories(),
        }
