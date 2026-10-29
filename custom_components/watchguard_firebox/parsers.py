"""Parsers for WatchGuard Fireware CLI output.

Pure functions, no Home Assistant dependency, so they can be unit-tested
against captured CLI output.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_MAC_RE = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}"


def clean(text: str) -> str:
    """Strip ANSI escapes and carriage returns."""
    return _ANSI_RE.sub("", text).replace("\r", "")


# --------------------------------------------------------------------------
# show sysinfo
# --------------------------------------------------------------------------

_UPTIME_UNITS = {
    "day": 86400,
    "days": 86400,
    "hour": 3600,
    "hours": 3600,
    "minute": 60,
    "minutes": 60,
    "second": 1,
    "seconds": 1,
}


def parse_uptime(value: str) -> int | None:
    """'21 days 21 hours 20 minutes 38 seconds' -> seconds."""
    total = 0
    found = False
    for num, unit in re.findall(r"(\d+)\s+([a-zA-Z]+)", value):
        mult = _UPTIME_UNITS.get(unit.lower())
        if mult:
            total += int(num) * mult
            found = True
    return total if found else None


def parse_sysinfo(text: str) -> dict:
    """Parse `show sysinfo`."""
    raw: dict[str, str] = {}
    for line in clean(text).splitlines():
        if line.startswith("--") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key:
            raw[key] = value.strip()

    def _null(v: str | None) -> str | None:
        return None if v in (None, "", "(null)") else v

    result: dict = {
        "system_name": _null(raw.get("system name")),
        "model": _null(raw.get("system model")),
        "contact": _null(raw.get("contact")),
        "location": _null(raw.get("location")),
        "serial_number": _null(raw.get("serial number")),
        "version": _null(raw.get("version")),
        "time_zone": _null(raw.get("time zone")),
        "uptime": parse_uptime(raw.get("up time", "")),
        "cpu_1min": None,
        "cpu_5min": None,
        "cpu_15min": None,
        "memory_total_kb": None,
        "memory_free_kb": None,
        "memory_used_kb": None,
    }

    cpu = raw.get("cpu utilization", "")
    for pct, period in re.findall(r"(\d+(?:\.\d+)?)%\s*\((\d+)\s*min\)", cpu):
        result[f"cpu_{period}min"] = float(pct)

    mem = raw.get("memory usage", "")
    for amount, kind in re.findall(r"(\d+)\s*kB\s*\((\w+)\)", mem):
        key = f"memory_{kind.lower()}_kb"
        if key in result:
            result[key] = int(amount)

    return result


# --------------------------------------------------------------------------
# show interface
# --------------------------------------------------------------------------

_IFACE_TYPES = {
    "TR": "trusted",
    "EX": "external",
    "OP": "optional",
    "CS": "custom",
    "VL": "vlan",
    "BR": "bridge",
    "CL": "cluster",
    "LA": "link_aggregation",
    "NA": "not_apply",
}

_IFACE_RE = re.compile(
    r"^\s*(?P<enabled>yes|no)\s+(?P<index>\d+)\s+(?P<name>.+?)\s+"
    rf"(?P<address>{_IP_RE}/\d+)\s+(?P<type>[A-Z]{{2}})/(?P<mtu>\d+)\s+"
    r"(?P<status>Up|Down)\s+(?P<assignment>\S+)\s+(?P<node_type>.+?)\s*$",
    re.IGNORECASE,
)


@dataclass(slots=True)
class FireboxInterface:
    """A Firebox interface."""

    index: int
    name: str
    enabled: bool
    address: str
    type: str
    mtu: int
    up: bool
    assignment: str
    node_type: str


def parse_interfaces(text: str) -> dict[int, FireboxInterface]:
    """Parse `show interface`."""
    result: dict[int, FireboxInterface] = {}
    for line in clean(text).splitlines():
        m = _IFACE_RE.match(line)
        if not m:
            continue
        idx = int(m["index"])
        result[idx] = FireboxInterface(
            index=idx,
            name=m["name"].strip(),
            enabled=m["enabled"].lower() == "yes",
            address=m["address"],
            type=_IFACE_TYPES.get(m["type"].upper(), m["type"].lower()),
            mtu=int(m["mtu"]),
            up=m["status"].lower() == "up",
            assignment=m["assignment"],
            node_type=m["node_type"].strip(),
        )
    return result


# --------------------------------------------------------------------------
# show arp
# --------------------------------------------------------------------------

_ARP_RE = re.compile(
    rf"^\S+\s+\((?P<ip>{_IP_RE})\)\s+at\s+(?P<mac>{_MAC_RE}|<incomplete>)"
    r"(?:\s+\[\w+\])?(?:\s+\w+)*?\s+on\s+(?P<iface>\S+)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class ArpEntry:
    """An ARP table entry. mac is None when incomplete."""

    ip: str
    mac: str | None
    interface: str


def parse_arp(text: str) -> list[ArpEntry]:
    """Parse `show arp`."""
    entries: list[ArpEntry] = []
    for line in clean(text).splitlines():
        m = _ARP_RE.match(line.strip())
        if not m:
            continue
        mac = m["mac"]
        entries.append(
            ArpEntry(
                ip=m["ip"],
                mac=None if mac.startswith("<") else mac.lower(),
                interface=m["iface"],
            )
        )
    return entries


# --------------------------------------------------------------------------
# show dhcp lease
# --------------------------------------------------------------------------

_DT = r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}"
_DHCP_RE = re.compile(
    rf"^(?P<iface>.+?)\s+(?P<ip>{_IP_RE})\s+(?P<host>.*?)\s*(?P<mac>{_MAC_RE})\s+"
    rf"(?P<start>{_DT})\s+(?P<end>{_DT})\s*$"
)


@dataclass(slots=True)
class DhcpLease:
    """A DHCP lease. start/end are naive datetimes in Firebox local time."""

    interface: str
    ip: str
    hostname: str | None
    mac: str
    start: datetime | None
    end: datetime | None


def _parse_dt(value: str) -> datetime | None:
    try:
        return datetime.strptime(" ".join(value.split()), "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


def parse_dhcp_leases(text: str) -> list[DhcpLease]:
    """Parse `show dhcp lease`."""
    leases: list[DhcpLease] = []
    for line in clean(text).splitlines():
        m = _DHCP_RE.match(line.rstrip())
        if not m:
            continue
        leases.append(
            DhcpLease(
                interface=m["iface"].strip(),
                ip=m["ip"],
                hostname=m["host"].strip() or None,
                mac=m["mac"].lower(),
                start=_parse_dt(m["start"]),
                end=_parse_dt(m["end"]),
            )
        )
    return leases


def is_cli_error(text: str) -> bool:
    """Detect a Fireware CLI error answer."""
    t = clean(text).lower()
    return any(
        marker in t
        for marker in ("% error", "%error", "invalid input", "unknown command", "permission denied")
    )
