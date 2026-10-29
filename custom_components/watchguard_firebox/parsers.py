"""Parsers for WatchGuard Fireware CLI output.

Pure functions, no Home Assistant dependency, so they can be unit-tested
against captured CLI output.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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


# --------------------------------------------------------------------------
# show features (licences)
# --------------------------------------------------------------------------

_TZ_OFFSETS = {
    "PST": -8, "PDT": -7, "MST": -7, "MDT": -6, "CST": -6, "CDT": -5,
    "EST": -5, "EDT": -4, "UTC": 0, "GMT": 0, "CET": 1, "CEST": 2,
}

_FEATURE_RE = re.compile(
    r"^(?P<name>[A-Z0-9_]+)\s+(?P<capacity>\S+)\s+(?P<status>Enabled|Disabled)\s+(?P<exp>.+?)\s*$"
)
_FEATURE_EXP_RE = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2})(?P<tz>[A-Z]{2,5})?\s+(?P<date>\d{2}/\d{2}/\d{4})$"
)


def _parse_feature_expiration(value: str) -> datetime | None:
    """'00:59:59PST 09/09/2027' -> aware datetime (UTC); 'Never' -> None."""
    m = _FEATURE_EXP_RE.match(value.strip())
    if not m:
        return None
    try:
        naive = datetime.strptime(f"{m['date']} {m['time']}", "%m/%d/%Y %H:%M:%S")
    except ValueError:
        return None
    offset = _TZ_OFFSETS.get((m["tz"] or "UTC").upper(), 0)
    return naive.replace(tzinfo=timezone(timedelta(hours=offset))).astimezone(timezone.utc)


@dataclass(slots=True)
class Feature:
    """A licensed feature."""

    name: str
    capacity: str
    enabled: bool
    expiration: datetime | None  # None = never expires


def parse_features(text: str) -> dict:
    """Parse `show features`."""
    summary: dict[str, str] = {}
    features: dict[str, Feature] = {}
    in_table = False
    for line in clean(text).splitlines():
        if line.startswith("Feature") and "Expiration" in line:
            in_table = True
            continue
        if not in_table:
            key, sep, value = line.partition(":")
            if sep and not line.startswith("--"):
                summary[key.strip().lower()] = value.strip()
            continue
        m = _FEATURE_RE.match(line.strip())
        if m:
            features[m["name"]] = Feature(
                name=m["name"],
                capacity=m["capacity"],
                enabled=m["status"] == "Enabled",
                expiration=_parse_feature_expiration(m["exp"]),
            )
    return {
        "edition": summary.get("software edition"),
        "features": features,
    }


# --------------------------------------------------------------------------
# show upgrade (history)
# --------------------------------------------------------------------------

_UPGRADE_RE = re.compile(
    r"^(?P<time>\d{2}/\d{2}/\d{4}:\d{2}:\d{2}:\d{2})\s+(?P<action>.+?)\s+"
    r"(?P<version>\d+(?:\.\d+)+)\s+(?P<build>\d+)\s+(?P<status>\S+)\s*(?P<comment>.*)$"
)


@dataclass(slots=True)
class UpgradeRecord:
    """One line of the upgrade history. time is naive (Firebox local time)."""

    time: datetime | None
    action: str
    version: str
    build: str
    success: bool
    status: str
    comment: str


def parse_upgrade_history(text: str) -> list[UpgradeRecord]:
    """Parse `show upgrade`; returns records oldest first."""
    records: list[UpgradeRecord] = []
    for line in clean(text).splitlines():
        m = _UPGRADE_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(m["time"], "%m/%d/%Y:%H:%M:%S")
        except ValueError:
            ts = None
        records.append(
            UpgradeRecord(
                time=ts,
                action=m["action"].strip(),
                version=m["version"],
                build=m["build"],
                success=m["status"].lower() == "success",
                status=m["status"],
                comment=m["comment"].strip(),
            )
        )
    records.sort(key=lambda r: r.time or datetime.min)
    return records


# --------------------------------------------------------------------------
# show signature-update
# --------------------------------------------------------------------------

_SIG_AUTO_RE = re.compile(
    r"^automatic\s+(?P<name>.+?)\s+(?:signature\s+update|database\s+update)\s*:\s*(?P<state>\w+)",
    re.IGNORECASE,
)


def parse_signature_update(text: str) -> dict:
    """Parse `show signature-update` -> {'interval_hours', 'auto': {name: bool}}."""
    result: dict = {"interval_hours": None, "auto": {}}
    for line in clean(text).splitlines():
        line = line.strip()
        if line.lower().startswith("automatic update interval"):
            m = re.search(r":\s*(\d+)", line)
            if m:
                result["interval_hours"] = int(m.group(1))
            continue
        m = _SIG_AUTO_RE.match(line)
        if m:
            result["auto"][m["name"].strip()] = m["state"].lower() == "enabled"
    return result


# --------------------------------------------------------------------------
# show login-user (management sessions)
# --------------------------------------------------------------------------

_LOGIN_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<domain>\S+)\s+(?P<role>.+?)\s+(?P<days>\d+)\s+days\s+"
    rf"(?P<hms>\d+:\d{{2}}:\d{{2}})\s+(?P<ip>{_IP_RE}|[0-9a-fA-F:]+)\s*(?P<limit>.*)$"
)


@dataclass(slots=True)
class LoginSession:
    """An open management session."""

    user: str
    domain: str
    role: str
    elapsed: int  # seconds
    ip: str


def parse_login_users(text: str) -> list[LoginSession]:
    """Parse `show login-user`."""
    sessions: list[LoginSession] = []
    for line in clean(text).splitlines():
        m = _LOGIN_RE.match(line.strip())
        if not m:
            continue
        h, mi, s = (int(x) for x in m["hms"].split(":"))
        sessions.append(
            LoginSession(
                user=m["user"],
                domain=m["domain"],
                role=m["role"].strip(),
                elapsed=int(m["days"]) * 86400 + h * 3600 + mi * 60 + s,
                ip=m["ip"],
            )
        )
    return sessions


# --------------------------------------------------------------------------
# show locked-out
# --------------------------------------------------------------------------


def parse_locked_out(text: str) -> int | None:
    """Parse `show locked-out` -> number of locked accounts."""
    m = re.search(r"Total\s+(\d+)\s+locked", clean(text), re.IGNORECASE)
    return int(m.group(1)) if m else None


# --------------------------------------------------------------------------
# show vlan
# --------------------------------------------------------------------------

_VLAN_RE = re.compile(
    r"^(?P<id>\d+)\s+(?P<name>.+?)\s+(?P<zone>Trusted|Optional|Custom|External)\s+"
    rf"(?P<address>{_IP_RE}/\d+)\s+(?P<members>\S+?)\s*(?P<node>IPv\d.*)$",
    re.IGNORECASE,
)


@dataclass(slots=True)
class Vlan:
    """A VLAN object."""

    id: int
    name: str
    zone: str
    address: str
    members: str


def parse_vlans(text: str) -> dict[int, Vlan]:
    """Parse `show vlan` (summary table)."""
    result: dict[int, Vlan] = {}
    for line in clean(text).splitlines():
        m = _VLAN_RE.match(line.strip())
        if m:
            vid = int(m["id"])
            result[vid] = Vlan(
                id=vid,
                name=m["name"].strip(),
                zone=m["zone"].lower(),
                address=m["address"],
                members=m["members"],
            )
    return result
