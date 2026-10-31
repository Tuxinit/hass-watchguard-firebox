"""Parse and classify WatchGuard Fireware syslog messages.

Pure functions (no Home Assistant dependency).

Fireware "Syslog" format, e.g.::

    <142>Oct 31 10:00:00 JURASSIC-T25 D0000000000AA (2026-10-31T09:00:00) firewall:
      msg_id="3000-0148" Deny 0-External 1-Trusted 60 tcp 20 51 203.0.113.7
      172.25.5.50 51544 22 offset 10 S 1234 win 64240 geo_src="CHN" geo_dst="FRA"
      (Unhandled External Packet-00)

Message ids come from the Fireware Log Catalog.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re

_MSG_ID_RE = re.compile(r'msg_id=["”“]([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})["”“]')
_KV_RE = re.compile(r'([A-Za-z_][\w.]*)=["”“]([^"”“]*)["”“]')
_ACTION_RE = re.compile(r"\b(Allow|Deny)\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_POLICY_RE = re.compile(r"\(([^()]+)\)\s*$")
_PROCESS_RE = re.compile(r"\)\s+([A-Za-z][\w.-]*)(?:\[\d+\])?:\s+msg_id=")

# Threat categories --------------------------------------------------------

CATEGORIES = (
    "ips",
    "antivirus",
    "apt",
    "botnet",
    "geolocation",
    "webblocker",
    "reputation",
    "dnswatch",
    "tor",
    "blocked_site",
    "attack",
    "admin_login_failed",
    "auth_failed",
    "denied",
)

# Categories that are counted as "threats" (events fired, last-threat sensor)
THREAT_CATEGORIES = frozenset(
    {"ips", "antivirus", "apt", "botnet", "geolocation", "reputation", "dnswatch",
     "tor", "blocked_site", "attack", "admin_login_failed"}
)

_MSGID_CATEGORY: dict[str, str] = {
    # IPS
    "3000-0150": "ips",
    "1AFF-0025": "ips", "1AFF-0026": "ips", "1BFF-0011": "ips", "1CFF-000D": "ips",
    "1DFF-0010": "ips", "2AFF-0006": "ips", "2DFF-0001": "ips", "21FF-000C": "ips",
    "28FF-0008": "ips",
    # Gateway AntiVirus / IntelligentAV
    "1AFF-0028": "antivirus", "1BFF-000C": "antivirus", "1CFF-000E": "antivirus",
    "21FF-000F": "antivirus",
    # APT Blocker
    "0F00-0015": "apt", "1AFF-0034": "apt", "1BFF-0028": "apt", "1CFF-0015": "apt",
    "21FF-001F": "apt",
    # WebBlocker (category match, counted only when denied)
    "1AFF-0021": "webblocker", "2CFF-0001": "webblocker",
    # Reputation Enabled Defense
    "1AFF-002C": "reputation",
    # Blocked sites / ports
    "3000-0168": "blocked_site", "3000-0172": "blocked_site",
    # Default threat protection (floods, scans, spoofing, hostile traffic)
    "3000-0152": "attack", "3000-0153": "attack", "3000-0154": "attack",
    "3000-0155": "attack", "3000-0156": "attack", "3000-0157": "attack",
    "3000-0158": "attack", "3000-0159": "attack", "3000-0160": "attack",
    "3000-0161": "attack", "3000-0162": "attack", "3000-0163": "attack",
    "3000-0164": "attack", "3000-0165": "attack", "3000-0166": "attack",
    "3000-0169": "attack", "3000-0173": "attack", "3000-012C": "attack",
    # Authentication
    "3E00-0003": "admin_login_failed",
    "1100-0005": "auth_failed", "1100-000C": "auth_failed",
}

# Keyword rules applied to denied traffic (3000-0148 and proxies) whose
# msg_id is generic. Checked in order, case-insensitive.
_KEYWORD_RULES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"botnet", re.I), "botnet"),
    (re.compile(r"tor[ _-]?exit", re.I), "tor"),
    (re.compile(r"geo[ _-]?location|geo_blocked|blocked country", re.I), "geolocation"),
    (re.compile(r"dnswatch", re.I), "dnswatch"),
)


@dataclass(slots=True)
class FireboxLogEvent:
    """A parsed log line."""

    msg_id: str | None
    process: str | None
    action: str | None  # Allow / Deny / None
    src_ip: str | None
    dst_ip: str | None
    policy: str | None
    fields: dict[str, str] = field(default_factory=dict)
    category: str | None = None
    raw: str = ""

    @property
    def geo_src(self) -> str | None:
        return _geo(self.fields.get("geo_src"))

    @property
    def geo_dst(self) -> str | None:
        return _geo(self.fields.get("geo_dst"))

    @property
    def remote_country(self) -> str | None:
        """ISO3 country of the public side of the connection."""
        if self.src_ip and not _is_private(self.src_ip) and self.geo_src:
            return self.geo_src
        if self.dst_ip and not _is_private(self.dst_ip) and self.geo_dst:
            return self.geo_dst
        return self.geo_src or self.geo_dst

    @property
    def remote_ip(self) -> str | None:
        if self.src_ip and not _is_private(self.src_ip):
            return self.src_ip
        if self.dst_ip and not _is_private(self.dst_ip):
            return self.dst_ip
        return None

    @property
    def detail(self) -> str | None:
        """Human detail: signature, virus name, category..."""
        for key in ("signature_name", "virus", "threat_name", "md5", "cats", "category", "msg", "reason"):
            if self.fields.get(key):
                return self.fields[key]
        return self.policy


def _geo(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().upper()
    if len(value) != 3 or not value.isalpha():
        return None
    return value


_LOCAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
        "224.0.0.0/4", "255.255.255.255/32",
    )
)


def _is_private(ip: str) -> bool:
    """True for addresses that are not on the Internet side (LAN, CGNAT...)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 6:
        return addr.is_private or addr.is_link_local or addr.is_multicast
    return any(addr in net for net in _LOCAL_NETS)


def parse_line(line: str) -> FireboxLogEvent | None:
    """Parse one syslog datagram. Returns None if it isn't a Fireware log."""
    line = line.strip().replace("\x00", "")
    m = _MSG_ID_RE.search(line)
    if not m:
        return None
    msg_id = m.group(1).upper()
    after = line[m.end():]
    fields = {k: v for k, v in _KV_RE.findall(after)}

    action = None
    am = _ACTION_RE.match(after.lstrip())
    if am:
        action = am.group(1)

    # Positional IPs: the first two IPv4 addresses after the action word,
    # before any key="value" part.
    positional = _KV_RE.split(after, maxsplit=1)[0] if fields else after
    ips = _IP_RE.findall(positional)
    src_ip = fields.get("src_ip") or (ips[0] if len(ips) > 0 else None)
    dst_ip = fields.get("dst_ip") or (ips[1] if len(ips) > 1 else None)

    pm = _POLICY_RE.search(line)
    proc = _PROCESS_RE.search(line)
    event = FireboxLogEvent(
        msg_id=msg_id,
        process=proc.group(1) if proc else None,
        action=action,
        src_ip=src_ip,
        dst_ip=dst_ip,
        policy=pm.group(1).strip() if pm else None,
        fields=fields,
        raw=line,
    )
    event.category = classify(event)
    return event


def classify(event: FireboxLogEvent) -> str | None:
    """Return the threat/traffic category, or None for uninteresting logs."""
    cat = _MSGID_CATEGORY.get(event.msg_id or "")
    if cat == "webblocker" and event.action != "Deny":
        return None  # categorisation only, not a block
    if cat is not None:
        return cat
    if event.action == "Deny":
        haystack = f"{event.policy or ''} {event.raw}"
        for pattern, keyword_cat in _KEYWORD_RULES:
            if pattern.search(haystack):
                return keyword_cat
        return "denied"
    if event.action == "Allow":
        return "allowed"
    return None
