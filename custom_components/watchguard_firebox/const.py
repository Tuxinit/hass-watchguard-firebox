"""Constants for the WatchGuard Firebox integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "watchguard_firebox"
MANUFACTURER: Final = "WatchGuard"

DEFAULT_PORT: Final = 4118
DEFAULT_SCAN_INTERVAL: Final = 30
MIN_SCAN_INTERVAL: Final = 10
DEFAULT_CONSIDER_HOME: Final = 180

CONF_HOST_KEY: Final = "host_key_fingerprint"
CONF_TRACKED_MACS: Final = "tracked_macs"
CONF_CONSIDER_HOME: Final = "consider_home"
CONF_POLL_DHCP: Final = "poll_dhcp"

CMD_SYSINFO: Final = "show sysinfo"
CMD_INTERFACE: Final = "show interface"
CMD_ARP: Final = "show arp"
CMD_DHCP: Final = "show dhcp lease"
CMD_FEATURES: Final = "show features"
CMD_UPGRADE: Final = "show upgrade"
CMD_SIGNATURE: Final = "show signature-update"
CMD_LOGIN_USER: Final = "show login-user"
CMD_LOCKED_OUT: Final = "show locked-out"
CMD_VLAN: Final = "show vlan"

# Slow-changing data (licences, upgrade history, signature config, VLANs)
SLOW_POLL_INTERVAL: Final = 3600
LICENSE_WARNING_DAYS: Final = 30
