"""Tests for Fireware CLI parsers, against real (anonymised) T25 output."""

from datetime import datetime
from pathlib import Path
import importlib.util
import sys

_PATH = Path(__file__).parents[1] / "custom_components/watchguard_firebox/parsers.py"
_spec = importlib.util.spec_from_file_location("wg_parsers", _PATH)
p = importlib.util.module_from_spec(_spec)
sys.modules["wg_parsers"] = p
_spec.loader.exec_module(p)

FIX = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIX / name).read_text()


def test_sysinfo():
    s = p.parse_sysinfo(_load("sysinfo.txt"))
    assert s["system_name"] == "JURASSIC-T25"
    assert s["model"] == "T25"
    assert s["contact"] is None
    assert s["version"] == "12.12.3.B747886"
    assert s["uptime"] == 21 * 86400 + 21 * 3600 + 20 * 60 + 38
    assert (s["cpu_1min"], s["cpu_5min"], s["cpu_15min"]) == (8, 10, 12)
    assert s["memory_total_kb"] == 3869588
    assert s["memory_free_kb"] == 1724216
    assert s["memory_used_kb"] == 2145372


def test_interfaces():
    ifs = p.parse_interfaces(_load("interface.txt"))
    assert sorted(ifs) == [0, 1, 2, 3, 4]
    assert ifs[0].name == "External"
    assert ifs[0].address == "192.168.34.40/24"
    assert ifs[0].type == "external"
    assert ifs[0].up and ifs[0].enabled
    assert ifs[2].name == "WIFI" and not ifs[2].enabled and not ifs[2].up
    assert ifs[3].name == "VLANS-SERVEURS2" and ifs[3].type == "vlan"


def test_arp():
    arp = p.parse_arp(_load("arp.txt"))
    assert len(arp) == 9
    assert arp[0].ip == "172.25.5.200" and arp[0].mac == "02:00:00:00:00:01"
    assert arp[0].interface == "vlan5"
    assert arp[1].mac is None and arp[1].interface == "vlan3"
    assert arp[2].interface == "eth0"


def test_dhcp():
    leases = p.parse_dhcp_leases(_load("dhcp_lease.txt"))
    assert len(leases) == 7
    by_ip = {l.ip: l for l in leases}
    assert by_ip["172.25.5.100"].hostname is None
    assert by_ip["172.25.5.102"].hostname == "Meross Smart Plug"
    assert by_ip["172.25.5.200"].interface == "JURASSIC DOMO"
    assert by_ip["192.168.134.30"].interface == "JURASSIC-ADMIN"
    assert by_ip["192.168.134.30"].hostname == "EAP610-98-BA-5F-C4-39-98"
    assert by_ip["172.25.5.50"].end == datetime(2026, 10, 30, 0, 20, 49)


def test_cli_error():
    assert p.is_cli_error("% Error: invalid input detected")
    assert not p.is_cli_error(_load("arp.txt"))


def test_features():
    from datetime import timezone
    f = p.parse_features(_load("features.txt"))
    assert f["edition"] == "Fireware XTM Pro"
    feats = f["features"]
    assert feats["IPS"].enabled
    assert feats["IPS"].expiration == datetime(2027, 9, 9, 8, 59, 59, tzinfo=timezone.utc)
    assert feats["BOVPN_TUNNEL"].expiration is None
    assert feats["BOVPN_TUNNEL"].capacity == "10"
    assert not feats["MODEL"].enabled
    assert "SERVER_LOAD_BALANCING" in feats


def test_upgrade():
    h = p.parse_upgrade_history(_load("upgrade.txt"))
    assert len(h) == 4
    last = h[-1]
    assert last.action == "Cloud Upgrade"
    assert last.version == "12.12.3" and last.build == "747886"
    assert last.success
    assert last.time == datetime(2026, 10, 7, 21, 1, 4)
    assert h[0].action == "Install"


def test_signature_update():
    s = p.parse_signature_update(_load("signature_update.txt"))
    assert s["interval_hours"] == 1
    assert s["auto"] == {
        "IPS": True,
        "GAV": True,
        "Botnet": True,
        "Geolocation Blocking": True,
        "Tor Exit Node Blocking": True,
    }


def test_login_users():
    sessions = p.parse_login_users(_load("login_user.txt"))
    assert len(sessions) == 2
    assert sessions[0].user == "ha_monitor"
    assert sessions[0].role == "Device Monitor"
    assert sessions[0].elapsed == 3600 + 26 * 60 + 32
    assert sessions[1].ip == "172.25.3.109"


def test_locked_out():
    assert p.parse_locked_out(_load("locked_out.txt")) == 0
    assert p.parse_locked_out("--\n--Total 3 locked users.\n") == 3
    assert p.parse_locked_out("garbage") is None


def test_vlans():
    v = p.parse_vlans(_load("vlan.txt"))
    assert sorted(v) == [1, 2, 3, 4, 5, 98, 99]
    assert v[5].name == "JURASSIC DOMO" and v[5].zone == "optional"
    assert v[5].members == "1(tagged),4(tagged)"
    assert v[1].members == "1(untagged),3(untagged),4(untagged)"
    assert v[98].address == "10.98.0.1/28"
