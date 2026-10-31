"""Syslog parser/classifier tests (lines built from the Fireware log format)."""
from pathlib import Path
import importlib.util
import sys

_PATH = Path(__file__).parents[1] / "custom_components/watchguard_firebox/syslog_parser.py"
_spec = importlib.util.spec_from_file_location("wg_syslog_parser", _PATH)
sp = importlib.util.module_from_spec(_spec)
sys.modules["wg_syslog_parser"] = sp
_spec.loader.exec_module(sp)

HDR = "<142>Oct 31 10:00:00 JURASSIC-T25 D0000000000AA (2026-10-31T09:00:00)"

DENY_IN = (
    f'{HDR} firewall: msg_id="3000-0148" Deny 0-External Firebox 60 tcp 20 51 '
    '203.0.113.7 192.168.34.40 51544 22 offset 10 S 1234 win 64240 '
    'geo_src="CHN" geo_dst="FRA" (Unhandled External Packet-00)'
)
ALLOW_OUT = (
    f'{HDR} firewall: msg_id="3000-0148" Allow 1-Trusted 0-External 52 tcp 20 128 '
    '172.25.3.109 93.184.216.34 50000 443 offset 8 S 99 win 64 '
    'geo_src="FRA" geo_dst="USA" (HTTPS-proxy-00)'
)
BOTNET = (
    f'{HDR} firewall: msg_id="3000-0148" Deny 1-Trusted 0-External 52 tcp 20 128 '
    '172.25.5.101 198.51.100.9 50001 8080 offset 8 S 1 win 64 '
    'geo_src="FRA" geo_dst="RUS" (Botnet Detection-00)'
)
IPS = (
    f'{HDR} firewall: msg_id="3000-0150" Deny 0-External 1-Trusted tcp '
    '198.51.100.20 172.25.2.10 4444 80 signature_name="WEB Apache Struts RCE" '
    'signature_cat="Web Attack" signature_id="1133407" severity="5" '
    'geo_src="NLD" geo_dst="FRA" (IPS-00)'
)
GAV = (
    f'{HDR} http-proxy[2160]: msg_id="1AFF-0028" Deny 1-Trusted 0-External tcp '
    '172.25.3.102 203.0.113.80 51000 80 msg="ProxyDrop: HTTP Virus found" '
    'proxy_act="HTTP-Client.Standard.1" virus="EICAR_Test_File" host="example.test" '
    'path="/eicar.com" (HTTP-proxy-00)'
)
WEBBLOCKER_ALLOW = (
    f'{HDR} https-proxy[1]: msg_id="2CFF-0001" Allow 1-Trusted 0-External tcp '
    '172.25.3.102 203.0.113.81 51001 443 cats="News" (HTTPS-proxy-00)'
)
ADMIN_FAIL = f'{HDR} admd[1]: msg_id="3E00-0003" Authentication of Firebox-DB user [admin@192.0.2.5] failed'


def test_deny_inbound():
    e = sp.parse_line(DENY_IN)
    assert e.msg_id == "3000-0148"
    assert e.action == "Deny"
    assert e.src_ip == "203.0.113.7" and e.dst_ip == "192.168.34.40"
    assert e.policy == "Unhandled External Packet-00"
    assert e.category == "denied"
    assert e.remote_country == "CHN"
    assert e.remote_ip == "203.0.113.7"
    assert e.process == "firewall"


def test_allow_outbound_country_is_destination():
    e = sp.parse_line(ALLOW_OUT)
    assert e.category == "allowed"
    assert e.remote_country == "USA"
    assert e.remote_ip == "93.184.216.34"


def test_botnet_keyword():
    e = sp.parse_line(BOTNET)
    assert e.category == "botnet"
    assert e.remote_country == "RUS"


def test_ips():
    e = sp.parse_line(IPS)
    assert e.category == "ips"
    assert e.detail == "WEB Apache Struts RCE"
    assert e.src_ip == "198.51.100.20"
    assert e.remote_country == "NLD"


def test_gav():
    e = sp.parse_line(GAV)
    assert e.category == "antivirus"
    assert e.detail == "EICAR_Test_File"
    assert e.process == "http-proxy"


def test_webblocker_allow_is_not_a_block():
    assert sp.parse_line(WEBBLOCKER_ALLOW).category is None


def test_admin_login_failed():
    e = sp.parse_line(ADMIN_FAIL)
    assert e.category == "admin_login_failed"
    assert e.action is None


def test_smart_quotes_and_garbage():
    e = sp.parse_line(DENY_IN.replace('"', "”"))
    assert e is not None and e.msg_id == "3000-0148" and e.remote_country == "CHN"
    assert sp.parse_line("<13>Oct 31 hello world") is None
