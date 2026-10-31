"""End-to-end tests inside a Home Assistant test instance."""
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import entity_registry as er

from custom_components.watchguard_firebox.const import DOMAIN

USER_INPUT = {"host": "172.25.5.1", "port": 4118, "username": "ha_monitor", "password": "x"}


async def _setup(hass: HomeAssistant):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    await hass.async_block_till_done()
    return result["result"]


async def test_flow_and_entities(hass: HomeAssistant, mock_client) -> None:
    entry = await _setup(hass)
    assert entry.title == "JURASSIC-T25"
    assert entry.unique_id == "D0000000000AA"
    assert entry.data["host_key_fingerprint"] == "SHA256:testfp"

    assert hass.states.get("sensor.jurassic_t25_cpu_1_min").state == "8.0"
    assert hass.states.get("sensor.jurassic_t25_memory_used").state == "55.4"
    assert hass.states.get("sensor.jurassic_t25_fireware_version").state == "12.12.3.B747886"
    assert hass.states.get("sensor.jurassic_t25_interfaces_arp_entries").state == "7"
    assert hass.states.get("sensor.jurassic_t25_interfaces_dhcp_leases").state == "7"
    assert hass.states.get("sensor.jurassic_t25_last_boot").state not in ("unknown", "unavailable")
    assert hass.states.get("binary_sensor.jurassic_t25_interfaces_external").state == "on"
    assert hass.states.get("binary_sensor.jurassic_t25_interfaces_vlan_home").state == "on"
    # disabled interface -> entity disabled by default
    reg = er.async_get(hass)
    wifi = reg.async_get("binary_sensor.jurassic_t25_interfaces_wifi")
    assert wifi is not None and wifi.disabled_by is not None


async def test_duplicate_aborts(hass: HomeAssistant, mock_client) -> None:
    await _setup(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_device_tracker(hass: HomeAssistant, mock_client) -> None:
    entry = await _setup(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            "scan_interval": 30,
            "poll_dhcp": True,
            "consider_home": 180,
            "tracked_macs": ["02:00:00:00:00:01", "02:00:00:00:00:08"],
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()

    samsung = hass.states.get("device_tracker.samsung")
    assert samsung is not None and samsung.state == "home"
    assert samsung.attributes["ip"] == "172.25.5.200"
    # in DHCP but not in ARP -> away
    shelly = hass.states.get("device_tracker.shellyplusrgbwpm_3076f53bc600")
    assert shelly is not None and shelly.state == "not_home"


async def test_auth_error_triggers_reauth(hass: HomeAssistant, mock_client) -> None:
    from custom_components.watchguard_firebox.api import FireboxAuthError

    entry = await _setup(hass)
    mock_client.run.side_effect = FireboxAuthError("denied")
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    flows = hass.config_entries.flow.async_progress()
    assert any(f["context"]["source"] == "reauth" for f in flows)


async def test_mcs_mco_entities(hass: HomeAssistant, mock_client) -> None:
    await _setup(hass)
    exp = hass.states.get("sensor.jurassic_t25_subscriptions_expiration")
    assert exp.state == "2027-09-09T08:59:59+00:00"
    assert "IPS" in exp.attributes["next_expiring"]
    assert exp.attributes["features"]["BOVPN_TUNNEL"] == "never"
    assert hass.states.get("binary_sensor.jurassic_t25_subscriptions_expiring_soon").state == "off"
    assert hass.states.get("binary_sensor.jurassic_t25_security_signature_auto_update_disabled").state == "off"
    assert hass.states.get("binary_sensor.jurassic_t25_last_upgrade_failed").state == "off"
    up = hass.states.get("sensor.jurassic_t25_last_fireware_upgrade")
    assert up.attributes["version"] == "12.12.3"
    # Firebox local time 21:01:04, test instance runs in America/Los_Angeles (UTC-7)
    assert up.state == "2026-10-08T04:01:04+00:00"
    # HA's own session (ha_monitor @ 172.25.5.50) is excluded
    sess = hass.states.get("sensor.jurassic_t25_security_management_sessions")
    assert sess.state == "1"
    assert sess.attributes["sessions"][0]["ip"] == "172.25.3.109"
    assert sess.attributes["total_including_home_assistant"] == 2
    assert hass.states.get("sensor.jurassic_t25_security_locked_out_accounts").state == "0"
    domo = hass.states.get("sensor.jurassic_t25_interfaces_devices_jurassic_domo")
    assert domo.state == "4"  # .200 .102 .50 .100 (.52 is incomplete)
    assert domo.attributes["dhcp_leases"] == 5
    assert domo.attributes["zone"] == "optional"


async def test_slow_commands_hourly(hass: HomeAssistant, mock_client) -> None:
    entry = await _setup(hass)
    first = mock_client.run.call_args_list[-1].args[0]
    assert "show features" in first
    await entry.runtime_data.async_refresh()
    second = mock_client.run.call_args_list[-1].args[0]
    assert "show features" not in second and "show login-user" in second


async def test_devices_grouping(hass: HomeAssistant, mock_client) -> None:
    from homeassistant.helpers import device_registry as dr

    entry = await _setup(hass)
    dreg = dr.async_get(hass)
    devices = {d.name: d for d in dr.async_entries_for_config_entry(dreg, entry.entry_id)}
    assert set(devices) == {"JURASSIC-T25", "JURASSIC-T25 Security", "JURASSIC-T25 Interfaces"}
    parent = devices["JURASSIC-T25"]
    assert devices["JURASSIC-T25 Security"].via_device_id == parent.id
    assert devices["JURASSIC-T25 Interfaces"].via_device_id == parent.id
    ips = hass.states.get("sensor.jurassic_t25_security_subscription_ips")
    assert ips.state == "2027-09-09T08:59:59+00:00"
    assert ips.attributes["days_remaining"] > 300


async def _setup_with_syslog(hass: HomeAssistant, port: int):
    entry = await _setup(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            "scan_interval": 30,
            "poll_dhcp": True,
            "consider_home": 180,
            "syslog_enabled": True,
            "syslog_port": port,
            "syslog_sources": "127.0.0.1",
            "tracked_macs": [],
        },
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    return entry


async def test_syslog_counters_map_and_events(hass: HomeAssistant, mock_client, socket_enabled) -> None:
    import asyncio
    import socket as pysocket

    from tests.test_syslog_parser import ALLOW_OUT, BOTNET, DENY_IN, GAV, IPS

    with pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    events = []
    hass.bus.async_listen("watchguard_firebox_threat", lambda e: events.append(e.data))
    entry = await _setup_with_syslog(hass, port)
    receiver = entry.runtime_data.syslog
    assert receiver.listening

    with pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM) as s:
        for line in (DENY_IN, DENY_IN, ALLOW_OUT, BOTNET, IPS, GAV):
            s.sendto(line.encode(), ("127.0.0.1", port))
    for _ in range(50):
        if receiver.lines_received >= 6:
            break
        await asyncio.sleep(0.02)
    assert receiver.lines_received == 6
    receiver._tick()
    await hass.async_block_till_done()

    assert hass.states.get("sensor.jurassic_t25_security_packets_denied").state == "2"
    assert hass.states.get("sensor.jurassic_t25_security_botnet_blocked").state == "1"
    assert hass.states.get("sensor.jurassic_t25_security_ips_detections").state == "1"
    assert hass.states.get("sensor.jurassic_t25_security_malware_blocked_av").state == "1"
    t24 = hass.states.get("sensor.jurassic_t25_security_threats_blocked_24_h")
    assert t24.state == "3"
    assert t24.attributes["by_category"] == {"antivirus": 1, "botnet": 1, "ips": 1}
    last = hass.states.get("sensor.jurassic_t25_security_last_threat")
    assert last.attributes["category"] == "antivirus"
    assert last.attributes["detail"] == "EICAR_Test_File"
    countries = hass.states.get("sensor.jurassic_t25_security_countries_blocked_24_h")
    assert countries.state == "3"  # CHN, RUS, NLD
    assert countries.attributes["top"][0]["iso3"] == "CHN"
    assert countries.attributes["top"][0]["blocked"] == 2
    assert hass.states.get("binary_sensor.jurassic_t25_security_syslog_receiving").state == "on"
    assert sorted(e["category"] for e in events) == ["antivirus", "botnet", "ips"]

    geo = [s for s in hass.states.async_all("geo_location")]
    by_iso = {s.attributes["iso3"]: s for s in geo}
    assert set(by_iso) == {"CHN", "USA", "RUS", "NLD"}
    assert hass.states.get("geo_location.firebox_chn") is not None
    assert by_iso["CHN"].attributes["blocked_24h"] == 2
    assert by_iso["USA"].attributes["allowed_24h"] == 1
    assert by_iso["CHN"].attributes["source"] == "watchguard_firebox"
    assert "China" in by_iso["CHN"].name or "Chine" in by_iso["CHN"].name

    # spoofed source is rejected
    receiver.allowed_sources = {"10.0.0.1"}
    with pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM) as s:
        s.sendto(IPS.encode(), ("127.0.0.1", port))
    for _ in range(50):
        if receiver.lines_rejected:
            break
        await asyncio.sleep(0.02)
    assert receiver.lines_rejected == 1 and receiver.totals["ips"] == 1

    # counters survive a reload (persisted in .storage)
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.runtime_data.syslog.totals["botnet"] == 1
    assert hass.states.get("sensor.jurassic_t25_security_botnet_blocked").state == "1"
