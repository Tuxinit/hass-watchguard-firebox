"""Fixtures."""
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

FIX = Path(__file__).parent / "fixtures"
OUTPUTS = {
    "show sysinfo": (FIX / "sysinfo.txt").read_text(),
    "show interface": (FIX / "interface.txt").read_text(),
    "show arp": (FIX / "arp.txt").read_text(),
    "show dhcp lease": (FIX / "dhcp_lease.txt").read_text(),
    "show features": (FIX / "features.txt").read_text(),
    "show upgrade": (FIX / "upgrade.txt").read_text(),
    "show signature-update": (FIX / "signature_update.txt").read_text(),
    "show login-user": (FIX / "login_user.txt").read_text(),
    "show locked-out": (FIX / "locked_out.txt").read_text(),
    "show vlan": (FIX / "vlan.txt").read_text(),
}


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
def mock_client():
    async def _run(cmds):
        return {c: OUTPUTS[c] for c in cmds}

    with patch(
        "custom_components.watchguard_firebox.FireboxClient", autospec=True
    ) as m1, patch(
        "custom_components.watchguard_firebox.config_flow.FireboxClient", autospec=True
    ) as m2:
        for m in (m1, m2):
            inst = m.return_value
            inst.run = AsyncMock(side_effect=_run)
            inst.close = AsyncMock()
            inst.host_key_fingerprint = "SHA256:testfp"
            inst.local_ip = "172.25.5.50"
            inst.username = "ha_monitor"
        yield m1.return_value
