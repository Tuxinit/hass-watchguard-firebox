"""Config flow for the WatchGuard Firebox integration."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import callback
from homeassistant.helpers import selector

from .api import (
    FireboxAuthError,
    FireboxClient,
    FireboxConnectionError,
    FireboxHostKeyError,
)
from .const import (
    CMD_SYSINFO,
    CONF_CONSIDER_HOME,
    CONF_HOST_KEY,
    CONF_POLL_DHCP,
    CONF_TRACKED_MACS,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MIN_SCAN_INTERVAL,
)
from .coordinator import FireboxConfigEntry
from .parsers import parse_sysinfo

_LOGGER = logging.getLogger(__name__)


async def _probe(
    host: str, port: int, username: str, password: str, fingerprint: str | None
) -> tuple[dict, str | None]:
    """Log in, read sysinfo, return (sysinfo, host key fingerprint)."""
    client = FireboxClient(host, port, username, password, fingerprint)
    try:
        out = await client.run([CMD_SYSINFO])
    finally:
        await client.close()
    return parse_sysinfo(out[CMD_SYSINFO]), client.host_key_fingerprint


class FireboxConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for WatchGuard Firebox."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info, fp = await _probe(
                    user_input[CONF_HOST],
                    user_input[CONF_PORT],
                    user_input[CONF_USERNAME],
                    user_input[CONF_PASSWORD],
                    None,
                )
            except FireboxAuthError:
                errors["base"] = "invalid_auth"
            except FireboxConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected error during Firebox setup")
                errors["base"] = "unknown"
            else:
                if not info.get("serial_number"):
                    errors["base"] = "unexpected_output"
                else:
                    await self.async_set_unique_id(info["serial_number"])
                    self._abort_if_unique_id_configured(
                        updates={CONF_HOST: user_input[CONF_HOST]}
                    )
                    return self.async_create_entry(
                        title=info.get("system_name") or user_input[CONF_HOST],
                        data={**user_input, CONF_HOST_KEY: fp},
                    )

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(schema, user_input or {}),
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Re-enter the password, and optionally accept a new SSH host key."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            accept_new_key = user_input.get("accept_new_host_key", False)
            try:
                info, fp = await _probe(
                    entry.data[CONF_HOST],
                    entry.data.get(CONF_PORT, DEFAULT_PORT),
                    entry.data[CONF_USERNAME],
                    user_input[CONF_PASSWORD],
                    None if accept_new_key else entry.data.get(CONF_HOST_KEY),
                )
            except FireboxHostKeyError:
                errors["base"] = "host_key_changed"
            except FireboxAuthError:
                errors["base"] = "invalid_auth"
            except FireboxConnectionError:
                errors["base"] = "cannot_connect"
            else:
                if info.get("serial_number") != entry.unique_id:
                    return self.async_abort(reason="wrong_device")
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={CONF_PASSWORD: user_input[CONF_PASSWORD], CONF_HOST_KEY: fp},
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                    ),
                    vol.Optional("accept_new_host_key", default=False): bool,
                }
            ),
            description_placeholders={"host": entry.data[CONF_HOST]},
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: FireboxConfigEntry) -> OptionsFlow:
        return FireboxOptionsFlow()


class FireboxOptionsFlow(OptionsFlow):
    """Options: polling and device tracking."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        opts = self.config_entry.options
        tracked: list[str] = opts.get(CONF_TRACKED_MACS, [])

        # Candidate devices: DHCP leases + complete ARP entries + already tracked
        choices: dict[str, str] = {}
        coordinator = getattr(self.config_entry, "runtime_data", None)
        if coordinator is not None and coordinator.data is not None:
            data = coordinator.data
            for lease in data.dhcp or []:
                label = lease.hostname or "?"
                choices[lease.mac] = f"{label} — {lease.ip} ({lease.mac})"
            for arp in data.arp:
                if arp.mac and arp.mac not in choices:
                    choices[arp.mac] = f"{arp.ip} ({arp.mac}, {arp.interface})"
        for mac in tracked:
            choices.setdefault(mac, mac)

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=opts.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): vol.All(vol.Coerce(int), vol.Range(min=MIN_SCAN_INTERVAL, max=3600)),
                vol.Required(
                    CONF_POLL_DHCP, default=opts.get(CONF_POLL_DHCP, True)
                ): bool,
                vol.Required(
                    CONF_CONSIDER_HOME,
                    default=opts.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME),
                ): vol.All(vol.Coerce(int), vol.Range(min=0, max=86400)),
                vol.Optional(CONF_TRACKED_MACS, default=tracked): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(value=mac, label=label)
                            for mac, label in sorted(choices.items(), key=lambda kv: kv[1].lower())
                        ],
                        multiple=True,
                        custom_value=True,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
