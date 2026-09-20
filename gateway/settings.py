"""Compatibility surface for canonical GatewaySettings."""

from narrowcti.infrastructure.config.settings import (
    GatewaySettings,
    env_bool,
    env_bool_alias,
    env_int,
    env_int_alias,
    env_list,
    load_settings,
)

__all__ = [
    "GatewaySettings", "env_int", "env_bool", "env_int_alias", "env_bool_alias",
    "env_list", "load_settings",
]
