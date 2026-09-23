from functools import cached_property

from sekoia_automation.action import Action

from vmray_modules.client import VMRayClient
from vmray_modules.models import VMRayModule


class VMRayAction(Action):
    """Shared base for every VMRay action. Mirrors Glimps/glimps/base.py's
    shape: one cached client, built once per action run from the module
    configuration."""

    module: VMRayModule

    @cached_property
    def client(self) -> VMRayClient:
        config = self.module.configuration
        version = self.module.manifest.get("version", "0.0.0")
        return VMRayClient(
            base_url=config.base_url,
            api_key=config.api_key,
            verify_ssl=config.verify_ssl,
            user_agent_suffix=f"Sekoia/{version}",
        )
