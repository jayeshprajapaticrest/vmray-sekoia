from functools import cached_property
from typing import Any

import orjson
from pydantic import ValidationError
from sekoia_automation.action import Action
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.client import VMRayClient
from vmray_modules.models import Report, VMRayModule
from vmray_modules.report_models import ReportInput


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

    def load_report(self, arguments: ReportInput) -> dict[str, Any]:
        """The Build report result: the file at `report_path`, else the inline `report`. An empty `report` counts
        as not given — Sekoia's playbook editor sends `{}` for an object input left blank, and taking that over
        `report_path` would render and extract an empty report.

        The report is checked against the report model, so a malformed one fails here with a clear message
        instead of half-way through rendering. `report_path` must stay inside the playbook run's data path."""
        if arguments.report_path:
            data_path = self.data_path.resolve()
            path = (data_path / arguments.report_path).resolve()
            if not path.is_relative_to(data_path):
                raise ValueError(f"report_path must be a Build report file: {arguments.report_path!r}")
            try:
                data = orjson.loads(path.read_bytes())
            except FileNotFoundError:
                raise ValueError(f"No report file at {arguments.report_path!r} — give Build report's report_path")
            except (OSError, orjson.JSONDecodeError) as exc:
                raise ValueError(f"The report file {arguments.report_path!r} could not be read: {exc}") from exc
        elif arguments.report:
            data = arguments.report
        else:
            raise MissingActionArgumentError("report_path")
        try:
            return Report.model_validate(data).model_dump(mode="json")
        except ValidationError as exc:
            raise ValueError(f"Not a Build report result: {exc.error_count()} invalid field(s)") from exc
