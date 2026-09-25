"""Submission form parameters shared by the submitting actions.

Field names confirmed against the VMRay Platform REST API OpenAPI spec, v2026.2.1.
"""

import json
from typing import Any

from vmray_modules.models import SubmissionOptions

_FORM_OPTIONS = {
    "enable_reputation",
    "enable_whois",
    "analyzer_mode",
    "known_malicious",
    "known_benign",
    "max_jobs",
    "archive_action",
    "archive_password",
    "shareable",
    "max_recursive_samples",
}


def submission_params(options: SubmissionOptions) -> dict[str, Any]:
    """Extra POST /sample/submit form fields. Unset options are omitted so the
    VMRay user's analyzer defaults apply; net_scheme_name and analysis_timeout
    aren't form fields and go inside the user_config JSON string instead."""
    params = options.model_dump(include=_FORM_OPTIONS, exclude_none=True)
    user_config = {"net_scheme_name": options.net_scheme_name, "timeout": options.analysis_timeout}
    user_config = {k: v for k, v in user_config.items() if v is not None}
    if user_config:
        params["user_config"] = json.dumps(user_config)
    return params
