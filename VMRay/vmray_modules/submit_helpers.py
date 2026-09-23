"""Shared submission logic, used by SubmitUrl, SubmitFile, SubmitAndWait and
SubmitAndEnrich so none of them duplicate it.

Field names confirmed against the VMRay Platform REST API OpenAPI spec,
v2026.2.1: `data.submissions[].submission_id`, `data.samples[].sample_id`,
`data.jobs[].job_id`, `data.errors[].{error_msg, submission_filename}`.

A 200 here does NOT mean the sample was accepted — `data.errors` must be
checked explicitly (design doc, "HTTP client contract").
"""

import time
from pathlib import Path
from typing import Any

from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.client import VMRayClient
from vmray_modules.models import SubmitAndWaitArguments, SubmitAndWaitResults, SubmitResults


def parse_submit_response(data: dict[str, Any]) -> SubmitResults:
    submissions = data.get("submissions") or []
    samples = data.get("samples") or []
    jobs = data.get("jobs") or []
    errors = data.get("errors") or []

    return SubmitResults(
        submission_id=submissions[0]["submission_id"] if submissions else None,
        sample_id=samples[0]["sample_id"] if samples else None,
        job_ids=[j["job_id"] for j in jobs if "job_id" in j],
        errors=errors,
    )


def submit(client: VMRayClient, data_path: Path, arguments: SubmitAndWaitArguments) -> dict[str, Any]:
    if arguments.sample_url:
        return client.submit_url(
            sample_url=arguments.sample_url,
            tags=arguments.tags,
            reanalyze=arguments.reanalyze,
            analysis_caching=arguments.analysis_caching,
        )
    if arguments.file_name:
        return client.submit_file(
            file_path=str(data_path.joinpath(arguments.file_name)),
            file_name=arguments.file_name,
            tags=arguments.tags,
            reanalyze=arguments.reanalyze,
            analysis_caching=arguments.analysis_caching,
        )
    raise MissingActionArgumentError("sample_url or file_name")


def wait_for_submission(client: VMRayClient, submission_id: int, timeout: float, pull_time: float) -> bool:
    """Poll GET /submission/{id} until `submission_finished`. A 429/5xx on any
    single poll is already absorbed by the client's retry adapter — this loop
    only needs its own sleep cadence, not special-cased throttling logic."""
    deadline = time.monotonic() + timeout
    while True:
        submission = client.get_submission(submission_id)
        if submission.get("submission_finished"):
            return True

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False

        time.sleep(min(pull_time, remaining))


def submit_and_wait(client: VMRayClient, data_path: Path, arguments: SubmitAndWaitArguments) -> SubmitAndWaitResults:
    """The core of SubmitAndWait, extracted so SubmitAndEnrich can reuse it
    without duplicating submit/poll logic."""
    response = submit(client, data_path, arguments)
    submitted = parse_submit_response(response)

    if submitted.submission_id is None:
        return SubmitAndWaitResults(errors=submitted.errors)

    finished = wait_for_submission(client, submitted.submission_id, arguments.timeout, arguments.pull_time)

    if not finished:
        return SubmitAndWaitResults(
            submission_id=submitted.submission_id,
            sample_id=submitted.sample_id,
            timed_out=True,
            errors=submitted.errors,
        )

    sample = client.get_sample(submitted.sample_id) if submitted.sample_id else {}

    return SubmitAndWaitResults(
        submission_id=submitted.submission_id,
        sample_id=submitted.sample_id,
        sample_verdict=sample.get("sample_verdict"),
        sample_vti_score=sample.get("sample_vti_score"),
        sample_webif_url=sample.get("sample_webif_url"),
        errors=submitted.errors,
    )
