"""
Thin client for the VMRay Platform REST API.

Deliberately hand-rolled rather than built on the official `vmray-rest-api`
PyPI package: that package's `VMRayRESTAPIError` only preserves `status_code`,
not response headers, so it cannot honour a `Retry-After` value — a real gap
against this module's documented 429 contract (design doc, "HTTP client
contract"). Retry-After handling instead lives at the transport layer via
urllib3's `Retry(respect_retry_after_header=True)`, which needs no response
object survives past the exception to work.

Loosely modelled on the Cortex-Analyzers VMRay analyzer's client (structure,
exception hierarchy, retry-adapter pattern) — adapted, not copied: retry
budget raised to 5 attempts (this module's documented contract), full
endpoint coverage added (system_info), and errors are
raised as typed exceptions for the caller to catch per-section rather than
letting one failure abort a whole fan-out.

Endpoint paths and response shapes are as confirmed against the VMRay
Platform REST API OpenAPI spec, v2026.2.1 (spikes/specs/vmray-openapi-2026.2.1.json
in the design repo) — see the design doc's "VMRay API surface" table.
"""

from typing import Any

from requests import Response, sessions
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_USER_AGENT = "Sekoia-VMRay-Module"

# Retried automatically at the transport layer. 429 honours Retry-After via
# respect_retry_after_header; 5xx get capped exponential backoff instead.
_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)
_RETRY_TOTAL = 5


class VMRayClientError(Exception):
    """Base class for every error this client raises."""


class VMRayAPIError(VMRayClientError):
    """The API answered 2xx but its own body envelope reports an error
    (`result` != "ok", or an `error_msg` field is present)."""


class BadResponseError(VMRayClientError):
    """The API answered with a non-2xx HTTP status, after the transport-level
    retry budget for 429/5xx was already exhausted."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class UnknownHashTypeError(VMRayClientError):
    """A hash string's length matches none of md5 (32), sha1 (40) or
    sha256 (64) hex characters."""


def _hash_type(value: str) -> str:
    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    raise UnknownHashTypeError(f"'{value}' is not a valid md5/sha1/sha256 hex hash ({length} chars).")


def _drop_none(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None}


class VMRayClient:
    """
    Client for the VMRay Platform REST API.

    :param base_url: VMRay Platform URL, e.g. https://eu.cloud.vmray.com
    :param api_key: VMRay API key
    :param verify_ssl: verify the server's TLS certificate (False for a
        self-signed on-prem appliance)
    :param user_agent_suffix: appended to the User-Agent, e.g. the module
        version, so VMRay-side logs can identify the calling integration
    """

    # -- endpoint paths, one place, matching the OpenAPI spec verbatim -----
    _system_info = "/rest/system_info"
    _submit = "/rest/sample/submit"
    _submission = "/rest/submission/{submission_id}"
    _sample = "/rest/sample/{sample_id}"
    _sample_by_hash = "/rest/sample/{hash_type}/{hash_value}"
    _sample_vtis = "/rest/sample/{sample_id}/vtis"
    _sample_iocs = "/rest/sample/{sample_id}/iocs"
    _sample_mitre_attack = "/rest/sample/{sample_id}/mitre_attack"
    _sample_threat_names = "/rest/sample/{sample_id}/threat_names"
    _sample_classifications = "/rest/sample/{sample_id}/classifications"
    _sample_analyses = "/rest/analysis/sample/{sample_id}"
    _sample_submissions = "/rest/submission/sample/{sample_id}"
    _submission_analyses = "/rest/analysis/submission/{submission_id}"
    _continuation = "/rest/continuation/{continuation_id}"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify_ssl: bool = True,
        user_agent_suffix: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = sessions.Session()
        user_agent = DEFAULT_USER_AGENT + (f" ({user_agent_suffix})" if user_agent_suffix else "")
        self.session.headers.update(
            {
                "Authorization": f"api_key {api_key}",
                "Accept": "application/json",
                "User-Agent": user_agent,
            }
        )
        self.session.verify = verify_ssl
        self._mount_retry_adapter()

    def _mount_retry_adapter(self) -> None:
        """Retries 429/5xx at the transport layer. `respect_retry_after_header`
        makes urllib3 honour the server's `Retry-After` value directly —
        the whole reason this module doesn't depend on the vendor SDK's
        client, whose raised exception drops response headers entirely."""
        retry = Retry(
            total=_RETRY_TOTAL,
            connect=_RETRY_TOTAL,
            read=_RETRY_TOTAL,
            status=_RETRY_TOTAL,
            status_forcelist=_RETRY_STATUS_CODES,
            allowed_methods=frozenset(["GET", "HEAD", "POST", "DELETE"]),
            backoff_factor=1,
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _raise_for_status(self, res: Response) -> None:
        """Layer 1 of the module's 3-layer error contract: HTTP status."""
        if not (200 <= res.status_code < 300):
            message = res.text
            try:
                body = res.json()
                if isinstance(body, dict) and body.get("error_msg"):
                    message = body["error_msg"]
            except ValueError:
                pass
            raise BadResponseError(f"VMRay API request failed (HTTP {res.status_code}): {message}", res.status_code)

    def _check_response(self, res: Response) -> Any:
        """Layers 2+3: HTTP status, then the body envelope (`result` field,
        checked even on a 200), then continuation-id pagination, drained
        immediately since a continuation id is single-shot per the API docs."""
        self._raise_for_status(res)
        body = res.json()

        if body.get("result") != "ok":
            # Layer 2 — a 2xx whose envelope still reports an error.
            error_msg = body.get("error_msg", "VMRay API returned an unspecified error.")
            raise VMRayAPIError(error_msg)

        data = body.get("data", [])
        continuation_id = body.get("continuation_id")
        while continuation_id:
            res = self.session.get(self._url(self._continuation.format(continuation_id=continuation_id)))
            self._raise_for_status(res)
            body = res.json()
            if body.get("result") != "ok":
                raise VMRayAPIError(body.get("error_msg", "VMRay API returned an unspecified error."))
            data.extend(body.get("data", []))
            continuation_id = body.get("continuation_id")

        return data

    # -- system -----------------------------------------------------------

    def system_info(self) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._system_info)))

    # -- submission -------------------------------------------------------

    def submit_url_sample(
        self,
        sample_url: str,
        tags: list[str] | None = None,
        reanalyze: bool = False,
        analysis_caching: bool = True,
        **extra_params: Any,
    ) -> dict[str, Any]:
        params = _drop_none(
            {
                "sample_url": sample_url,
                "reanalyze": reanalyze,
                "analysis_caching": analysis_caching,
                "tags": ",".join(tags) if tags else None,
                **extra_params,
            }
        )
        return self._check_response(self.session.post(self._url(self._submit), data=params))

    def update_submission(self, submission_id: int) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._submission.format(submission_id=submission_id))))

    # -- sample -------------------------------------------------------------

    def get_sample(self, sample_id: int) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._sample.format(sample_id=sample_id))))

    def get_samples_by_hash(self, sample_hash: str) -> list[dict[str, Any]]:
        """Zero-quota lookup. Returns [] if VMRay has never analysed this hash."""
        return self._check_response(
            self.session.get(
                self._url(self._sample_by_hash.format(hash_type=_hash_type(sample_hash), hash_value=sample_hash))
            )
        )

    def get_sample_threat_indicators(self, sample_id: int) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._sample_vtis.format(sample_id=sample_id))))

    def get_sample_iocs(self, sample_id: int, severity: str | None = None) -> dict[str, Any]:
        params = _drop_none({"ioc_severity": severity})
        return self._check_response(
            self.session.get(self._url(self._sample_iocs.format(sample_id=sample_id)), params=params)
        )

    def get_sample_mitre_attack(self, sample_id: int) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._sample_mitre_attack.format(sample_id=sample_id))))

    def get_sample_threat_names(self, sample_id: int) -> list[str]:
        """Unique threat names of the sample and its recursive children (children: 2026.2+ only)."""
        data = self._check_response(self.session.get(self._url(self._sample_threat_names.format(sample_id=sample_id))))
        entries = data.get("sample_threat_names", []) + data.get("children_threat_names", [])
        return sorted({e["threat_name"] for e in entries if e.get("threat_name")})

    def get_sample_classifications(self, sample_id: int) -> list[str]:
        """Unique classifications of the sample and its recursive children (children: 2026.2+ only)."""
        data = self._check_response(
            self.session.get(self._url(self._sample_classifications.format(sample_id=sample_id)))
        )
        entries = data.get("sample_classifications", []) + data.get("children_classifications", [])
        return sorted({e["classification_name"] for e in entries if e.get("classification_name")})

    def get_sample_latest_submission(self, sample_id: int) -> dict[str, Any] | None:
        submissions = self._check_response(
            self.session.get(self._url(self._sample_submissions.format(sample_id=sample_id)))
        )
        if not submissions:
            return None
        return max(submissions, key=lambda submission: submission.get("submission_created", ""))

    def get_sample_analyses(self, sample_id: int, verdicts: list[str] | None = None) -> list[dict[str, Any]]:
        """Analyses of the sample's LATEST submission — the run its current verdict
        comes from — falling back to every analysis of the sample if it has no
        submission. One sample can carry several analyses (different VM profiles)."""
        latest_submission = self.get_sample_latest_submission(sample_id)
        if latest_submission:
            return self.get_submission_analyses(latest_submission["submission_id"], verdicts=verdicts)
        analyses = self._check_response(self.session.get(self._url(self._sample_analyses.format(sample_id=sample_id))))
        return self._filter_analyses_by_verdict(analyses, verdicts)

    def get_submission_analyses(self, submission_id: int, verdicts: list[str] | None = None) -> list[dict[str, Any]]:
        analyses = self._check_response(
            self.session.get(self._url(self._submission_analyses.format(submission_id=submission_id)))
        )
        return self._filter_analyses_by_verdict(analyses, verdicts)

    @staticmethod
    def _filter_analyses_by_verdict(
        analyses: list[dict[str, Any]], verdicts: list[str] | None
    ) -> list[dict[str, Any]]:
        wanted = {v.strip().lower() for v in verdicts or [] if v}
        if not wanted:
            return analyses
        return [a for a in analyses if (a.get("analysis_verdict") or "").lower() in wanted]
