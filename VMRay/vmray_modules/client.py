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
endpoint coverage added (quota, system_info, reanalyze), and errors are
raised as typed exceptions for the caller to catch per-section rather than
letting one failure abort a whole fan-out.

Endpoint paths and response shapes are as confirmed against the VMRay
Platform REST API OpenAPI spec, v2026.2.1 (spikes/specs/vmray-openapi-2026.2.1.json
in the design repo) — see the design doc's "VMRay API surface" table.
"""

import base64
import os
from typing import Any

from requests import Response, sessions
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_USER_AGENT = "Sekoia-VMRay-Module"

# Retried automatically at the transport layer. 429 honours Retry-After via
# respect_retry_after_header; 5xx get capped exponential backoff instead.
_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)
_RETRY_TOTAL = 5

# VMRay's documented default password for the encrypted sample-file ZIP when
# no encryption_password argument is supplied (GET /sample/{id}/file).
DEFAULT_SAMPLE_FILE_PASSWORD = "infected"


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


class SampleFileNotFoundError(VMRayClientError):
    """A local file path passed for submission does not exist."""


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
    _quota = "/rest/api_key/quota"
    _submit = "/rest/sample/submit"
    _submission = "/rest/submission/{submission_id}"
    _sample = "/rest/sample/{sample_id}"
    _sample_by_hash = "/rest/sample/{hash_type}/{hash_value}"
    _sample_file = "/rest/sample/{sample_id}/file"
    _sample_report = "/rest/sample/{sample_id}/report"
    _sample_vtis = "/rest/sample/{sample_id}/vtis"
    _sample_iocs = "/rest/sample/{sample_id}/iocs"
    _sample_mitre_attack = "/rest/sample/{sample_id}/mitre_attack"
    _sample_threat_names = "/rest/sample/{sample_id}/threat_names"
    _sample_classifications = "/rest/sample/{sample_id}/classifications"
    _sample_relations = "/rest/sample_relation/sample/{sample_id}"
    _analysis_reanalyze = "/rest/analysis/{analysis_id}/reanalyze"
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

    # -- system / account ----------------------------------------------

    def system_info(self) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._system_info)))

    def quota(self) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._quota)))

    # -- submission -------------------------------------------------------

    def submit_url(
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

    def submit_file(
        self,
        file_path: str,
        file_name: str,
        tags: list[str] | None = None,
        reanalyze: bool = False,
        analysis_caching: bool = True,
        **extra_params: Any,
    ) -> dict[str, Any]:
        if not (file_path and os.path.isfile(file_path)):
            raise SampleFileNotFoundError(f"Sample file not found at '{file_path}'.")
        params = _drop_none(
            {
                "sample_filename_b64enc": base64.b64encode(file_name.encode("utf-8")).decode("utf-8"),
                "reanalyze": reanalyze,
                "analysis_caching": analysis_caching,
                "tags": ",".join(tags) if tags else None,
                **extra_params,
            }
        )
        with open(file_path, mode="rb") as fh:
            return self._check_response(
                self.session.post(self._url(self._submit), data=params, files={"sample_file": fh})
            )

    def get_submission(self, submission_id: int) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._submission.format(submission_id=submission_id))))

    def reanalyze(self, analysis_id: int) -> dict[str, Any]:
        url = self._url(self._analysis_reanalyze.format(analysis_id=analysis_id))
        return self._check_response(self.session.post(url))

    # -- sample -------------------------------------------------------------

    def get_sample(self, sample_id: int) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._sample.format(sample_id=sample_id))))

    def get_sample_by_hash(self, sample_hash: str) -> list[dict[str, Any]]:
        """Zero-quota lookup. Returns [] if VMRay has never analysed this hash."""
        return self._check_response(
            self.session.get(
                self._url(self._sample_by_hash.format(hash_type=_hash_type(sample_hash), hash_value=sample_hash))
            )
        )

    def get_sample_vtis(self, sample_id: int) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._sample_vtis.format(sample_id=sample_id))))

    def get_sample_iocs(self, sample_id: int, ioc_severity: str | None = None) -> dict[str, Any]:
        params = _drop_none({"ioc_severity": ioc_severity})
        return self._check_response(
            self.session.get(self._url(self._sample_iocs.format(sample_id=sample_id)), params=params)
        )

    def get_sample_mitre_attack(self, sample_id: int) -> dict[str, Any]:
        return self._check_response(self.session.get(self._url(self._sample_mitre_attack.format(sample_id=sample_id))))

    def get_sample_threat_names(self, sample_id: int) -> dict[str, Any]:
        """Recursive (children) threat names — 2026.2+ only. Distinct from
        the base sample object's own `sample_threat_names` field."""
        return self._check_response(self.session.get(self._url(self._sample_threat_names.format(sample_id=sample_id))))

    def get_sample_classifications(self, sample_id: int) -> dict[str, Any]:
        """Recursive (children) classifications — 2026.2+ only. Distinct from
        the base sample object's own `sample_classifications` field."""
        return self._check_response(
            self.session.get(self._url(self._sample_classifications.format(sample_id=sample_id)))
        )

    def get_sample_relations(self, sample_id: int) -> list[dict[str, Any]]:
        """Fallback only — the base sample object's `sample_child_relations`
        is preferred and only truncated for very large families."""
        return self._check_response(self.session.get(self._url(self._sample_relations.format(sample_id=sample_id))))

    def get_sample_file(self, sample_id: int, encryption_password: str | None = None) -> bytes:
        """Returns the sample wrapped in an encrypted ZIP — never raw bytes.
        VMRay encrypts with `DEFAULT_SAMPLE_FILE_PASSWORD` ("infected") unless
        `encryption_password` is given."""
        params = _drop_none({"encryption_password": encryption_password})
        res = self.session.get(self._url(self._sample_file.format(sample_id=sample_id)), params=params)
        self._raise_for_status(res)
        return res.content

    def get_sample_report(self, sample_id: int) -> bytes:
        res = self.session.get(self._url(self._sample_report.format(sample_id=sample_id)))
        self._raise_for_status(res)
        return res.content
