"""End-to-end tests: each action runs the way Sekoia runs it — `Action.execute()`, reading its `arguments` and
`module_configuration` files and reporting results, outputs and errors to the callback URL — against a fake
VMRay, chained the way the playbooks chain them."""

import io
import json
import re
from pathlib import Path
from typing import ClassVar

import pytest
from PIL import Image
from sekoia_automation.configuration.filesystem import FileSystemConfiguration

from vmray_modules.build_report_action import BuildReport
from vmray_modules.extract_iocs_action import ExtractIocs
from vmray_modules.get_samples_by_hash_action import GetSamplesByHash
from vmray_modules.models import VMRayModule
from vmray_modules.render_report_action import RenderReport
from vmray_modules.submit_url_sample_action import SubmitUrlSample

BASE_URL = "https://eu.cloud.vmray.com"

CALLBACK = "https://sekoia.example/api/v1/symphony/callback/run-1"
SHA256 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
MD5 = "9e107d9d372bb6826bd81d3542a419d6"
UNKNOWN = "0" * 64
URL = "https://login-check.example/verify"


def ok(data):
    return {"result": "ok", "data": data}


def png(color=(200, 30, 40)):
    buf = io.BytesIO()
    Image.new("RGB", (1600, 900), color).save(buf, format="PNG")
    return buf.getvalue()


class FakeVMRay:
    """One parent sample (42) with a malicious child (43) that has a clean grandchild (44); 42 has two
    screenshots in its newest analysis. A URL submission (111) resolves to sample 42."""

    def __init__(self, mocker, broken=()):
        self.m = mocker
        for sample_id in (42, 43, 44):
            self._sample(sample_id)
        self.m.get(f"{BASE_URL}/rest/sample/sha256/{SHA256}", json=ok([self.samples[42]]))
        self.m.get(f"{BASE_URL}/rest/sample/md5/{MD5}", json=ok([self.samples[42]]))
        self.m.get(f"{BASE_URL}/rest/sample/sha256/{UNKNOWN}", json=ok([]))
        self.m.post(f"{BASE_URL}/rest/sample/submit", json=ok({"submissions": [{"submission_id": 111}], "errors": []}))
        self.m.get(
            f"{BASE_URL}/rest/submission/111",
            [
                {"json": ok({"submission_id": 111, "submission_finished": False})},
                {"json": ok({"submission_id": 111, "submission_finished": True, "submission_sample_id": 42})},
            ],
        )
        for path in broken:  # e.g. "sample/43/iocs" answers 500
            self.m.get(f"{BASE_URL}/rest/{path}", status_code=500, json={"result": "error", "error_msg": "boom"})

    samples: ClassVar[dict[int, dict]] = {
        42: {
            "sample_id": 42,
            "sample_verdict": "malicious",
            "sample_type": "URL",
            "sample_url": URL,
            "sample_sha256hash": SHA256,
            "sample_md5hash": MD5,
            "sample_webif_url": f"{BASE_URL}/samples/42",
            "sample_child_sample_ids": [43],
        },
        43: {
            "sample_id": 43,
            "sample_verdict": "malicious",
            "sample_type": "Windows Exe (x86-64)",
            "sample_filename": "payload.exe",
            "sample_sha256hash": "d" * 64,
            "sample_webif_url": f"{BASE_URL}/samples/43",
            "sample_child_sample_ids": [44],
        },
        44: {
            "sample_id": 44,
            "sample_verdict": "clean",
            "sample_type": "Text",
            "sample_filename": "readme.txt",
            "sample_sha256hash": "e" * 64,
            "sample_child_sample_ids": [],
        },
    }
    iocs: ClassVar[dict[int, dict]] = {
        42: {
            "domains": [
                {
                    "ioc_type": "domain",
                    "domain": "login-check.example",
                    "severity": "malicious",
                    "verdict": "malicious",
                },
                {"ioc_type": "domain", "domain": "cdn.example", "severity": "suspicious", "verdict": "suspicious"},
            ],
            "files": [
                {
                    "ioc_type": "file",
                    "filename": "update.exe",
                    "severity": "malicious",
                    "hashes": [{"sha256_hash": "f" * 64}],
                }
            ],
        },
        43: {
            "ips": [{"ioc_type": "ip", "ip_address": "203.0.113.9", "severity": "malicious", "verdict": "malicious"}]
        },
        44: {"domains": [{"ioc_type": "domain", "domain": "readme.example", "severity": "suspicious"}]},
    }

    def _sample(self, sample_id):
        m, rest = self.m, f"{BASE_URL}/rest"
        m.get(f"{rest}/sample/{sample_id}", json=ok(self.samples[sample_id]))
        m.get(
            f"{rest}/submission/sample/{sample_id}",
            json=ok([{"submission_id": sample_id * 10, "submission_created": "2026-10-01T00:00:00"}]),
        )
        m.get(
            f"{rest}/analysis/submission/{sample_id * 10}",
            json=ok(
                [
                    {
                        "analysis_id": sample_id * 100,
                        "analysis_analyzer_name": "vmray",
                        "analysis_vm_description": "Windows 10 64-bit",
                        "analysis_created": "2026-10-01T00:05:00",
                        "analysis_verdict": self.samples[sample_id]["sample_verdict"],
                    }
                ]
            ),
        )
        m.get(
            f"{rest}/sample/{sample_id}/vtis",
            json=ok({"threat_indicators": [{"score": 5, "category": "C", "operation": "op"}]}),
        )
        m.get(
            f"{rest}/sample/{sample_id}/mitre_attack",
            json=ok(
                {
                    "mitre_attack_techniques": [
                        {"technique_id": "T1204.001", "technique": "Malicious Link", "tactics": ["Execution"]}
                    ]
                }
            ),
        )
        m.get(f"{rest}/sample/{sample_id}/iocs", json=ok({"iocs": self.iocs[sample_id]}))
        m.get(
            f"{rest}/sample/{sample_id}/classifications",
            json=ok({"sample_classifications": [], "children_classifications": []}),
        )
        m.get(
            f"{rest}/sample/{sample_id}/threat_names",
            json=ok({"sample_threat_names": [{"threat_name": "Lumma"}], "children_threat_names": []}),
        )
        archive = f"{rest}/analysis/{sample_id * 100}/archive"
        if sample_id == 42:
            shots = ["screenshots/001.png", "screenshots/002.png"]
            m.get(
                f"{archive}/logs/summary.json", json={"screenshots": [{"screenshot_archive_path": p} for p in shots]}
            )
            for path in shots:
                m.get(f"{archive}/{path}", content=png())
        else:
            m.get(re.compile(rf"{re.escape(archive)}/.*"), status_code=404, json={"result": "error", "error_msg": "x"})


@pytest.fixture
def sekoia(tmp_path, monkeypatch, data_storage, requests_mock):
    """Runs an action the way Sekoia does and returns what Sekoia's callback received."""
    symphony = tmp_path / "symphony"
    symphony.mkdir()
    monkeypatch.setattr(FileSystemConfiguration, "VOLUME_PATH", str(symphony))
    (symphony / "url_callback").write_text(CALLBACK)
    (symphony / "token").write_text("token")
    callback = requests_mock.patch(CALLBACK, json={"module_configuration": {"value": {"api_key": "test-key"}}})

    def run(action_class, arguments, **configuration):
        (symphony / "arguments").write_text(json.dumps(arguments))
        (symphony / "module_configuration").write_text(
            json.dumps({"base_url": BASE_URL, "api_key": "test-key", **configuration})
        )
        callback.reset()
        action_class(module=VMRayModule()).execute()  # as main.py's module.run() does
        finished = [c.json() for c in callback.request_history if c.json().get("status") == "finished"]
        assert len(finished) == 1, "Sekoia must receive exactly one final status"
        return finished[0]

    run.data_path = Path(data_storage)
    return run


def assert_ok(payload):
    assert "error" not in payload, payload.get("error")
    return payload["results"]


def one_output(payload):
    """A playbook action must take exactly one branch."""
    outputs = [name for name, active in payload.get("outputs", {}).items() if active]
    assert len(outputs) == 1, payload.get("outputs")
    return outputs[0]


# -- the playbook's hash branch ---------------------------------------------------------------


def test_hash_branch_end_to_end(sekoia, requests_mock):
    FakeVMRay(requests_mock)

    # the alert's first event carries md5 and sha256 of the same file, in mixed case
    lookup = sekoia(GetSamplesByHash, {"hashes": [MD5.upper(), SHA256, f" {SHA256} "]})
    assert one_output(lookup) == "found"
    found = assert_ok(lookup)
    assert found["sample_ids"] == [42]  # the same sample once, whatever the hash
    assert found["not_found"] == [] and found["errors"] == {}

    built = assert_ok(sekoia(BuildReport, {"sample_ids": found["sample_ids"]}))
    assert built["errors"] == {}
    report = json.loads((sekoia.data_path / built["report_path"]).read_bytes())
    parent = report["samples"][0]
    assert parent["sample_child_samples"][0]["sample_child_samples"][0]["sample_id"] == 44  # default depth reaches 44
    assert parent["has_screenshots"] is True
    assert parent["sample_child_samples"][0]["has_screenshots"] is False  # child screenshots never fetched

    # the playbook editor sends `{}` for the inline report left blank — report_path must still be used
    rendered = assert_ok(sekoia(RenderReport, {"report_path": built["report_path"], "report": {}}))
    content = rendered["content"].replace("<wbr>", "")  # long values carry optional line breaks
    assert "No matches found" not in content
    assert "login-check.example" in content and "payload.exe" in content
    assert "<img" not in content  # screenshots only in their own comments
    assert len(rendered["screenshot_comments"]) == 1
    assert rendered["screenshot_comments"][0].count("<img") == 2

    extracted = assert_ok(sekoia(ExtractIocs, {"report_path": built["report_path"], "report": {}}))
    values = {(i["type"], i["value"]) for i in extracted["indicators"]}
    assert ("domain", "login-check.example") in values  # malicious IOC
    assert ("hash", "f" * 64) in values  # dropped file
    assert ("IP address", "203.0.113.9") in values  # malicious IOC of the child
    assert ("hash", "d" * 64) in values  # the malicious child itself
    assert ("domain", "cdn.example") not in values  # suspicious IOC: not by default
    assert ("hash", "e" * 64) not in values  # the clean grandchild
    assert ("hash", SHA256) not in values  # the alert's own observable
    assert [g["type"] for g in extracted["indicator_groups"]] == ["hash", "IP address", "domain"]


def test_unknown_hash_takes_the_not_found_branch(sekoia, requests_mock):
    FakeVMRay(requests_mock)

    payload = sekoia(GetSamplesByHash, {"hashes": [UNKNOWN, "not-a-hash"]})

    assert one_output(payload) == "not_found"
    results = assert_ok(payload)
    assert results["not_found"] == [UNKNOWN]
    assert "not-a-hash" in results["errors"]
    assert results["sample_ids"] == []


# -- the playbook's URL branch ----------------------------------------------------------------


def test_url_branch_end_to_end(sekoia, requests_mock):
    vmray = FakeVMRay(requests_mock)

    submitted = sekoia(SubmitUrlSample, {"sample_url": URL, "query_retry_wait": 0.01})
    assert one_output(submitted) == "completed"
    results = assert_ok(submitted)
    assert results["submission_ids"] == [111] and results["sample_ids"] == [42]
    form = requests_mock.request_history[[r.method for r in requests_mock.request_history].index("POST")]
    assert "max_recursive_samples=10" in form.text and "archive_password" not in form.text

    built = assert_ok(sekoia(BuildReport, {"submission_ids": results["submission_ids"], "include_screenshots": False}))
    report = json.loads((sekoia.data_path / built["report_path"]).read_bytes())
    assert [s["sample_id"] for s in report["samples"]] == [42]
    assert report["samples"][0]["has_screenshots"] is False

    rendered = assert_ok(sekoia(RenderReport, {"report_path": built["report_path"]}))
    assert rendered["screenshot_comments"] == []  # nothing for the playbook's Foreach — its guard skips it
    assert vmray.samples[42]["sample_url"] in rendered["content"].replace("<wbr>", "")


def test_detonation_that_never_finishes_takes_the_timed_out_branch(sekoia, requests_mock):
    FakeVMRay(requests_mock)
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json=ok({"submission_id": 111, "submission_finished": False}))

    payload = sekoia(SubmitUrlSample, {"sample_url": URL, "query_retry_wait": 0.01, "timeout": 0.05})

    assert one_output(payload) == "timed_out"
    assert assert_ok(payload)["pending_submission_ids"] == [111]


def test_rejected_submission_takes_the_submission_failed_branch(sekoia, requests_mock):
    FakeVMRay(requests_mock)
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=ok({"submissions": [], "errors": [{"error_msg": "quota exceeded", "submission_filename": "x.url"}]}),
    )

    payload = sekoia(SubmitUrlSample, {"sample_url": URL})

    assert one_output(payload) == "submission_failed"
    assert assert_ok(payload)["errors"][0]["error_msg"] == "quota exceeded"


# -- failures VMRay or Sekoia can throw at a playbook -------------------------------------------


def test_a_failing_section_still_gives_a_full_comment(sekoia, requests_mock):
    FakeVMRay(requests_mock, broken=["sample/43/iocs"])

    built = assert_ok(sekoia(BuildReport, {"sample_ids": [42]}))
    content = assert_ok(sekoia(RenderReport, {"report_path": built["report_path"]}))["content"].replace("<wbr>", "")

    assert "login-check.example" in content  # parent fully rendered
    extracted = assert_ok(sekoia(ExtractIocs, {"report_path": built["report_path"]}))
    assert ("IP address", "203.0.113.9") not in {(i["type"], i["value"]) for i in extracted["indicators"]}


def test_vmray_down_reports_an_error_not_a_crash(sekoia, requests_mock):
    requests_mock.get(
        re.compile(rf"{BASE_URL}/rest/.*"), status_code=503, json={"result": "error", "error_msg": "down"}
    )

    built = assert_ok(sekoia(BuildReport, {"sample_ids": [42]}))

    assert "42" in built["errors"]
    content = assert_ok(sekoia(RenderReport, {"report_path": built["report_path"]}))["content"]
    assert "42" in content


@pytest.mark.parametrize(
    "action_class,arguments",
    [
        (GetSamplesByHash, {}),
        (SubmitUrlSample, {}),
        (BuildReport, {}),
        (RenderReport, {}),
        (ExtractIocs, {"report": {}}),
        (RenderReport, {"report_path": "missing.json"}),
    ],
)
def test_bad_arguments_give_an_error_status(sekoia, requests_mock, action_class, arguments):
    payload = sekoia(action_class, arguments)

    assert payload.get("error")  # the playbook run shows the failure on this node
    assert "results" not in payload


def test_every_result_is_valid_json_for_sekoia(sekoia, requests_mock):
    """`validate_results` drops results that do not serialise — every action's results must."""
    FakeVMRay(requests_mock)
    for action_class, arguments in [
        (GetSamplesByHash, {"hashes": [SHA256]}),
        (SubmitUrlSample, {"sample_url": URL, "query_retry_wait": 0.01}),
    ]:
        payload = sekoia(action_class, arguments)
        assert json.loads(json.dumps(assert_ok(payload)))

    built = assert_ok(sekoia(BuildReport, {"sample_ids": [42]}))
    for action_class in (RenderReport, ExtractIocs):
        assert json.loads(json.dumps(assert_ok(sekoia(action_class, {"report_path": built["report_path"]}))))


def test_screenshot_comments_stay_under_the_size_limit(sekoia, requests_mock):
    FakeVMRay(requests_mock)
    built = assert_ok(sekoia(BuildReport, {"sample_ids": [42]}))

    comments = assert_ok(sekoia(RenderReport, {"report_path": built["report_path"], "max_comment_kb": 16}))[
        "screenshot_comments"
    ]

    assert sum(c.count("<img") for c in comments) == 2  # nothing lost
    for comment in comments:
        assert len(json.dumps(comment).encode()) <= 16 * 1024  # as Sekoia receives it
