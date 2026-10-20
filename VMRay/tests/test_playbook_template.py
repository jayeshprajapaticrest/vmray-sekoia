"""Runs the "Report on demand" playbook template end to end, the way Sekoia's playbook engine walks it.

The template JSON is read as is: every argument and condition is rendered with Jinja (`node.<id>[...]`), conditions
pick their branch, Foreach nodes loop over their items. The five VMRay actions run for real through
`Action.execute()` against the fake VMRay of the integration tests. The nodes of other modules (Sekoia.io Get
Alert, Get Events, Comment Alert, Add IOC to IOC Collection, and the JSONPath extraction) are emulated: they
check the arguments they receive and record what the playbook would have done.

What this cannot reproduce: the engine's own scheduling (parallel branches, overlapping Foreach iterations),
its argument size limit, and how comments render in the UI.
"""

import json
import re
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jinja2
import pytest

from tests.test_integration import BASE_URL, MD5, SHA256, UNKNOWN, URL, FakeVMRay, ok, sekoia  # noqa: F401
from vmray_modules import submit_url_sample_action
from vmray_modules.build_report_action import BuildReport
from vmray_modules.extract_iocs_action import ExtractIocs
from vmray_modules.get_samples_by_hash_action import GetSamplesByHash
from vmray_modules.render_report_action import RenderReport
from vmray_modules.submit_url_sample_action import SubmitUrlSample

# A copy of playbooks/templates/vmray_report_on_demand.json, so the module's tests run on their own
TEMPLATE = Path(__file__).parent / "data" / "vmray_report_on_demand.json"
PUBLISHED_TEMPLATE = Path(__file__).resolve().parents[2] / "playbooks" / "templates" / "vmray_report_on_demand.json"

ALERT = {
    "uuid": "5b7f9a1e-0000-4000-8000-000000000001",
    "short_id": "ALxyz123",
    "first_seen_at": "2026-10-13T08:00:00Z",
    "last_seen_at": "2026-10-13T08:05:00Z",
}

VMRAY_ACTIONS = {
    cls_uuid: cls
    for cls_uuid, cls in [
        ("ef382164-6133-5fa2-b380-622c026789d1", GetSamplesByHash),
        ("10c9d58f-4e09-53c6-ba6a-91a765dc5634", SubmitUrlSample),
        ("8fef9429-5a84-5f96-b5c6-c152e2d8ad30", BuildReport),
        ("f6426a65-3f5b-5157-842e-d2ec2db51000", RenderReport),
        ("b260276d-2d98-5e4a-8be8-a960dc3a5e0c", ExtractIocs),
    ]
}
GET_ALERT = "8d189665-5401-4098-8d60-944de9a6199a"
GET_EVENTS = "af0b4355-a428-43d6-991c-d5ff878e17d5"
JSONPATH_EXTRACT = "ecedfa52-7033-4ea8-9c3b-93ad34295f87"
COMMENT_ALERT = "0d323de3-a864-4afe-a0c3-e7ff45883d7a"
ADD_IOCS = "0acabc04-43b4-4564-b9b2-08b80e0e1ecf"
SEKOIA_IOC_TYPES = {"IP address", "domain", "url", "email", "hash"}

HASH_FIELDS = [
    "file.hash.sha256",
    "file.hash.sha1",
    "file.hash.md5",
    "process.hash.sha256",
    "process.hash.sha1",
    "process.hash.md5",
]


class NodeFailedError(Exception):
    pass


@dataclass
class Run:
    path: list[str] = field(default_factory=list)  # "<id> <name> -> <branch>"
    comments: list[str] = field(default_factory=list)
    ioc_pushes: list[tuple[str, list[str]]] = field(default_factory=list)
    failures: dict[str, str] = field(default_factory=dict)
    results: dict[int, Any] = field(default_factory=dict)

    def ran(self, node_id: str) -> bool:
        return int(node_id) in self.results

    def trace(self) -> str:
        lines = [*self.path]
        lines += [f"  comment #{i + 1}: {_summary(c)}" for i, c in enumerate(self.comments)]
        lines += [f"  IOC push: {t} x{len(v)}" for t, v in self.ioc_pushes]
        lines += [f"  FAILED {k}: {v}" for k, v in self.failures.items()]
        return "\n".join(lines)


def _summary(content: str) -> str:
    if "<img" in content:
        return f"screenshots ({content.count('<img')} image(s), {len(content) // 1024} KB)"
    return content.replace("\n", " ")[:90]


# -- the playbook engine ----------------------------------------------------------------------

_ENV = jinja2.Environment(undefined=jinja2.StrictUndefined)
_WHOLE_EXPRESSION = re.compile(r"^\{\{(.*)\}\}$", re.S)


def render(value: Any, nodes: dict[int, Any]) -> Any:
    """A string that is one `{{ expression }}` gives the expression's own value (a list stays a list), any other
    string is rendered as text — as Sekoia does. A reference to a node that did not run fails, as Sekoia's
    "Invalid Node Run Reference"."""
    if isinstance(value, dict):
        return {k: render(v, nodes) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, nodes) for v in value]
    if not isinstance(value, str) or "{" not in value:
        return value
    try:
        whole = _WHOLE_EXPRESSION.match(value)
        if whole and "{{" not in whole.group(1):
            return _ENV.compile_expression(whole.group(1), undefined_to_none=False)(node=nodes)
        return _ENV.from_string(value).render(node=nodes)
    except jinja2.UndefinedError as exc:
        raise NodeFailedError(f"Invalid Node Run Reference: {exc}") from exc


def jsonpath_extract(arguments: dict[str, Any]) -> dict[str, Any]:
    """The two JSONPath queries of the template, evaluated on Sekoia's flat events."""
    events, query = arguments["file"], arguments["jsonpath"]
    assert isinstance(events, list), f"file must be the event list, got {type(events).__name__}"
    assert arguments["return_list"] is True and arguments["to_file"] is False
    if query.startswith("$..["):
        fields = re.findall(r"'([^']+)'", query)
        assert fields == HASH_FIELDS, fields
        output = [e[f] for e in events for f in fields if f in e]
    else:
        assert query == "$[?(@['url.original'] =~ '(?i)^https?://')]['url.original']", query
        output = [e["url.original"] for e in events if re.match(r"(?i)^https?://", str(e.get("url.original", "")))]
    return {"output": output}


class Playbook:
    def __init__(self, sekoia_run, events: list[dict[str, Any]], overrides: dict[str, dict[str, Any]]):
        self.spec = json.loads(TEMPLATE.read_text())["nodes"]
        self.sekoia_run = sekoia_run
        self.events = events
        self.overrides = overrides
        self.run = Run()

    def start(self) -> Run:
        trigger = self.spec["0"]
        assert trigger["trigger_uuid"] == "fc26eb9f-b272-4c15-b3bf-ace397c0dc57"  # Manual trigger
        self.run.results[0] = {"alert_uuid": ALERT["uuid"]}
        self.run.path.append(f"0 {trigger['name']}")
        self._follow(trigger["outputs"]["default"])
        return self.run

    def _follow(self, node_ids: list[str]) -> None:
        for node_id in node_ids:
            self._execute(node_id)

    def _execute(self, node_id: str) -> None:
        node = self.spec[node_id]
        label = f"{node_id} {node['name']}"
        try:
            if node["type"] == "action":
                branch = self._action(node_id, node)
            elif node.get("subtype") == "condition":
                branch = self._condition(node)
            elif node.get("subtype") == "foreach":
                branch = self._foreach(node_id, node, label)
            else:
                raise AssertionError(f"unknown node {node}")
        except NodeFailedError as exc:
            self.run.path.append(f"{label} -> FAILED")
            self.run.failures[label] = str(exc)
            return  # Sekoia stops this branch; the others go on
        self.run.path.append(f"{label} -> {branch}")
        self._follow(node["outputs"].get(branch, []))

    def _condition(self, node: dict[str, Any]) -> str:
        ops = {"==": lambda a, b: a == b, "!=": lambda a, b: a != b, ">": lambda a, b: a > b, "<": lambda a, b: a < b}
        for case in node["cases"]:
            if ops[case["comparison"]](
                render(case["left"], self.run.results), render(case["right"], self.run.results)
            ):
                return case["name"]
        return "else"

    def _foreach(self, node_id: str, node: dict[str, Any], label: str) -> str:
        items = render(node["items"], self.run.results)
        if not isinstance(items, list) or not items:
            raise NodeFailedError(f"Foreach input is not a list: {items!r}")
        for index, item in enumerate(items):
            self.run.results[int(node_id)] = {"default": {"value": item}}
            self.run.path.append(f"{label} [iteration {index + 1}/{len(items)}]")
            self._follow(node["loop"])
        return "default"

    def _action(self, node_id: str, node: dict[str, Any]) -> str:
        arguments = render(node["arguments"], self.run.results)
        arguments.update(self.overrides.get(node_id, {}))
        action = node["action_uuid"]

        if action in VMRAY_ACTIONS:
            payload = self.sekoia_run(VMRAY_ACTIONS[action], arguments)
            if payload.get("error"):
                raise NodeFailedError(payload["error"])
            results = payload["results"]
            active = [name for name, on in (payload.get("outputs") or {}).items() if on]
            assert len(active) <= 1, active
            branch = active[0] if active else "default"
            assert branch in node["outputs"], f"{node['name']} took {branch}, which the template does not wire"
        elif action == GET_ALERT:
            assert arguments == {"stix": False, "uuid": ALERT["uuid"]}, arguments
            results, branch = dict(ALERT), "default"
        elif action == GET_EVENTS:
            assert arguments["query"] == f'alert_short_ids: "{ALERT["short_id"]}"', arguments["query"]
            assert (arguments["earliest_time"], arguments["latest_time"]) == (
                ALERT["first_seen_at"],
                ALERT["last_seen_at"],
            )
            results, branch = {"events": self.events[: arguments["limit"]]}, "default"
        elif action == JSONPATH_EXTRACT:
            results, branch = jsonpath_extract(arguments), "default"
        elif action == COMMENT_ALERT:
            content = arguments["content"]
            assert arguments["uuid"] == ALERT["uuid"] and arguments["author"] == "VMRay"
            assert isinstance(content, str) and content.strip(), f"empty comment from {node['name']}"
            assert "{{" not in content and "{%" not in content, content
            self.run.comments.append(content)
            results, branch = {}, "default"
        elif action == ADD_IOCS:
            assert arguments["indicator_type"] in SEKOIA_IOC_TYPES, arguments["indicator_type"]
            indicators = arguments["indicators"]
            assert isinstance(indicators, list) and indicators and all(isinstance(i, str) for i in indicators)
            assert arguments["ioc_collection_id"].startswith("ioc-collection--")
            self.run.ioc_pushes.append((arguments["indicator_type"], indicators))
            results, branch = {}, "default"
        else:
            raise AssertionError(f"no emulation for action {action} ({node['name']})")

        self.run.results[int(node_id)] = results
        return branch


@pytest.fixture
def playbook(sekoia, monkeypatch):  # noqa: F811
    """Runs the template on an alert whose events are given. The submit action's polling runs on a virtual clock,
    so the template's own wait (query_retry_wait, 30 min timeout) is kept without real waiting."""
    clock = {"now": 0.0}

    def sleep(seconds):
        clock["now"] += seconds

    monkeypatch.setattr(
        submit_url_sample_action, "time", types.SimpleNamespace(monotonic=lambda: clock["now"], sleep=sleep)
    )

    def run(events, **overrides):
        result = Playbook(sekoia, events, {k.removeprefix("node_"): v for k, v in overrides.items()}).start()
        print(f"\n{result.trace()}")
        return result

    return run


def report_comments(run: Run) -> list[str]:
    return [c for c in run.comments if "<img" not in c and not c.startswith(("**VMRay", "No VMRay"))]


def screenshot_comments(run: Run) -> list[str]:
    return [c for c in run.comments if "<img" in c]


def pushed(run: Run) -> set[tuple[str, str]]:
    return {(t, v) for t, values in run.ioc_pushes for v in values}


# -- scenarios ----------------------------------------------------------------------------------


@pytest.mark.skipif(not PUBLISHED_TEMPLATE.exists(), reason="the published playbook templates are not alongside")
def test_template_copy_matches_the_published_template():
    """Where the published template sits alongside the module, the tested copy must be the same playbook."""
    assert json.loads(TEMPLATE.read_text()) == json.loads(PUBLISHED_TEMPLATE.read_text())


def test_known_hash(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"file.hash.sha256": SHA256, "file.hash.md5": MD5}])

    assert not run.failures
    assert run.ran("9") and not run.ran("17") and not run.ran("24") and not run.ran("25")
    assert run.results[9]["sample_ids"] == [42]  # md5 and sha256 of one file: one sample
    assert len(report_comments(run)) == 1
    assert "payload.exe" in report_comments(run)[0].replace("<wbr>", "")  # child sample in the report
    assert "Not in this report" not in report_comments(run)[0]  # every hash found: no note
    assert sum(c.count("<img") for c in screenshot_comments(run)) == 2
    assert ("IP address", "203.0.113.9") in pushed(run)  # child's IOC
    assert ("domain", "login-check.example") in pushed(run)
    assert ("domain", "cdn.example") in pushed(run)  # every severity by default
    assert len(run.ioc_pushes) == len({t for t, _ in run.ioc_pushes})  # one push per indicator type


def test_unknown_hash(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"process.hash.sha256": UNKNOWN}])

    assert not run.failures
    assert run.ran("24") and not run.ran("10")
    assert run.comments == [run.comments[0]] and UNKNOWN in run.comments[0]
    assert "no known sample" in run.comments[0] and "Lookup failed" not in run.comments[0]
    assert run.ioc_pushes == []


def test_malformed_hash_only(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"file.hash.sha256": "not-a-hash"}])

    assert not run.failures
    assert run.ran("24")
    assert "Lookup failed for" in run.comments[0] and "not-a-hash" in run.comments[0]


def test_known_and_unknown_hash(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"file.hash.sha256": SHA256, "process.hash.sha256": UNKNOWN}])

    assert not run.failures
    assert run.ran("10") and not run.ran("24")  # found wins: the report is posted
    [report] = report_comments(run)
    note = report[report.index("<b>Not in this report</b>") :]  # the unknown hash is listed after the report
    assert f"<li><code>{UNKNOWN}</code></li>" in note and "Lookup failed" not in note


def test_known_and_malformed_hash(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"file.hash.sha256": SHA256, "file.hash.md5": "not-a-hash"}])

    assert not run.failures
    [report] = report_comments(run)
    note = report[report.index("<b>Not in this report</b>") :]
    assert "Lookup failed for:" in note and "<li><code>not-a-hash</code> — <code>" in note
    assert "never analysed" not in note


def test_clean_sample_no_iocs_no_screenshots(playbook, requests_mock):
    vmray = FakeVMRay(requests_mock)
    requests_mock.get(f"{BASE_URL}/rest/sample/sha256/{'e' * 64}", json=ok([vmray.samples[44]]))

    # only malicious IOCs: the clean sample's single suspicious IOC is filtered out, so nothing is pushed
    run = playbook([{"file.hash.sha256": "e" * 64}], node_13={"ioc_severity_filter": ["malicious"]})

    assert not run.failures  # both Foreach guards hold
    assert run.ran("13") and not run.ran("14") and not run.ran("27")
    assert len(run.comments) == 1 and run.ioc_pushes == []


def test_url_detonated(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"url.original": URL}])

    assert not run.failures
    assert run.ran("17") and run.ran("18") and not run.ran("9") and not run.ran("26")
    assert run.results[17]["submission_ids"] == [111]
    assert len(report_comments(run)) == 1
    assert sum(c.count("<img") for c in screenshot_comments(run)) == 2
    assert ("domain", "login-check.example") in pushed(run)


def test_url_upper_case_scheme(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"url.original": "HTTPS://login-check.example/verify"}])

    assert run.ran("17") and not run.failures


def test_url_detonation_times_out(playbook, requests_mock):
    FakeVMRay(requests_mock)
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json=ok({"submission_id": 111, "submission_finished": False}))

    run = playbook([{"url.original": URL}])

    assert not run.failures
    assert run.ran("26") and not run.ran("18")
    assert "detonation incomplete" in run.comments[0] and "submission(s) 111 may still finish" in run.comments[0]


def test_url_submission_rejected(playbook, requests_mock):
    FakeVMRay(requests_mock)
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=ok({"submissions": [], "errors": [{"error_msg": "quota exceeded"}]}),
    )

    run = playbook([{"url.original": URL}])

    assert not run.failures
    assert run.ran("26") and "quota exceeded" in run.comments[0]


def test_url_submission_refused_with_http_error(playbook, requests_mock):
    FakeVMRay(requests_mock)
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit", status_code=400, json={"result": "error", "error_msg": "invalid url"}
    )

    run = playbook([{"url.original": URL}])

    assert not run.failures
    assert run.ran("26") and "invalid url" in run.comments[0]


def test_submission_finished_with_error(playbook, requests_mock):
    FakeVMRay(requests_mock)
    requests_mock.get(
        f"{BASE_URL}/rest/submission/111",
        json=ok({"submission_id": 111, "submission_finished": True, "submission_has_errors": True}),
    )

    run = playbook([{"url.original": URL}])

    assert not run.failures
    assert run.ran("26") and "Failed submission(s): 111" in run.comments[0]


def test_hash_and_url(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"file.hash.sha256": SHA256, "url.original": URL}])

    assert not run.failures
    assert run.ran("10") and run.ran("18") and not run.ran("25")
    assert len(report_comments(run)) == 2 and len(screenshot_comments(run)) == 2


@pytest.mark.parametrize(
    "events",
    [
        pytest.param([], id="no-events"),
        pytest.param([{"source.ip": "10.0.0.1"}], id="no-hash-no-url"),
        pytest.param([{"url.original": "ftp://files.example/x"}], id="non-http-url"),
        pytest.param([{"url.original": "hxxps://defanged.example"}], id="defanged-url"),
        pytest.param(
            [{"source.ip": "10.0.0.1"}, {"url.original": URL, "file.hash.sha256": SHA256}], id="second-event"
        ),
    ],
)
def test_nothing_to_enrich(playbook, requests_mock, events):
    FakeVMRay(requests_mock)

    run = playbook(events)

    assert not run.failures
    assert run.ran("25") and not run.ran("9") and not run.ran("17")
    assert [c for c in run.comments] == [run.comments[0]] and "No VMRay enrichment" in run.comments[0]
    assert not any(r.method == "POST" for r in requests_mock.request_history)  # no quota spent


def test_url_only_takes_first_url_of_first_event(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"url.original": URL}, {"url.original": "https://other.example/"}])

    assert run.results[6]["output"] == [URL]
    assert sum(r.method == "POST" for r in requests_mock.request_history) == 1


def test_vmray_down_during_report(playbook, requests_mock):
    FakeVMRay(requests_mock, broken=["sample/42"])

    run = playbook([{"file.hash.sha256": SHA256}])

    assert not run.failures  # lookup worked; the report carries the error instead of failing
    assert run.results[10]["errors"] and len(run.comments) == 1
    assert "42" in run.comments[0]
    assert run.ioc_pushes == []


def test_one_section_broken(playbook, requests_mock):
    FakeVMRay(requests_mock, broken=["sample/43/iocs"])

    run = playbook([{"file.hash.sha256": SHA256}])

    assert not run.failures
    assert ("IP address", "203.0.113.9") not in pushed(run)  # child's IOCs lost, the rest pushed
    assert ("domain", "login-check.example") in pushed(run)


def test_vmray_unreachable_fails_the_lookup_node(playbook, requests_mock):
    requests_mock.get(
        re.compile(rf"{BASE_URL}/rest/.*"), status_code=503, json={"result": "error", "error_msg": "down"}
    )

    run = playbook([{"file.hash.sha256": SHA256}])

    assert list(run.failures) == ["9 VMRay: Get Samples By Hash"]
    assert run.comments == []


def test_small_comment_limit_splits_screenshots(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"file.hash.sha256": SHA256}], node_11={"max_comment_kb": 16})

    assert not run.failures
    assert len(screenshot_comments(run)) == len(run.results[11]["screenshot_comments"])
    assert sum(c.count("<img") for c in screenshot_comments(run)) == 2


def test_screenshots_disabled(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"file.hash.sha256": SHA256}], node_10={"include_screenshots": False})

    assert not run.failures and not run.ran("27") and screenshot_comments(run) == []


def test_malicious_iocs_only_when_filtered(playbook, requests_mock):
    FakeVMRay(requests_mock)

    run = playbook([{"file.hash.sha256": SHA256}], node_13={"ioc_severity_filter": ["malicious"]})

    assert ("domain", "login-check.example") in pushed(run)
    assert ("domain", "cdn.example") not in pushed(run)  # suspicious
    assert ("hash", "e" * 64) not in pushed(run)  # clean grandchild
