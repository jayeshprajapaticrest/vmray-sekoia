"""RenderReport — pure transform: a BuildReport result -> one markdown alert comment.

Laid out like the Cortex-Analyzers TheHive template (VMRay_4_1/long.html), section
for section: Overview, Detections, IOC Summary, VMRay Threat Identifiers, MITRE
ATT&CK, Indicators of Compromise, Analyses, Child Samples. Screenshots are left
out — Sekoia cannot show them. A comment has no click-to-expand, so child sample
details are rendered in full below the child-sample table instead of on demand.

Field names follow the VMRay OpenAPI spec (v2026.2.1) and the template: VTIs
carry `score`/`category`/`operation`/`classifications`, MITRE techniques
`technique_id`/`technique`/`tactics`, analyses `analysis_analyzer_name`/
`analysis_vm_description`. No VMRay or Sekoia call.
"""

from typing import Any

import orjson
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.report_models import RenderReportArguments, RenderReportResults

_MAX_ROWS = 20  # per table (and per IOC type) — keeps a comment readable; the report link has the rest
_MAX_CHILD_DETAILS = 5  # children rendered in full; the child table still lists up to _MAX_ROWS

# (key under sample_iocs.iocs, value key, label) — the template's IOC order and fields
_IOC_TYPES = (
    ("domains", "domain", "Domains"),
    ("ips", "ip_address", "IPs"),
    ("urls", "url", "URLs"),
    ("files", "filename", "Files"),
    ("filenames", "filename", "Filenames"),
    ("processes", "process_names", "Processes"),
    ("mutexes", "mutex_name", "Mutexes"),
    ("registry", "reg_key_name", "Registry"),
    ("emails", "sender", "Emails"),
    ("email_addresses", "email_address", "Email Addresses"),
)


def _cell(value: Any) -> str:
    """Text safe inside a markdown table cell."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _code(value: Any) -> str:
    """Inline code, table-safe. Also keeps URLs and domains from rendering as clickable links."""
    return "`" + _cell(value).replace("`", "'") + "`"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(row) + " |" for row in rows[:_MAX_ROWS]]
    if len(rows) > _MAX_ROWS:
        lines.append("| " + " | ".join([f"_…and {len(rows) - _MAX_ROWS} more_"] + [""] * (len(headers) - 1)) + " |")
    return lines


def _section(title: str, body: list[str]) -> list[str]:
    return ["", f"#### {title}", "", *body] if body else []


def _verdict(verdict: str | None) -> str:
    return f"**{verdict.upper()}**" if verdict else "N/A"


def _sample_name(sample: dict[str, Any]) -> str:
    if sample.get("sample_type") == "URL":
        name = sample.get("sample_url") or sample.get("sample_display_url")
    else:
        name = sample.get("sample_filename")
    return name or sample.get("sample_sha256hash") or "Sample"


def _mitre_link(technique_id: str) -> str:
    return f"[{technique_id}](https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/)"


def _overview(sample: dict[str, Any]) -> list[str]:
    rows = [["**Verdict**", _verdict(sample.get("sample_verdict"))]]
    if sample.get("sample_vti_score") is not None:
        rows.append(["**VTI score**", f"{sample['sample_vti_score']}/100"])
    if sample.get("sample_verdict_reason_description"):
        rows.append(["**Reason**", _cell(sample["sample_verdict_reason_description"])])
    url = sample.get("sample_url") or sample.get("sample_display_url")
    if sample.get("sample_type") == "URL" and url:
        rows.append(["**URL**", _code(url)])
    elif sample.get("sample_filename"):
        rows.append(["**Filename**", _cell(sample["sample_filename"])])
    for key, label in (("sample_type", "Type"), ("sample_created", "Created")):
        if sample.get(key):
            rows.append([f"**{label}**", _cell(sample[key])])
    for key, label in (("sample_md5hash", "MD5"), ("sample_sha1hash", "SHA1"), ("sample_sha256hash", "SHA256")):
        if sample.get(key):
            rows.append([f"**{label}**", _code(sample[key])])
    if sample.get("sample_webif_url"):
        rows.append(["**Report**", f"[View in VMRay]({sample['sample_webif_url']})"])
    return _table(["Field", "Value"], rows)


def _detections(sample: dict[str, Any]) -> list[str]:
    lines = []
    for key, label in (("sample_threat_names", "Threat Names"), ("sample_classifications", "Classifications")):
        if sample.get(key):
            lines.append(f"**{label}:** " + " ".join(_code(v) for v in sample[key]) + "  ")
    return lines


def _ioc_summary(iocs: dict[str, Any]) -> list[str]:
    present = [(label, len(iocs.get(key) or [])) for key, _value_key, label in _IOC_TYPES if iocs.get(key)]
    if not present:
        return []
    return _table([label for label, _count in present], [[str(count) for _label, count in present]])


def _threat_indicators(vtis: list[dict[str, Any]]) -> list[str]:
    if not vtis:
        return []
    rows = [
        [
            f"**{vti['score']}/5**" if vti.get("score") is not None else "—",
            _cell(vti.get("category") or "—"),
            _cell(vti.get("operation") or "—"),
            _cell(", ".join(vti.get("classifications") or []) or "—"),
        ]
        for vti in sorted(vtis, key=lambda v: v.get("score") or 0, reverse=True)
    ]
    return _table(["Score", "Category", "Operation", "Classification"], rows)


def _mitre(techniques: list[dict[str, Any]]) -> list[str]:
    if not techniques:
        return []
    rows = [
        [
            _mitre_link(t["technique_id"]) if t.get("technique_id") else "—",
            _cell(t.get("technique") or "—"),
            _cell(", ".join(t.get("tactics") or []) or "—"),
        ]
        for t in techniques
    ]
    return _table(["ID", "Technique", "Tactics"], rows)


def _iocs(iocs: dict[str, Any]) -> list[str]:
    rows: list[list[str]] = []
    omitted = 0
    for key, value_key, _label in _IOC_TYPES:
        items = iocs.get(key) or []
        for item in items[:_MAX_ROWS]:
            value = item.get(value_key)
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            rows.append(
                [
                    _cell((item.get("ioc_type") or key).upper()),
                    _code(value) if value else "—",
                    _verdict(item.get("verdict")) if item.get("verdict") else "—",
                ]
            )
        omitted += max(0, len(items) - _MAX_ROWS)
    if not rows:
        return []
    lines = ["| Type | Value | Verdict |", "|---|---|---|", *("| " + " | ".join(row) + " |" for row in rows)]
    if omitted:
        lines.append(f"| _…and {omitted} more_ | | |")
    return lines


def _analyses(analyses: list[dict[str, Any]]) -> list[str]:
    if not analyses:
        return []
    rows = [
        [
            _cell(a.get("analysis_analyzer_name") or "—"),
            _cell(a.get("analysis_vm_description") or "—"),
            _code(a["analysis_created"]) if a.get("analysis_created") else "—",
            _verdict(a.get("analysis_verdict")),
        ]
        for a in sorted(analyses, key=lambda a: a.get("analysis_created") or "", reverse=True)
    ]
    return _table(["Analysis", "Target Environment", "Created", "Verdict"], rows)


def _child_rows(children: list[dict[str, Any]], depth: int = 0) -> list[list[str]]:
    rows = []
    for child in children:
        grandchildren = child.get("sample_child_samples") or []
        count = len(grandchildren) or len(child.get("sample_child_sample_ids") or [])
        rows.append(
            [
                _verdict(child.get("sample_verdict")),
                ("↳ " * depth) + _code(_sample_name(child)),
                _cell(child.get("sample_type") or "—"),
                str(count) if count else "—",
                f"[View]({child['sample_webif_url']})" if child.get("sample_webif_url") else "—",
            ]
        )
        rows += _child_rows(grandchildren, depth + 1)
    return rows


def _sample_detail(sample: dict[str, Any]) -> list[str]:
    iocs = (sample.get("sample_iocs") or {}).get("iocs") or {}
    lines: list[str] = []
    lines += _section("Overview", _overview(sample))
    lines += _section("Detections", _detections(sample))
    lines += _section("IOC Summary", _ioc_summary(iocs))
    vtis = (sample.get("sample_threat_indicators") or {}).get("threat_indicators") or []
    lines += _section("VMRay Threat Identifiers", _threat_indicators(vtis))
    lines += _section(
        "MITRE ATT&CK", _mitre((sample.get("sample_mitre_attack") or {}).get("mitre_attack_techniques") or [])
    )
    lines += _section("Indicators of Compromise", _iocs(iocs))
    lines += _section("Analyses", _analyses(sample.get("sample_analyses") or []))
    if sample.get("errors"):
        lines += ["", f"⚠️ _Partial data — these sections failed to load: {', '.join(sorted(sample['errors']))}._"]
    return lines


def _render_sample(sample: dict[str, Any]) -> list[str]:
    lines = _sample_detail(sample)
    children = sample.get("sample_child_samples") or []
    if children:
        lines += _section(
            f"Child Samples ({len(children)})",
            _table(["Verdict", "Sample", "Type", "Children", "Report"], _child_rows(children)),
        )
        for child in children[:_MAX_CHILD_DETAILS]:
            lines += ["", f"### Child sample: {_code(_sample_name(child))}"]
            lines += _render_sample(child)
        if len(children) > _MAX_CHILD_DETAILS:
            lines += [
                "",
                f"_Details of {len(children) - _MAX_CHILD_DETAILS} more child sample(s) are in the VMRay report._",
            ]
    elif sample.get("sample_child_sample_ids"):
        count = len(sample["sample_child_sample_ids"])
        lines += _section(f"Child Samples ({count})", ["_Not expanded — see the VMRay report._"])
    return lines


def render_report(report: dict[str, Any]) -> str:
    samples = report.get("samples") or []
    lines = ["## VMRay Report"]
    if not samples:
        lines += ["", "**No matches found for this observable.**"]
    for index, sample in enumerate(samples, start=1):
        if len(samples) > 1:
            lines += ["", "---", "", f"### Sample ({index}/{len(samples)})"]
        lines += _render_sample(sample)
    if report.get("errors"):
        failed = ", ".join(sorted(report["errors"]))
        lines += ["", f"⚠️ _These samples could not be fetched from VMRay: {failed}._"]
    return "\n".join(lines)


class RenderReport(VMRayAction):
    name = "Render report"
    description = (
        "Render a Build report result into one markdown alert comment, laid out like the VMRay TheHive "
        "report: overview, detections, IOCs, threat identifiers, MITRE ATT&CK, analyses and child samples."
    )
    results_model = RenderReportResults

    def run(self, arguments: RenderReportArguments) -> RenderReportResults:
        if arguments.report is not None:
            report = arguments.report
        elif arguments.report_path:
            report = orjson.loads(self.data_path.joinpath(arguments.report_path).read_bytes())
        else:
            raise MissingActionArgumentError("report")
        return RenderReportResults(content=render_report(report))
