"""RenderReport — pure transform: a BuildReport result -> one markdown comment.

Reads the Cortex-Analyzers VMRay analyzer's report shape directly, with field
names checked against the VMRay OpenAPI spec (v2026.2.1): VTIs carry
`classifications` and a 1-5 `score`; MITRE techniques carry `technique_id` and
`technique`. Covers every top-level sample plus a line per child sample. No
VMRay or Sekoia call.
"""

from typing import Any

import orjson
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.report_models import RenderReportArguments, RenderReportResults

_MAX_ITEMS = 10

# (key under sample_iocs.iocs, value key on each item, label) — per the spec's IOC serializers
_IOC_TYPES = (
    ("domains", "domain", "Domains"),
    ("ips", "ip_address", "IPs"),
    ("urls", "url", "URLs"),
    ("files", "filename", "Dropped files"),
    ("filenames", "filename", "Filenames"),
    ("mutexes", "mutex_name", "Mutexes"),
    ("registry", "reg_key_name", "Registry keys"),
    ("emails", "sender", "Emails"),
    ("email_addresses", "email_address", "Email addresses"),
)


def _capped(lines: list[str], total: int) -> list[str]:
    if total > _MAX_ITEMS:
        lines.append(f"- _...and {total - _MAX_ITEMS} more_")
    return lines


def _verdict(sample: dict[str, Any]) -> str:
    verdict = (sample.get("sample_verdict") or "unknown").upper()
    score = sample.get("sample_vti_score")
    return f"{verdict} (VTI score {score}/100)" if score is not None else verdict


def _subject(sample: dict[str, Any]) -> str | None:
    url = sample.get("sample_url") or sample.get("sample_display_url")
    return (
        f"**URL:** `{url}`"
        if url
        else (f"**Filename:** {sample['sample_filename']}" if sample.get("sample_filename") else None)
    )


def _render_iocs(iocs: dict[str, Any]) -> list[str]:
    counts = [(label, len(iocs.get(key) or [])) for key, _value_key, label in _IOC_TYPES]
    if not any(count for _label, count in counts):
        return []
    lines = ["", "**IOCs:** " + ", ".join(f"{count} {label}" for label, count in counts if count)]
    for key, value_key, label in _IOC_TYPES:
        items = iocs.get(key) or []
        if not items:
            continue
        values = [f"`{item[value_key]}`" for item in items[:_MAX_ITEMS] if item.get(value_key)]
        if len(items) > _MAX_ITEMS:
            values.append(f"...and {len(items) - _MAX_ITEMS} more")
        lines.append(f"- _{label}_: " + ", ".join(values))
    return lines


def _render_vtis(vtis: list[dict[str, Any]]) -> list[str]:
    if not vtis:
        return []
    lines = ["", "**Top VMRay Threat Identifiers:**"]
    for vti in sorted(vtis, key=lambda v: v.get("score") or 0, reverse=True)[:_MAX_ITEMS]:
        label = vti.get("operation") or vti.get("category") or "Unclassified rule"
        bits = [f"**{label}**"]
        if vti.get("category") and vti["category"] != label:
            bits.append(f"({vti['category']})")
        if vti.get("classifications"):
            bits.append(f"— {', '.join(vti['classifications'])}")
        if vti.get("score") is not None:
            bits.append(f"[score {vti['score']}/5]")
        lines.append("- " + " ".join(bits))
    return _capped(lines, len(vtis))


def _render_mitre(techniques: list[dict[str, Any]]) -> list[str]:
    if not techniques:
        return []
    labels = []
    for technique in techniques[:_MAX_ITEMS]:
        label = " ".join(p for p in (technique.get("technique_id"), technique.get("technique")) if p) or "Unknown"
        if technique.get("tactics"):
            label += f" ({', '.join(technique['tactics'])})"
        labels.append(label)
    suffix = f"; ...and {len(techniques) - _MAX_ITEMS} more" if len(techniques) > _MAX_ITEMS else ""
    return ["", f"**MITRE ATT&CK:** {'; '.join(labels)}{suffix}"]


def _render_analyses(analyses: list[dict[str, Any]]) -> list[str]:
    if not analyses:
        return []
    lines = ["", "**Analyses:**"]
    for run in analyses[:_MAX_ITEMS]:
        bits = [f"**{(run.get('analysis_verdict') or 'unknown').upper()}**"]
        if run.get("analysis_vti_score") is not None:
            bits.append(f"(VTI {run['analysis_vti_score']}/100)")
        for key in ("analysis_configuration_name", "analysis_created"):
            if run.get(key):
                bits.append(f"— {run[key]}")
        lines.append("- " + " ".join(bits))
    return _capped(lines, len(analyses))


def _render_child(child: dict[str, Any]) -> str:
    bits = [f"**{_verdict(child)}**"]
    if child.get("sample_type"):
        bits.append(child["sample_type"])
    subject = child.get("sample_url") or child.get("sample_display_url") or child.get("sample_filename")
    if subject:
        bits.append(f"`{subject}`")
    if child.get("sample_threat_names"):
        bits.append(", ".join(child["sample_threat_names"]))
    ioc_total = sum(
        len(v) for v in ((child.get("sample_iocs") or {}).get("iocs") or {}).values() if isinstance(v, list)
    )
    if ioc_total:
        bits.append(f"{ioc_total} IOCs")
    if child.get("sample_webif_url"):
        bits.append(f"[report]({child['sample_webif_url']})")
    return "- " + " · ".join(bits)


def render_sample(sample: dict[str, Any], heading: str) -> list[str]:
    lines = [f"## {heading}{_verdict(sample)}"]
    if sample.get("sample_verdict_reason_description"):
        lines.append(sample["sample_verdict_reason_description"])
    if sample.get("sample_threat_names"):
        lines.append(f"**Threat:** {', '.join(sample['sample_threat_names'])}")
    if sample.get("sample_classifications"):
        lines.append(f"**Classification:** {', '.join(sample['sample_classifications'])}")
    subject = _subject(sample)
    if subject:
        lines.append(subject)
    hashes = [f"`{sample[k]}`" for k in ("sample_sha256hash", "sample_sha1hash", "sample_md5hash") if sample.get(k)]
    if hashes:
        lines.append(f"**Sample:** {' / '.join(hashes)}")

    lines += _render_iocs((sample.get("sample_iocs") or {}).get("iocs") or {})
    lines += _render_vtis((sample.get("sample_threat_indicators") or {}).get("threat_indicators") or [])
    lines += _render_mitre((sample.get("sample_mitre_attack") or {}).get("mitre_attack_techniques") or [])
    lines += _render_analyses(sample.get("sample_analyses") or [])

    children = sample.get("sample_child_samples") or []
    if children:
        lines += ["", f"**Child samples ({len(children)}):**"]
        lines += _capped([_render_child(c) for c in children[:_MAX_ITEMS]], len(children))
    elif sample.get("sample_child_sample_ids"):
        lines += [
            "",
            f"**Child samples:** {len(sample['sample_child_sample_ids'])} (not expanded — see the full report)",
        ]

    if sample.get("sample_webif_url"):
        lines += ["", f"[Full VMRay report]({sample['sample_webif_url']})"]
    if sample.get("errors"):
        lines += ["", f"⚠️ _Partial data — these sections failed to load: {', '.join(sorted(sample['errors']))}._"]
    return lines


def render_report(report: dict[str, Any]) -> str:
    samples = report.get("samples") or []
    lines: list[str] = []
    for index, sample in enumerate(samples, start=1):
        if index > 1:
            lines += ["", "---", ""]
        heading = f"Sample {index}/{len(samples)} — VMRay verdict: " if len(samples) > 1 else "VMRay verdict: "
        lines += render_sample(sample, heading)
    if report.get("errors"):
        failed = ", ".join(sorted(report["errors"]))
        lines += ["", f"⚠️ _These samples could not be fetched from VMRay: {failed}._"]
    return "\n".join(lines) if lines else "VMRay returned no samples for this report."


class RenderReport(VMRayAction):
    name = "Render report"
    description = (
        "Render a Build report result — every sample with its VTIs, IOCs, MITRE ATT&CK, analyses and child "
        "samples — into one markdown comment."
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
