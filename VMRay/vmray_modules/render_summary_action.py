"""Pure transform: VMRay AnalysisDetails -> one markdown comment.

No VMRay call, no Sekoia call. Keeps presentation out of the API actions so
it stays cheap, deterministic and trivially unit-testable against fixture
JSON (design doc, "Aggregation belongs in the module, not the playbook").
"""

from typing import Any

import orjson
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.models import (
    AnalysisDetails,
    AnalysisRun,
    MitreAttackTechnique,
    RenderSummaryArguments,
    RenderSummaryResults,
    ThreatIndicator,
)

_MAX_THREAT_INDICATORS = 10
_MAX_MITRE_TECHNIQUES = 10
_MAX_IOCS_PER_TYPE = 10
_MAX_ANALYSES = 10

# (IOCSet field name, payload key on each item, display label) — payload key
# per the VMRay OpenAPI spec's IOC serializers (DomainIOCSerializer,
# IPIOCSerializer, etc.), same mapping the Cortex-Analyzers VMRay analyzer
# used in production.
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


def _render_threat_indicator(vti: ThreatIndicator) -> str:
    label = vti.operation or vti.category or "Unclassified rule"
    bits = [f"**{label}**"]
    if vti.category and vti.category != label:
        bits.append(f"({vti.category})")
    if vti.classification:
        bits.append(f"— {', '.join(vti.classification)}")
    return " ".join(bits)


def _render_mitre_technique(technique: MitreAttackTechnique) -> str:
    label = " ".join(part for part in (technique.id, technique.name) if part) or "Unknown technique"
    if technique.tactics:
        label += f" ({', '.join(technique.tactics)})"
    return label


def _ioc_values(items: list[dict[str, Any]], payload_key: str) -> list[str]:
    values = [str(item[payload_key]) for item in items[:_MAX_IOCS_PER_TYPE] if item.get(payload_key)]
    remaining = len(items) - _MAX_IOCS_PER_TYPE
    if remaining > 0:
        values.append(f"...and {remaining} more")
    return values


def _render_analysis_run(run: AnalysisRun) -> str:
    verdict = (run.analysis_verdict or "unknown").upper()
    bits = [f"**{verdict}**"]
    if run.analysis_vti_score is not None:
        bits.append(f"(VTI {run.analysis_vti_score}/100)")
    if run.analysis_configuration_name:
        bits.append(f"— {run.analysis_configuration_name}")
    if run.analysis_created:
        bits.append(f"— {run.analysis_created}")
    return " ".join(bits)


def render_summary(details: AnalysisDetails) -> str:
    lines: list[str] = []

    verdict = (details.sample_verdict or "unknown").upper()
    score = details.sample_vti_score if details.sample_vti_score is not None else details.sample_score
    header = f"## VMRay verdict: {verdict}"
    if score is not None:
        header += f" (VTI score {score}/100)"
    lines.append(header)

    if details.sample_verdict_reason_description:
        lines.append(details.sample_verdict_reason_description)

    if details.sample_threat_names:
        lines.append(f"**Threat:** {', '.join(details.sample_threat_names)}")
    if details.sample_classifications:
        lines.append(f"**Classification:** {', '.join(details.sample_classifications)}")

    identity_bits = [
        f"`{h}`" for h in (details.sample_sha256hash, details.sample_sha1hash, details.sample_md5hash) if h
    ]
    if identity_bits:
        lines.append(f"**Sample:** {' / '.join(identity_bits)}")
    if details.sample_filename:
        lines.append(f"**Filename:** {details.sample_filename}")

    iocs = details.iocs.model_dump()
    ioc_type_counts = [(label, len(iocs.get(field, []))) for field, _payload_key, label in _IOC_TYPES]
    if any(count for _label, count in ioc_type_counts):
        lines.append("")
        lines.append("**IOCs:** " + ", ".join(f"{count} {label}" for label, count in ioc_type_counts if count))
        for field, payload_key, label in _IOC_TYPES:
            items = iocs.get(field, [])
            if not items:
                continue
            lines.append(f"- _{label}_: " + ", ".join(f"`{v}`" for v in _ioc_values(items, payload_key)))

    if details.threat_indicators:
        lines.append("")
        lines.append("**Top VMRay Threat Identifiers:**")
        for vti in details.threat_indicators[:_MAX_THREAT_INDICATORS]:
            lines.append(f"- {_render_threat_indicator(vti)}")
        remaining = len(details.threat_indicators) - _MAX_THREAT_INDICATORS
        if remaining > 0:
            lines.append(f"- _...and {remaining} more_")

    if details.mitre_attack_techniques:
        techniques = [_render_mitre_technique(t) for t in details.mitre_attack_techniques[:_MAX_MITRE_TECHNIQUES]]
        lines.append("")
        lines.append(f"**MITRE ATT&CK:** {'; '.join(techniques)}")

    if details.sample_analyses:
        lines.append("")
        lines.append("**Analyses:**")
        for run in details.sample_analyses[:_MAX_ANALYSES]:
            lines.append(f"- {_render_analysis_run(run)}")
        remaining = len(details.sample_analyses) - _MAX_ANALYSES
        if remaining > 0:
            lines.append(f"- _...and {remaining} more_")

    if details.sample_child_sample_ids:
        note = f"{len(details.sample_child_sample_ids)} child sample(s) extracted"
        if details.sample_child_relations_truncated:
            note += " (list truncated by VMRay — see the full report)"
        lines.append("")
        lines.append(f"**Lineage:** {note}")

    if details.sample_webif_url:
        lines.append("")
        lines.append(f"[Full VMRay report]({details.sample_webif_url})")

    if details.errors:
        lines.append("")
        failed = ", ".join(sorted(details.errors))
        lines.append(f"⚠️ _Partial data — these sections failed to load: {failed}._")

    return "\n".join(lines)


class RenderSummary(VMRayAction):
    """Render an analysis summary as markdown, ready for post-alerts/{uuid}/comments."""

    name = "Render analysis summary"
    description = (
        "Render VTIs, itemized IOCs, classifications, threat names, per-analysis verdicts, "
        "MITRE ATT&CK and a report link from a VMRay analysis into one markdown comment"
    )
    results_model = RenderSummaryResults

    def run(self, arguments: RenderSummaryArguments) -> RenderSummaryResults:
        if arguments.analysis is not None:
            raw = arguments.analysis
        elif arguments.analysis_path:
            raw = orjson.loads(self.data_path.joinpath(arguments.analysis_path).read_bytes())
        else:
            raise MissingActionArgumentError("analysis")

        details = AnalysisDetails.model_validate(raw)
        return RenderSummaryResults(content=render_summary(details))
