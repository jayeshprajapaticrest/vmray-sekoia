"""Pure transform: VMRay AnalysisDetails -> one markdown comment.

No VMRay call, no Sekoia call. Keeps presentation out of the API actions so
it stays cheap, deterministic and trivially unit-testable against fixture
JSON (design doc, "Aggregation belongs in the module, not the playbook").
"""

import orjson
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.models import (
    AnalysisDetails,
    MitreAttackTechnique,
    RenderSummaryArguments,
    RenderSummaryResults,
    ThreatIndicator,
)

_MAX_THREAT_INDICATORS = 10
_MAX_MITRE_TECHNIQUES = 10


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
        "Render VTIs, classifications, threat names, MITRE ATT&CK and a report link "
        "from a VMRay analysis into one markdown comment"
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
