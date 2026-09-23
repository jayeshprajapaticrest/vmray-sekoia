#!/usr/bin/env python3
"""
Phase 0 spike 0.3 — enumerate the VMRay API surface behind the fan-out.

Answers, empirically and against YOUR instance rather than from memory:
  - which per-analysis / per-sample endpoints exist (200 vs 404 vs 403)
  - the real response shape of each (top-level keys, item counts, one sample item)
  - per-call latency, which feeds spikes 0.4 and 0.5
  - the Platform version, which settles the "minimum supported version" open item

READ-ONLY. Issues GETs only. Submits nothing, so it costs ZERO detonation quota.

Usage:
    export VMRAY_BASE_URL=https://eu.cloud.vmray.com      # or your appliance
    export VMRAY_API_KEY=<api key>
    python3 spikes/spike_03_vmray_surface.py

    # optionally pin a known-interesting analysis instead of auto-picking:
    python3 spikes/spike_03_vmray_surface.py --sample-id 123456
    # self-signed on-prem appliance:
    python3 spikes/spike_03_vmray_surface.py --no-verify

Outputs:
    spikes/out/vmray/<endpoint>.json   full body of every endpoint that answered
    spikes/out/vmray/REPORT.md         surface map + which fan-out calls are real
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests

OUT = Path(__file__).parent / "out" / "vmray"

# Candidate endpoints. This list is a HYPOTHESIS, not a claim — the whole point
# of the spike is to find out which of these your Platform actually serves, and
# to surface anything reachable that is not listed here.
#   {sample}   -> sample_id
#   {analysis} -> analysis_id
#   {submission} -> submission_id
CANDIDATES = [
    # --- instance level -------------------------------------------------
    ("system_info",        "/rest/system_info"),
    ("usage",              "/rest/usage"),
    ("openapi",            "/rest/openapi.json"),
    ("swagger",            "/rest/swagger.json"),

    # --- listing --------------------------------------------------------
    ("analysis_list",      "/rest/analysis?_limit=3"),
    ("sample_list",        "/rest/sample?_limit=3"),
    ("submission_list",    "/rest/submission?_limit=3"),

    # --- per analysis ---------------------------------------------------
    ("analysis",           "/rest/analysis/{analysis}"),
    ("analysis_vtis",      "/rest/analysis/{analysis}/vtis"),
    ("analysis_iocs",      "/rest/analysis/{analysis}/iocs"),
    ("analysis_mitre",     "/rest/analysis/{analysis}/mitre_attack"),
    ("analysis_screenshots", "/rest/analysis/{analysis}/screenshots"),
    ("analysis_archive",   "/rest/analysis/{analysis}/archive"),

    # --- per sample -----------------------------------------------------
    ("sample",             "/rest/sample/{sample}"),
    ("sample_analyses",    "/rest/sample/{sample}/analyses"),
    ("sample_vtis",        "/rest/sample/{sample}/vtis"),
    ("sample_iocs",        "/rest/sample/{sample}/iocs"),
    ("sample_mitre",       "/rest/sample/{sample}/mitre_attack"),
    ("sample_threat_ind",  "/rest/sample/{sample}/threat_indicators"),
    ("sample_childsamples","/rest/sample/{sample}/childsamples"),
    ("sample_relations",   "/rest/sample/{sample}/relations"),
    ("sample_submissions", "/rest/sample/{sample}/submissions"),

    # --- per submission -------------------------------------------------
    ("submission",         "/rest/submission/{submission}"),
    ("submission_analyses","/rest/submission/{submission}/analyses"),
]

# Which VMRay outputs the design needs, and which probe name would supply each.
NEEDED = {
    "verdict":         ["analysis", "sample", "submission"],
    "VTIs":            ["analysis_vtis", "sample_vtis", "sample_threat_ind"],
    "IOCs":            ["analysis_iocs", "sample_iocs"],
    "threat names":    ["sample", "analysis", "sample_threat_ind"],
    "classifications": ["sample", "analysis"],
    "MITRE ATT&CK":    ["analysis_mitre", "sample_mitre"],
    "child samples":   ["sample_childsamples", "sample_relations"],
    "relations":       ["sample_relations", "sample_childsamples"],
    "screenshots":     ["analysis_screenshots", "analysis_archive"],
}


class VMRay:
    def __init__(self, base, key, verify=True):
        self.base = base.rstrip("/")
        self.verify = verify
        self.s = requests.Session()
        # VMRay Platform uses this scheme; if your instance rejects it the
        # report will show 401 across the board and we switch to Bearer.
        self.s.headers.update({
            "Authorization": f"api_key {key}",
            "Accept": "application/json",
            "User-Agent": "vmray-sekoia-spike/0.3",
        })

    def probe(self, path):
        url = self.base + path
        t0 = time.perf_counter()
        try:
            r = self.s.get(url, timeout=60, verify=self.verify)
        except Exception as e:
            return {"status": "ERR", "ms": None, "error": str(e)[:200], "body": None}
        ms = int((time.perf_counter() - t0) * 1000)
        out = {"status": r.status_code, "ms": ms, "error": None, "body": None}
        if r.ok:
            try:
                out["body"] = r.json()
            except ValueError:
                out["body"] = {"__non_json__": r.headers.get("Content-Type"),
                               "__bytes__": len(r.content)}
        else:
            out["error"] = r.text[:200]
        return out


def shape(body):
    """Describe a response without dumping it."""
    if body is None:
        return "-", "-"
    if isinstance(body, dict):
        data = body.get("data", body)
        if isinstance(data, list):
            n = len(data)
            keys = sorted(data[0].keys())[:14] if n and isinstance(data[0], dict) else []
            return f"list[{n}]", ", ".join(f"`{k}`" for k in keys) or "-"
        if isinstance(data, dict):
            return "object", ", ".join(f"`{k}`" for k in sorted(data.keys())[:14]) or "-"
    if isinstance(body, list):
        return f"list[{len(body)}]", "-"
    return type(body).__name__, "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample-id")
    ap.add_argument("--analysis-id")
    ap.add_argument("--submission-id")
    ap.add_argument("--no-verify", action="store_true", help="self-signed on-prem appliance")
    args = ap.parse_args()

    base = os.environ.get("VMRAY_BASE_URL")
    key = os.environ.get("VMRAY_API_KEY")
    if not base or not key:
        sys.exit("set VMRAY_BASE_URL and VMRAY_API_KEY")

    api = VMRay(base, key, verify=not args.no_verify)
    OUT.mkdir(parents=True, exist_ok=True)

    # --- discover concrete ids to probe with --------------------------------
    sample_id, analysis_id, submission_id = args.sample_id, args.analysis_id, args.submission_id
    if not analysis_id:
        print("discovering a recent analysis ...")
        r = api.probe("/rest/analysis?_limit=3")
        if r["status"] != 200:
            sys.exit(f"cannot list analyses: {r['status']} {r['error']}\n"
                     f"If 401, the auth scheme differs — try Bearer and tell me.")
        data = (r["body"] or {}).get("data") or []
        if not data:
            sys.exit("no analyses on this instance — submit one sample by hand, then rerun")
        a = data[0]
        analysis_id = analysis_id or a.get("analysis_id")
        sample_id = sample_id or a.get("analysis_sample_id") or a.get("sample_id")
        submission_id = submission_id or a.get("analysis_submission_id")
    print(f"  analysis_id={analysis_id}  sample_id={sample_id}  submission_id={submission_id}")

    subs = {"analysis": analysis_id, "sample": sample_id, "submission": submission_id}

    # --- probe ---------------------------------------------------------------
    results = {}
    for name, tmpl in CANDIDATES:
        if any(f"{{{k}}}" in tmpl and not v for k, v in subs.items()):
            results[name] = {"path": tmpl, "status": "SKIP", "ms": None,
                             "error": "no id available", "body": None}
            print(f"  {name:22} SKIP")
            continue
        path = tmpl.format(**{k: v for k, v in subs.items() if v})
        r = api.probe(path)
        r["path"] = path
        results[name] = r
        if r["body"] is not None:
            (OUT / f"{name}.json").write_text(json.dumps(r["body"], indent=2, default=str))
        print(f"  {name:22} {r['status']}  {r['ms'] if r['ms'] is not None else '-'}ms")

    # --- report --------------------------------------------------------------
    sysinfo = (results.get("system_info", {}).get("body") or {}).get("data", {})
    version = sysinfo.get("version_vmray") or sysinfo.get("version") or "unknown"

    L = [
        "# Phase 0 spike 0.3 — VMRay API surface",
        "",
        f"- Instance: `{base}`",
        f"- Platform version: **{version}**  ← settles the minimum-supported-version item",
        f"- Probed with: analysis_id=`{analysis_id}` sample_id=`{sample_id}` submission_id=`{submission_id}`",
        "- Read-only, zero detonation quota consumed.",
        "",
        "## Surface map",
        "",
        "| Probe | Path | Status | ms | Shape | Top-level keys |",
        "|---|---|---|---|---|---|",
    ]
    for name, r in results.items():
        kind, keys = shape(r["body"])
        L.append(f"| `{name}` | `{r['path']}` | {r['status']} | {r['ms'] or '-'} | {kind} | {keys} |")

    L += ["", "## Coverage of what the design needs", "",
          "| Output the design consumes | Served by | Verdict |", "|---|---|---|"]
    missing = []
    for need, cands in NEEDED.items():
        ok = [c for c in cands if results.get(c, {}).get("status") == 200]
        if ok:
            L.append(f"| {need} | {', '.join(f'`{c}`' for c in ok)} | ✅ available |")
        else:
            tried = ", ".join(f"`{c}`" for c in cands)
            L.append(f"| {need} | tried {tried} | ❌ **not found** |")
            missing.append(need)

    live = [n for n, r in results.items() if r.get("status") == 200
            and n not in ("system_info", "usage", "openapi", "swagger")
            and not n.endswith("_list")]
    total_ms = sum(results[n]["ms"] or 0 for n in live)

    L += [
        "", "## Fan-out cost", "",
        f"- Endpoints answering 200 that `GetAnalysisDetails` would call: **{len(live)}**",
        f"- Sum of their latencies, sequential: **{total_ms} ms**",
        f"- Slowest single call: **{max((results[n]['ms'] or 0) for n in live) if live else 0} ms**",
        "",
        "If the sequential sum is a meaningful fraction of the detonation time, run the",
        "fan-out concurrently — spike 0.5 decides whether VMRay tolerates that.",
        "",
        "## Next actions",
        "",
    ]
    if missing:
        L += [f"- ⚠️ **No endpoint found for: {', '.join(missing)}.** Either the path guess is",
              "  wrong or this Platform version does not expose it. Check the Cloud API Reference",
              "  for the real route before writing `GetAnalysisDetails`.", ""]
    else:
        L += ["- ✅ Every output the design consumes has a live endpoint. `GetAnalysisDetails`",
              "  can be written directly against the bodies in this directory.", ""]
    L += [
        "- Promote the dumped bodies to `tests/fixtures/vmray/` — the pure-transform",
        "  actions (`RenderSummary`, `IocsToIndicators`, `AnalysisToBundle`) are written",
        "  and unit-tested against exactly these, no credentials required.",
        "- Derive the results model field-by-field from the real keys above, not from the",
        "  provisional list in the design doc.",
    ]

    (OUT / "REPORT.md").write_text("\n".join(L))
    print(f"\nwrote {OUT / 'REPORT.md'}")
    if missing:
        print(f"MISSING: {', '.join(missing)}")


if __name__ == "__main__":
    main()
