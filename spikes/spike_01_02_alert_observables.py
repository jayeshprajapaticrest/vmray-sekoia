#!/usr/bin/env python3
"""
Phase 0 spikes 0.1 + 0.2 — what do Sekoia alerts actually give VMRay?

0.1  Which observables do alerts carry, and under which field names?
     Checks BOTH paths: GET /alerts/{uuid}/objects (STIX-typed, filterable by
     match[type]) and the event-search route the VirusTotal template uses.
0.2  Does any alert path expose sample BYTES (gates the SubmitFile action)?

Read-only. Issues GETs plus one event-search job per alert (the same call the
`Get Events` playbook action makes). Creates nothing, modifies nothing.

Usage:
    export SEKOIA_BASE_URL=https://api.sekoia.io
    export SEKOIA_API_KEY=<api key>
    python3 spikes/spike_01_02_alert_observables.py --limit 50 --days 7

Outputs:
    spikes/out/alerts/<short_id>.json     alert detail
    spikes/out/events/<short_id>.json     its events
    spikes/out/REPORT.md                  field histogram + verdict on 0.1/0.2
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from posixpath import join as urljoin

import requests

OUT = Path(__file__).parent / "out"

# Field-name patterns worth reporting. Sekoia normalises to an ECS-like taxonomy,
# so we match on shape rather than assuming exact names.
PATTERNS = {
    "hash":     re.compile(r"(^|\.)(hash|sha256|sha1|md5|ssdeep|imphash)(\.|$)", re.I),
    "url":      re.compile(r"(^|\.)(url|uri|referrer)(\.|$)", re.I),
    "domain":   re.compile(r"(^|\.)(domain|hostname|fqdn|question\.name)(\.|$)", re.I),
    "ip":       re.compile(r"(^|\.)(ip|address)(\.|$)", re.I),
    "filename": re.compile(r"(^|\.)(file\.name|filename|original_file_name|path)(\.|$)", re.I),
    # 0.2: anything that smells like retrievable content rather than metadata
    "BYTES":    re.compile(r"(content|payload|body|base64|raw|attachment|blob|data_b64|download|artifact)", re.I),
}

HASH_VALUE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)


def flatten(obj, prefix=""):
    """Yield (dotted_key, value) for every leaf in a nested structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from flatten(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for item in obj:
            yield from flatten(item, prefix)
    else:
        yield prefix, obj


class Sekoia:
    def __init__(self, base_url: str, api_key: str):
        self.base = base_url.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": "vmray-sekoia-spike/0.1",
        })

    def _get(self, path, **kw):
        r = self.s.get(urljoin(self.base, path), timeout=30, **kw)
        r.raise_for_status()
        return r.json()

    def list_alerts(self, limit):
        return self._get("api/v1/sic/alerts", params={"limit": limit})

    def get_alert(self, uuid):
        return self._get(f"api/v1/sic/alerts/{uuid}")

    def get_alert_objects(self, uuid, limit=1000):
        """GET /v1/sic/alerts/{uuid}/objects — STIX-typed objects attached to the alert.

        Discovered in the public SIC OpenAPI spec. Supports match[type], so
        `match[type]=file,url` yields exactly the observables VMRay can take.
        This is a far cleaner extraction path than the event-search route.
        """
        return self._get(f"api/v1/sic/alerts/{uuid}/objects", params={"limit": limit})

    def get_events(self, short_id, earliest, latest, limit=100):
        """Mirrors the `Get Events` action: start a search job, poll, page results."""
        api = urljoin(self.base, "api/v1/sic/conf/events")
        r = self.s.post(f"{api}/search/jobs", timeout=30, json={
            "term": f"alert_short_ids:{short_id}",
            "earliest_time": earliest,
            "latest_time": latest,
            "visible": False,
            "max_last_events": limit,
        })
        r.raise_for_status()
        job = r.json()["uuid"]

        for _ in range(60):
            st = self._get(f"api/v1/sic/conf/events/search/jobs/{job}")
            if st.get("status") == 2 or st.get("stopped_at"):
                break
            time.sleep(1)

        out, offset = [], 0
        while True:
            page = self._get(
                f"api/v1/sic/conf/events/search/jobs/{job}/events",
                params={"limit": limit, "offset": offset},
            )
            items = page.get("items", [])
            out += items
            if not items or len(out) >= min(page.get("total", 0), limit):
                break
            offset += limit
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50, help="alerts to sample")
    ap.add_argument("--days", type=int, default=7, help="lookback window")
    args = ap.parse_args()

    base = os.environ.get("SEKOIA_BASE_URL", "https://api.sekoia.io")
    key = os.environ.get("SEKOIA_API_KEY")
    if not key:
        sys.exit("SEKOIA_API_KEY not set")

    api = Sekoia(base, key)
    (OUT / "alerts").mkdir(parents=True, exist_ok=True)
    (OUT / "events").mkdir(parents=True, exist_ok=True)

    print(f"listing up to {args.limit} alerts from {base} ...")
    alerts = api.list_alerts(args.limit).get("items", [])
    print(f"  {len(alerts)} alerts")

    field_hits = defaultdict(Counter)      # category -> field name -> count
    sample_values = defaultdict(dict)      # category -> field -> example value
    bytes_fields = {}                      # 0.2 candidates
    alerts_with = Counter()                # how many alerts carry each category
    object_types = Counter()               # STIX types seen on /objects
    since = (datetime.now(timezone.utc) - timedelta(days=args.days)).isoformat()
    now = datetime.now(timezone.utc).isoformat()

    for i, stub in enumerate(alerts, 1):
        uuid = stub.get("uuid")
        try:
            alert = api.get_alert(uuid)
        except Exception as e:
            print(f"  [{i}] alert {uuid}: {e}")
            continue

        short_id = alert.get("short_id", uuid)
        (OUT / "alerts" / f"{short_id}.json").write_text(json.dumps(alert, indent=2))

        try:
            objects = api.get_alert_objects(uuid)
        except Exception as e:
            print(f"  [{i}] {short_id}: /objects failed: {e}")
            objects = {}
        (OUT / "objects").mkdir(parents=True, exist_ok=True)
        (OUT / "objects" / f"{short_id}.json").write_text(json.dumps(objects, indent=2))
        obj_items = objects.get("items", objects if isinstance(objects, list) else [])
        for o in obj_items:
            if isinstance(o, dict) and o.get("type"):
                object_types[o["type"]] += 1

        try:
            events = api.get_events(
                short_id,
                alert.get("first_seen_at") or since,
                alert.get("last_seen_at") or now,
            )
        except Exception as e:
            print(f"  [{i}] {short_id}: events failed: {e}")
            events = []

        (OUT / "events" / f"{short_id}.json").write_text(json.dumps(events, indent=2))

        seen_here = set()
        for blob in [alert, objects] + events:
            for field, value in flatten(blob):
                if value in (None, "", [], {}):
                    continue
                for cat, pat in PATTERNS.items():
                    if pat.search(field):
                        field_hits[cat][field] += 1
                        sample_values[cat].setdefault(field, repr(value)[:120])
                        seen_here.add(cat)
                        if cat == "BYTES":
                            bytes_fields[field] = repr(value)[:200]
                # a hash-shaped value under an unexpected field name
                if isinstance(value, str) and HASH_VALUE.match(value):
                    field_hits["hash"][field] += 1
                    sample_values["hash"].setdefault(field, value)
                    seen_here.add("hash")

        for cat in seen_here:
            alerts_with[cat] += 1
        print(f"  [{i}/{len(alerts)}] {short_id}: {len(obj_items)} objects, "
              f"{len(events)} events, found {sorted(seen_here)}")

    # ---- report -------------------------------------------------------------
    n = len(alerts)
    lines = [
        "# Phase 0 spikes 0.1 + 0.2 — results",
        "",
        f"- Tenant: `{base}`",
        f"- Alerts sampled: **{n}** (lookback {args.days}d)",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## 0.1 — Observable coverage",
        "",
        "How many sampled alerts carry at least one field of each kind:",
        "",
        "| Kind | Alerts with it | Coverage |",
        "|---|---|---|",
    ]
    for cat in ("hash", "url", "domain", "ip", "filename"):
        c = alerts_with[cat]
        lines.append(f"| {cat} | {c}/{n} | {(100*c/n if n else 0):.0f}% |")

    lines += [
        "", "### STIX object types on `/alerts/{uuid}/objects`", "",
        "This endpoint is the cleanest extraction path (supports `match[type]`).",
        "", "| STIX type | Count |", "|---|---|",
    ]
    for t, c in object_types.most_common(20):
        lines.append(f"| `{t}` | {c} |")
    if not object_types:
        lines.append("| _(none returned)_ | 0 |")

    lines += ["", "### Field names seen (submittable kinds)", ""]
    for cat in ("hash", "url"):
        lines += [f"**{cat}**", "", "| Field | Occurrences | Example |", "|---|---|---|"]
        for field, count in field_hits[cat].most_common(15):
            lines.append(f"| `{field}` | {count} | `{sample_values[cat][field]}` |")
        lines.append("")

    lines += ["## 0.2 — Are sample bytes available?", ""]
    if bytes_fields:
        lines += [
            "**Candidate fields found.** Inspect each before concluding — a field name "
            "matching `content`/`payload` is often log text, not sample bytes.",
            "",
            "| Field | Example |",
            "|---|---|",
        ]
        for f, v in sorted(bytes_fields.items()):
            lines.append(f"| `{f}` | `{v}` |")
        lines += ["", "**Verdict: INSPECT** — decide `SubmitFile` after reading these."]
    else:
        lines += [
            "**No byte-bearing field found in any sampled alert or event.**",
            "",
            "**Verdict: confirms the design assumption.** `SubmitFile` ships but stays "
            "unwired in both playbook templates; it is usable only when an upstream node "
            "fetches the sample and writes it to `data_path`. Document in the README.",
        ]

    lines += [
        "", "## Raw output", "",
        f"- `spikes/out/alerts/` — {n} alert bodies",
        "- `spikes/out/objects/` — STIX objects per alert",
        "- `spikes/out/events/` — matching events per alert",
        "",
        "Promote the most representative of these to `tests/fixtures/` for the module's unit tests.",
    ]

    (OUT / "REPORT.md").write_text("\n".join(lines))
    print(f"\nwrote {OUT / 'REPORT.md'}")


if __name__ == "__main__":
    main()
