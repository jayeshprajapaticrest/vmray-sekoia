#!/usr/bin/env python3
"""
Phase 0 spike 0.0 — seed one synthetic alert so 0.1/0.2/0.6 have something to test against.

The tenant has zero data. Two slow paths exist (wait for a real log source; author
a custom parser). This takes a third: push synthetic events through an EXISTING,
already-parsed catalog format (Suricata EVE JSON) so no parser-authoring is needed,
using values chosen to be unambiguous and safe:

  - a TEST-NET-3 address (203.0.113.0/24, RFC 5737 — reserved for documentation,
    will never collide with real traffic) as the "malicious" destination, so a
    SOL rule can match on it with zero false-positive risk
  - the canonical EICAR test string's real hashes, computed below from the same
    68-byte fixture `automation-library/Glimps/tests/eicar.txt` already uses —
    a standard, universally-recognised benign test artifact. Using it here means
    the same hash can be pushed at VMRay later for the submit-path test, without
    detonating anything actually malicious.

This script only prepares and POSTs the JSON. Two things still require the UI,
because they need credentials/clicks this session doesn't have:

  1. Create an intake using the built-in "Suricata" format → gives INTAKE_KEY.
     Intakes → + Intake → search "Suricata" → name it, e.g. "vmray-spike-seed".
  2. Create one SOL rule to turn the pushed events into an alert. Detection >
     Rules catalog > + New rule > SOL tab:
         events | where destination.ip == "203.0.113.66" | limit 100
     (field name may differ — the Query editor autocompletes; use what it offers
     for "destination IP". Severity/effort/threats: anything, this is a test rule.)
     Enable it, set "Run query every" to the shortest option so it fires fast.

Usage:
    export SEKOIA_INTAKE_KEY=<key from step 1>
    export SEKOIA_INTAKE_BASE=https://intake.sekoia.io          # FRA1 default;
        # other regions: https://intake.<region>.sekoia.io/api/v1/intake-http
    python3 spikes/spike_00_seed_test_alert.py

After the rule has run once (watch Detection > Rules catalog > your rule > Runs,
or just wait one interval), the alert shows up in Alerts — that alert is what
spike_01_02_alert_observables.py and the live playbook consume.
"""

import hashlib
import json
import os
import sys
import time
import uuid

import requests

TEST_IP = "203.0.113.66"          # RFC 5737 TEST-NET-3 — reserved, non-routable
TEST_DOMAIN = "malicious-test.invalid.example"   # .invalid per RFC 2606

EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def eicar_hashes():
    return {
        "sha256": hashlib.sha256(EICAR).hexdigest(),
        "sha1": hashlib.sha1(EICAR).hexdigest(),
        "md5": hashlib.md5(EICAR).hexdigest(),
    }


def eve_events():
    """Two Suricata EVE JSON lines: an `http` alert event (carries the URL/domain)
    and a `fileinfo` event (carries the hashes) — the two observable shapes the
    design needs to see flow through Sekoia's own parser and land as real,
    Sekoia-native fields on the alert."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime())
    flow_id = int(time.time() * 1000)
    h = eicar_hashes()

    alert_event = {
        "timestamp": now,
        "flow_id": flow_id,
        "event_type": "alert",
        "src_ip": "198.51.100.10",     # RFC 5737 TEST-NET-2 — also reserved
        "src_port": 443,
        "dest_ip": TEST_IP,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": "VMRAY-SPIKE-TEST synthetic malicious download",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
        "http": {
            "hostname": TEST_DOMAIN,
            "url": f"/payload/{uuid.uuid4().hex}.bin",
            "http_method": "GET",
            "status": 200,
        },
    }

    fileinfo_event = {
        "timestamp": now,
        "flow_id": flow_id,
        "event_type": "fileinfo",
        "src_ip": "198.51.100.10",
        "dest_ip": TEST_IP,
        "http": {"hostname": TEST_DOMAIN, "url": alert_event["http"]["url"]},
        "fileinfo": {
            "filename": "invoice.exe",
            "size": len(EICAR),
            "sha256": h["sha256"],
            "sha1": h["sha1"],
            "md5": h["md5"],
        },
    }
    return [alert_event, fileinfo_event]


def main():
    key = os.environ.get("SEKOIA_INTAKE_KEY")
    base = os.environ.get("SEKOIA_INTAKE_BASE", "https://intake.sekoia.io")
    if not key:
        print(__doc__)
        sys.exit("SEKOIA_INTAKE_KEY not set — create the Suricata intake in the UI first")

    events = eve_events()
    h = eicar_hashes()
    print("Seeding with:")
    print(f"  destination.ip candidate : {TEST_IP}  (RFC 5737 TEST-NET-3)")
    print(f"  hostname/url candidate   : {TEST_DOMAIN}")
    print(f"  EICAR sha256             : {h['sha256']}")
    print(f"  EICAR sha1               : {h['sha1']}")
    print(f"  EICAR md5                : {h['md5']}")
    print()

    payload = [json.dumps(e) for e in events]
    r = requests.post(
        f"{base}/jsons",
        headers={"X-SEKOIAIO-INTAKE-KEY": key, "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    print(f"POST {base}/jsons -> {r.status_code}")
    print(r.text[:500])
    r.raise_for_status()

    print("""
Pushed. Next (UI, manual):
  1. If the SOL rule from the docstring isn't created yet, create + enable it now.
  2. Wait one rule interval (or trigger a manual run if the UI offers one).
  3. Check Alerts — a new alert should appear.
  4. That alert is real data for:
       - spike_01_02_alert_observables.py  (point SEKOIA_API_KEY at the same tenant)
       - the live 'vmray-playbook' Alert Created trigger, for spike 0.6
""")


if __name__ == "__main__":
    main()
