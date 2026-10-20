# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-10-16 - 1.0.0

### Added

- Initial release
- Get Samples By Hash action: look up SHA256/SHA1/MD5 hashes in VMRay's existing analyses (no quota used)
- Submit URL Sample action: submit a URL to VMRay and wait until its analyses finish, with a timeout
- Build Report action: build the full VMRay report for sample IDs or submission IDs — analyses, VMRay Threat Identifiers, MITRE ATT&CK, IOCs, classifications, threat names and screenshots, including child samples
- Render Report action: render a report as an alert comment, with screenshots split across extra comments under a size limit
- Extract IOCs action: extract a report's IOCs as typed indicators for an IOC collection, grouped by type
