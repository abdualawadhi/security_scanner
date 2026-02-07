# Threat Model (Low-Code Platform Security Scanner)

## Scope
- Targets: Low-code web applications (Bubble, OutSystems, Airtable, Shopify, Webflow, Wix, Mendix, Generic Web).
- Scanner: Passive and safe active verification of findings.

## Assets
- Scan reports and evidence metadata.
- Target URLs and discovered endpoints.
- Verification payloads and detection rules.

## Trust Boundaries
- Scanner host vs. target application.
- Report storage vs. user access.
- Plugins or external modules (if enabled).

## Assumptions
- The user has permission to scan targets.
- Scanner runs in a controlled environment.
- Network traffic is allowed and rate limited.

## Threats
- False positives from heuristic detection.
- False negatives due to limited coverage or blocked access.
- Data leakage in reports (sensitive evidence).
- Report tampering or altered findings.
- Excessive request rates causing target impact.

## Mitigations
- Evidence verification with timestamps and hashes.
- Confidence scoring and verification states.
- Per-host rate limiting and scan profiles.
- Report integrity section with scan profile hash and git commit.
- Optional disabling of external JS fetching.

## Out of Scope
- Exploit development or intrusive testing.
- Privileged or authenticated scans (unless explicitly configured by the user).
- Dynamic runtime instrumentation or full behavioral analysis.
- Denial-of-service testing.

