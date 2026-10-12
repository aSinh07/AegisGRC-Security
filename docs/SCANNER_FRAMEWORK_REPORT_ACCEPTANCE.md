# Scanner and framework integration acceptance standard

Status: engineering acceptance specification, **not** evidence of complete implementation or certification.

## Capability truth table
- Greenbone/OpenVAS: JSON report import/normalization exists; authenticated GMP task creation, scan execution, polling and collection are **not implemented**. Do not mark as a live connected scanner.
- Wazuh and Prowler: report ingestion exists; live authenticated collection is **not proven**.
- Guardius: no implementation or verified vendor API contract is present. Evaluate its API, authorization, licensing, and report formats before advertising support.
- "Wals" is ambiguous. Confirm exact product name/vendor before adding an integration; do not silently equate it with Wazuh, Wapiti, or w3af.
- Local scanner availability and runtime execution are separate. Presence in a Docker image is not proof of successful scans.

## OpenVAS GMP implementation acceptance
1. Run Greenbone Community Edition or an approved Greenbone appliance as a separately managed scanner service; do not embed its database/feed/daemon into the existing application/PostgreSQL volume.
2. Use a least-privileged GMP account, authenticated TLS transport, credential isolation and strict target authorization; do not expose GMP publicly.
3. Implement scoped target creation, scan config, task start/stop, status polling, bounded concurrency, cancellation, and report retrieval.
4. Parse native report data with stable source identifiers, asset/port, CVE/CVSS, evidence timestamps, raw report SHA-256 and import provenance.
5. Distinguish NOT_RUN, RUNNING, FAILED, PARTIAL, COMPLETED and STALE. No fabricated PASS or clean result on timeout.
6. Test against a controlled authorized target, with an intentionally vulnerable fixture, a known-clean fixture, interrupted scan, bad credentials, tenant-isolation checks, duplicate imports and retest closure.
7. No production claim until a real scan and the entire finding-to-remediation-to-retest workflow are evidenced.

## Framework library priorities
Priority: ISO/IEC 27001:2022 (and applicable amendment), ISO/IEC 42001:2023, NIST CSF 2.0, NIST SP 800-53 Rev 5, SOC 2 Trust Services Criteria, CIS Controls v8.1, PCI DSS v4.0.1, ISO/IEC 27701 (version verified), ISO 22301, ISO 31000, GDPR, India DPDP Act/Rules with provision-level effective dates, HIPAA (applicability-dependent), and cloud CCM where licensed.

A named framework is **not** complete coverage. Every edition needs an authoritative source, licensing check, complete requirement inventory, versioned IDs, applicability rules, mapping provenance, evidence types, reviewer/approver roles and change tracking. Imported third-party mappings are informative and must be reviewed.

## Mandatory framework-report schema
Each export (PDF/DOCX/XLSX/JSON as applicable) must contain:
- organization, assessment scope and boundaries, framework edition and amendment, report identifier/version, generation timestamp, author/reviewer/approval, confidentiality classification;
- methodology, assessed systems and dates, exclusions, limitations and sample size;
- complete applicable requirement inventory with exact IDs and approved short descriptions (full licensed text only when authorized);
- per requirement: applicability, justification, control owner, implementation state, operating effectiveness, test method, evidence reference and SHA-256, observation, risk, corrective action, due date, retest state and human review;
- explicit statuses: PASS, FAIL, PARTIAL, NOT_TESTED, NOT_APPLICABLE (justified), INSUFFICIENT_EVIDENCE. Never convert missing evidence into PASS;
- risk summary, findings with severity and source, remediation plan, residual risk, exceptions and approvals;
- traceable appendices, immutable source IDs and report-generation provenance.

ISO 27001: include Statement of Applicability, risk treatment linkage, internal audit, management review and corrective actions where within scope.
ISO 42001: include AI system inventory, impact/risk assessments, lifecycle responsibilities, policies, AI-related controls, monitoring, human oversight and management-system review.
NIST CSF: outcome-based profile and gap view, not an ISO certificate.
Vulnerability findings may support a control but cannot alone prove management-system conformity or certification.

## Export acceptance tests (must pass before 'correct format' claim)
1. Golden-file/structural checks for each edition and export type, with exact requirement IDs and counts compared to a licensed or official authoritative source.
2. PDF/DOCX/XLSX render and parse round-trip; no truncated tables, malformed files, missing pages, broken cross-references or formula injection.
3. Every status supported by attributable evidence; no 100% score for missing, stale, out-of-scope or untested controls.
4. Verify scope isolation, RBAC, redaction, stable pagination, metadata, hashes and signed approval trail.
5. Reviewer sign-off by a competent framework specialist. External audit/certification remains a separate independent process.

## Release gates
- Integration catalog must state IMPORT_ONLY vs LIVE_AUTHENTICATED and not overclaim.
- Real scanner E2E and negative tests pass in an authorized isolated environment.
- Full framework inventory reconciled with authoritative versioned source; licensed content not redistributed.
- Format validation and sample human audit approval recorded.
- Independent security validation, operational load/recovery tests and production acceptance remain external evidence gates.
