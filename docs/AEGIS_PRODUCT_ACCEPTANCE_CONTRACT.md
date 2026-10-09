# AegisGRC — Evidence-to-Assurance Product Contract
Status: engineering specification; capabilities are NOT complete until acceptance tests pass.

## Mission
One authorized platform for external web, internal infrastructure, cloud, source-code and manual security assessments; immutable evidence; normalized findings; traceable framework crosswalks; risk, incident and CAPA workflows; architecture visualization; and independently reviewed branded audit packages.

## Non-negotiable report truth model
- SOURCE_OBSERVATION: raw scanner/import output with tool/version/time/target, SHA-256, collection status.
- NORMALIZED_FINDING: typed issue with affected asset, location, evidence references, detection method, confidence, severity, CVSS vector/version when actually supported.
- ANALYST_VERIFIED: reproducible observation with manual validation and reviewer identity.
- CONTROL_RELEVANCE: deterministic candidate framework cross-reference, edition and rule ID; NOT a conformity verdict.
- CONTROL_TEST: separately executed test with scope, expected condition, independent evidence, pass/fail/not-tested/error.
- AUDIT_CONCLUSION: human-approved scoped conclusion with reviewer, rationale, evidence, exceptions and report snapshot.
- AI may summarize and propose, but never self-approve evidence, claim compliance, fabricate network topology, CVSS, exploitability, breach, incident, or tool execution.
- No universal accuracy percentage until ground-truth evaluation exists. Measure precision, recall, false positives, coverage, mapping agreement and reviewer overrides separately.

## Eight integrated operational modules
1. **Scope & Asset Inventory:** organizations, legal authorization, targets, CIDRs, IPs, hosts, apps, cloud accounts, services, environments, owners, data sensitivity, exclusions and scan windows.
2. **Assessment Orchestrator:** authorized/manual workflows and isolated adapters for Nmap, ZAP, Wapiti, Semgrep, SQLMap plus extensible Nessus/OpenVAS/Trivy/Grype/Checkov/Prowler/ScoutSuite/Cloud APIs. Tools only marked CONNECTED after a verified invocation; capability matrix distinguishes supported/import-only/unavailable. No indiscriminate scan-all.
3. **Evidence Vault & Imports:** versioned binaries in durable storage, verified server-side SHA-256, source, timestamp, tenant, integrity chain, import adapters (SARIF, JSON, XML, CSV, PDF with extraction limitations), retention and read permissions.
4. **Findings & Exposure Graph:** normalization, dedup fingerprints, correlation, false-positive handling, CVE/CWE/CVSS/EPSS enrichment when sourced, asset criticality, ownership, confidence and technical-to-business impact.
5. **Architecture Intelligence:** imported diagrams, IaC, SBOM and inventories plus externally observed services. Explicit OBSERVED / DOCUMENTED / INFERRED labels; reviewer-confirmed nodes/edges; interactive 3D drilldown, trust boundaries, data flows and finding overlays. Never infer private topology from a URL alone.
6. **Framework & GRC Assurance:** versioned ISO 27001/42001, NIST CSF/AI RMF, CIS, OWASP, SOC 2, PCI and other applicability-gated catalogs; licensed standards content not copied; SoA, evidence sufficiency, tests, gap review, risk and exceptions. NOT_TESTED is not PASS.
7. **Incident, Risk & Remediation:** incident intake/triage/containment/eradication/recovery/lessons learned; issue→risk→CAPA→evidence→retest→independent closure; configurable risk treatment and business-calendar SLAs, escalations, approval and append-only history.
8. **Reporting & Audit Packages:** separate executive, technical, framework gap, SoA, remediation, architecture and incident reports; PDF/DOCX/PPTX/XLSX/CSV/JSON with consistent branded template and document control; diagrams, risk heatmap, severity legend, remediation SLA, owners, evidence manifest, test coverage, limitations and approval snapshot.

## Severity and remediation timing
- Severity is NOT the same as SLA. CVSS base score is technical severity; prioritize with exploitability, exposure, asset criticality and business context.
- Default illustrative response targets only (NOT hardcoded regulatory obligations): CRITICAL triage 4h / remediation 7d; HIGH triage 1 business day / remediation 30d; MEDIUM 5 business days / 90d; LOW 10 business days / 180d; INFO review. Each organization must approve its policy and exceptions.
- Store due_at, policy_version, owner, escalation status and remaining time; compute remaining days from current time, never invent historical deadlines.
- Graphs must use real scoped records, distinguish findings from unique affected assets, and show UNKNOWN/NOT_TESTED explicitly.

## Release gates and testable scenarios
A. Authorization: only authorized assets are scanned; exclusions and private-network safeguards are enforced. Scanner jobs are isolated with timeouts/resource limits.
B. Ingestion: fixture import per supported format; original bytes/hash preserved; invalid, partial, duplicate and malformed imports handled; no client-provided hash trusted.
C. Normalization: same weakness from two scanners produces linked sources, not duplicate inflated risk; open HTTPS 443 alone does not create a vulnerability or ISO nonconformity.
D. Accuracy: curated labeled fixture set measures detection precision/recall, severity agreement, framework mapping precision and false-positive rates; publish methodology and sample size.
E. Architecture: unknown edges never presented as observed; reviewer can confirm/correct topology; viewer renders a real versioned graph.
F. Governance: multi-tenant isolation, independent approvals, transaction-safe audit trail, no arbitrary status transitions; expired evidence never PASS.
G. Reports: at least one complete sample with >= 10 findings, two evidence sources, multiple assets, coverage table, full control matrix, executive summary, severity charts, risk heatmap, remediation timeline, appendices and approval record. Visual review for overflow, contrast, page numbers and citations.
H. Operations: CI build/tests + database integration tests + end-to-end UI tests + backup/restore rehearsal + HTTPS smoke checks; deploy only passing revisions.
I. Demo: authorized web URL + imported infrastructure inventory + diagram + manual evidence + two scanner outputs → correlated findings → framework review → CAPA → independent signoff → branded report. No fabricated records.

## Development order (dependencies first)
P0: CI, schema migrations, authorization and evidence integrity.
P1: normalized import schema + fixture adapters + correlation and source coverage.
P2: framework catalog versioning, assurance states, scoped controls, analyst review.
P3: risk/incident/SLA/CAPA lifecycle and audit timeline.
P4: report design system and reproducible approved snapshot exports.
P5: architecture graph ingestion and 3D viewer.
P6: additional scanners/connectors and scheduled evidence automation.
P7: benchmark accuracy, hardening, scale and independent security review.

## Operational truth
Code committed != CI passed != VM deployed != feature tested. Maintain separate statuses and record test evidence for each.
