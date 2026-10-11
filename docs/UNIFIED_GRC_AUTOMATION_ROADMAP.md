# AegisGRC unified GRC and vulnerability automation roadmap

Benchmark: Scrut Automation public platform and documentation (October 2026). This is a functional benchmark, not a claim of access to Scrut's internal implementation. Never copy proprietary UI, templates, or content.

Official sources:
- https://www.scrut.io/
- https://help.scrut.io/docs/evidence-automation-workflow
- https://help.scrut.io/docs/integrations-overview
- https://help.scrut.io/docs/evidence-tasks-walkthrough
- https://help.scrut.io/docs/quick-start-guide-risk-management
- https://help.scrut.io/docs/policy-module-walkthrough

## One-workspace operating model

A discovered asset should be connected to: identity/owner, organization/scope, architecture node, vulnerability finding, exploitability/exposure context, business service, applicable framework controls, evidence, risk, remediation/CAPA, reviewer approval, and exportable audit history. Each transition must preserve evidence provenance and enforce tenant RBAC.

## Highest-value gaps versus the current platform

1. **Integration control center:** OAuth/API connectors, encrypted tenant-scoped secrets, least-privilege permissions, connection health, last successful sync, retry queues, rate-limit budgets, connector audit trails. Prioritize AWS/Azure/GCP, GitHub/GitLab, Microsoft Entra/Okta, Jira, ticketing, EDR/SIEM, HRIS. No connector is 'active' until credentials, scopes and an actual successful sync are verified.
2. **Evidence automation engine:** each evidence task shows MANUAL_ONLY / AUTOMATION_READY / PARTIAL / FULL, required sources, freshness/expiry, collection provenance, hash, human acceptance, drift history. Failed collection must never count as passing evidence.
3. **Unified exposure-to-control graph:** normalize scanner results using stable asset/finding fingerprints; correlate CVE, KEV, EPSS, reachability, exploit preconditions, compensating controls and owner; open risk/issue/CAPA with explicit human review; retest before closure.
4. **Trust portal and questionnaires:** external redacted trust center, access requests, time-limited sharing, approval, audit trail, questionnaire answer library with citations to approved current evidence. Never leak internal findings.
5. **Identity and people compliance:** periodic access recertification, privileged account review, joiner/mover/leaver evidence, training/attestation campaigns, segregation-of-duties checks.
6. **Audit collaboration:** audit cycles, auditor requests, workpaper collaboration, management responses, evidence freeze/version, review signoff, export with complete source trace.
7. **Policy lifecycle:** version history, review recurrence, policy variables, approved templates, publication, target audience, attestations and exceptions with expiry.
8. **Vendor lifecycle:** discovery and shadow SaaS/AI, tailored questionnaires, contract/SLA/DPAs, subprocessor inventory, fourth-party dependencies, external incidents, continuous reviews, offboarding.
9. **Privacy and AI governance:** data processing inventory, retention and deletion evidence, DPIA/PIA, DSAR workflow, India DPDP applicability, AI model inventory, model evaluation, AI risk and ISO 42001 control evidence.
10. **Business resilience:** critical business-service dependencies, RTO/RPO validation, tabletop/restore drills, immutable results, incidents and vendor concentration, recovery gaps and risk linkage.
11. **Reporting and AI assistant:** executive/auditor/technical views share one source of truth; explain what was tested and not tested; assistant responses cite specific evidence and require human approval for write actions.
12. **Operational safety:** tenant-isolation integration tests, background-job idempotency, backups + restore drills, retention policies, secure document processing, security review of every new integration.

## Architecture workspace: release scope and limitations

Implemented in this feature branch: authenticated in-memory architecture PDF/DOCX/text/spreadsheet upload, deterministic component and explicit-flow extraction, provenance labels, interactive perspective 3D graph with rotation/zoom/selection, and removal of the old architecture Control-plane workflow panel.

Not yet implemented: OCR for image-only diagrams, shape/connector recognition from PDF drawings, actual CAD solids, BIM/STEP/DWG import, live infrastructure telemetry, automatic cloud topology reconciliation, editable verified graph, time-series simulation, URL retrieval, persistent per-tenant model history. Those are separate milestones and must never be misrepresented as present.

## Suggested phased delivery

Phase A: architecture diagram OCR/shape extraction, manual correction and signed approval, tenant-scoped graph persistence; provenance and confidence per edge.
Phase B: integration hub + evidence automation + normalized vulnerability correlation.
Phase C: people/vendor/trust/audit workflow completeness and cross-framework evidence reuse.
Phase D: verified architecture change-detection, attack-path context, performance and recovery scenario simulation.

Acceptance must include representative scanned PDFs and vector PDFs, multiple-page DOCX, tenant isolation, hostile/oversized documents, accessibility, no invented links, no unauthorized URL fetching, and audit-grade export validation. No GRC product can guarantee '100% compliant' without scoped evidence, organizational operation, and independent assurance.
