# AegisGRC — Full Cybersecurity Platform Architecture Upgrade

## Target product hierarchy
Dashboard | Offensive Security | Defensive Security | Incident Response & IDR | Third-Party Risk Management | Enterprise GRC | Audit | Architecture Studio | Learning Hub | AI Copilot.

## Operational pipeline
Authorized offensive testing / defensive telemetry / incident cases / identity detections / vendor due diligence
→ tenant-owned assessment and evidence
→ SHA-256 provenance and source normalization
→ PostgreSQL finding, evidence, issue and report records
→ analyst validation and independent review
→ framework applicability and canonical-control mapping
→ evidence freshness, control tests, treatment and retest
→ reviewed enterprise GRC / audit package
→ password + enrolled TOTP step-up export.

A report is never automatically evidence of compliance. A scanner PASS is not an ISO certification. A vendor security rating is not a substitute for due diligence.

## Existing capabilities to reuse
- TPRM: vendor register, tier, criticality, inherent/residual risk, questionnaires, evidence, reviewer independence, vendor incidents, due dates.
- Automation: PostgreSQL outbox with idempotency, retries, lease recovery and dead letters; allowlisted script tasks only; optional ServiceNow REST delivery.
- Security testing: Nmap, Nuclei, ZAP, SQLmap, Semgrep, Wapiti, Trivy, Grype, Syft, and evidence imports; tool availability depends on runtime installation.
- Architecture: source-labelled document extraction, explicit topology edges, 3D scene layout, confidence and human review gates.
- Reporting: multi-format export and password/TOTP step-up.

## Incident Response & Identity Detection and Response (IDR)
Implement tenant-isolated cases with DETECTED → TRIAGED → CONTAINMENT → ERADICATION → RECOVERY → POST_INCIDENT_REVIEW → CLOSED transitions. Require event source, timeline, owner, incident severity, evidence hash, affected assets, containment approvals, SLA, escalation, root cause and lessons learned. Normalize identity alerts (MFA fatigue, privilege escalation, suspicious login, dormant accounts, impossible travel); require independent review before account disablement or containment. Correlate cases with third-party incidents, technical findings and risk treatment. The current `cyber-operations-handoff.ts` provides pure validation contracts, **not a live case-management API**.

## TPRM comparable to enterprise suites
Onboarding → inherent risk tier → questionnaire → evidence validation → security/privacy review → residual risk → approval → contractual obligations → continuous monitoring → renewal / offboarding. Support supplier-to-subprocessor dependencies and vendor-related incidents. Reuse existing PostgreSQL tables and outbox; do not introduce a second database or claim that ServiceNow is connected without credentials and successful delivery receipts.

## Free/open-source integration candidates (evaluation, not deployed)
- DFIR-IRIS: https://github.com/dfir-iris/iris-web — collaborative incident cases, LGPL-3.0; isolated service and secure private networking required.
- Shuffle: https://github.com/Shuffle/Shuffle — SOAR workflows/webhooks, AGPL-3.0; licensing and deployment costs must be evaluated.
- CISO Assistant Community: https://github.com/intuitem/ciso-assistant-community — TPRM/framework/workflow design reference, AGPL-3.0; do not copy proprietary enterprise files.
- Wazuh: https://github.com/wazuh/wazuh — endpoint and detection telemetry; Aegis already supports evidence ingestion.
- Velociraptor: https://github.com/Velocidex/velociraptor — endpoint forensics and incident investigation.
- Keycloak: https://github.com/keycloak/keycloak — optional identity federation and policy integration.
These tools are not guaranteed to run for zero infrastructure cost. Do not install all of them on the production VM without memory, CPU, disk, license and security assessment.

## 3D architecture assurance
Provide two modes: (1) verified, source-labelled 3D logical topology and (2) hypothetical scenario simulation. For a 50-person organization, model employees → SSO/MFA → IAM/zero-trust policy enforcement → application → PostgreSQL and AWS services; annotate assets, trust zones, permissions, network paths and evidence. An uploaded PDF or image can contain ambiguous/incomplete diagrams: mark unknown edges, ask for confirmation, and never fabricate IAM rules, firewall policies or actual database access. Existing scene positions are layout-only, not CAD measurements. True simulation requires explicit behavioral models and measured configuration.

## Release acceptance / 95% threshold
Do not report 95% functional correctness without a published denominator and test evidence. Define feature acceptance cases for each shipped capability: positive, negative, tenant isolation, authorization, idempotency, data integrity, webhook signature/replay, worker retries, source parsing, report provenance, download MFA, accessibility and disaster recovery. Require ≥95% passing applicable acceptance cases, **100% passing critical security invariants**, no known critical vulnerabilities and a successful restore rehearsal. A synthetic test or a mocked connector cannot establish production integration correctness.

## Delivery gates
1. Static build + complete unit tests.
2. Real PostgreSQL integration tests with tenant isolation.
3. Webhook authentication, replay, signature and idempotency tests.
4. Manual authorized test plan and evidence screenshots.
5. External tool runtime checks and license review.
6. Multi-format report validation against immutable source evidence.
7. Backup/restore and rollback rehearsal.
8. Deploy exact green main SHA to existing GCE infrastructure; do not modify production PostgreSQL without migration/backup approval.

**Status:** Architecture design and pure handoff contracts added. Full live IR/IDR service, free-tool adapters, webhook execution, image-to-3D verification and end-to-end 95% certification remain open engineering work. Do not present them as complete.
