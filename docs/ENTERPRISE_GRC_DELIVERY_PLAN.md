# AegisGRC — Enterprise GRC delivery contract (10-day proof / 15-day target)

Status: engineering plan; NOT a certification, penetration-test result, or claim of production readiness.

## Product objective
Build an operational GRC workspace inspired by the *publicly documented patterns* of Scrut (evidence tasks, reusable controls, automated tests, audits) and ServiceNow IRM (policy/control hierarchy, indicators, issues, remediation, assignments, approvals). Do not copy proprietary code or UI. Prioritize GRC; defer pentesting changes.

## Release blockers identified in current repository
1. **Cross-tenant data exposure:** GET /api/grc/risks without organizationId lists global risks; /api/grc/dashboard aggregates globally. Authentication alone is not authorization. Block production use until every GRC read/write enforces organization membership and scope.
2. **Unauthorized mutation:** POST /api/grc/workflow/transitions accepts arbitrary record IDs, state and actor-supplied payload, with no state-machine/role validation. Restrict or disable until server-owned transitions exist.
3. **Unverified control effectiveness:** PATCH /api/grc/control-assessments/:id accepts client-supplied evidenceStatus/designEffectiveness/operatingEffectiveness. A user can self-assert EFFECTIVE without evidence/reviewer. Results must derive from signed test results and validated evidence.
4. **Incomplete record creation:** organizations, scopes and controls tables exist but no authenticated CRUD/ownership lifecycle. Current assessment creation cannot work end-to-end from UI.
5. **Risk acceptance without approval:** treatment=ACCEPT is accepted as input; it must require accountable approver, residual risk, expiry and separation of duties.
6. **Mutable review approval:** existing grc_report_reviews upserts reset status/history; approval hash is not bound to immutable evidence/report/control-version snapshot.
7. **Evidence integrity:** evidence records need source identifiers, tenant binding, object storage, immutable versions, timestamps, collection errors, reviewer status, hash verification, expiry and retention.
8. **Misleading framework claims:** regex-based finding-to-control mapping is not full control testing. No default PASS for untested requirements; URL evidence cannot establish organizational compliance.
9. **Unsafe scoring:** control dashboard metrics are unscoped and can imply a compliance percentage without applicability and test coverage. Never report a certified score.
10. **Database deployment safety:** runtime CREATE TABLE IF NOT EXISTS is not a controlled migration. Introduce versioned migrations, backups, rollbacks, indexes and constraints. DB SSL defaults must be appropriate for actual deployment.
11. **No demonstrated integration verification:** real connector success needs auth scopes, successful API calls, timestamps, evidence payload, failure states, and automated integration tests.
12. **No current end-to-end validation:** commit existence is not proof that build, auth, UI, PDF, database, or production deployment works.

## Non-negotiable data model
Organization → Members/Roles → Scope/Assets → Framework Requirement → Canonical Control → Control Implementation → Evidence Task → Evidence Version → Test Definition → Test Execution/Result → Issue → Risk → Treatment/CAPA → Retest → Independent Approval → Audit Package.

Every tenant-owned row MUST include organization_id or be reachable via enforced tenant-safe joins. Add composite foreign keys or row-level security where practical.

## Workflow rules
- Never allow arbitrary transitions. Define allowed from→to per record type, role, guard, and required evidence.
- Separate author, owner, tester and approver. No self-approval of high-risk closure or risk acceptance.
- Use transactionally persisted state changes + append-only audit events + idempotency keys.
- Failed control test may open an issue; repeat failures deduplicate by tenant/control/test/fingerprint.
- Issue closure requires completed remediation, passing retest (or formally approved exception), and reviewer approval.
- Exception must have rationale, compensating control, risk owner, approver, expiry, reassessment.
- Evidence freshness and control test status are distinct; missing evidence is NOT_TESTED, never PASS.
- Preserve manual review for policy, HR, training, governance and other non-automatable controls.

## Professional report acceptance contract
Reports must contain: title/organization/scope/period; document ID and version; methodology; framework edition and licensed-content disclaimer; applicability/SoA; control-by-control status with test coverage; evidence provenance; risk register; issue/CAPA register; exception register; independent reviewer/approval record; limitations; management summary; evidence appendix and reproducible timestamps. 
Separate **Technical Test Passed** from **Control Effective** and **Audit Ready**. Mark drafts and unapproved reports clearly. Only approved reports may display an internal approval badge; never claim third-party certification.

## Architecture
- Existing Node/TypeScript Express: authentication, authorization, tenant-safe API, workflows, audit events, PDF/DOCX/XLSX export.
- PostgreSQL: canonical source of truth, versioned migrations, constraints, tenant isolation, transactions, indexes.
- Python workers (optional, useful for team): FastAPI or worker process for read-only cloud/SaaS evidence connectors, deterministic normalization, document parsing and scheduled control tests. Python workers must never independently approve compliance or bypass tenant policies.
- Queue: PostgreSQL-backed job queue initially; workers process scheduled evidence/test jobs with retries, idempotency and dead-letter status.
- UI: role-specific GRC workspace (My Work, Controls, Evidence, Risks, Issues, CAPA, SoA, Audits, Reports). Every card drills into real database records. Never seed fake production data.

## 10-day vertical-slice plan
Day 1: Freeze GRC scope, run build/tests, inventory routes; fix cross-tenant access and disable unsafe mutation.
Day 2: Organization onboarding, memberships, role checks, scope CRUD, tenant-safe repository layer.
Day 3: Versioned framework catalog, canonical controls, mappings, applicability/SoA with owner/justification.
Day 4: Evidence tasks, secure upload, version/hash/provenance/expiry, owner assignment.
Day 5: Deterministic control tests with real sample evidence; execution history, failure/NOT_TESTED semantics.
Day 6: Risk register + issue creation/dedup, links to controls and evidence.
Day 7: ServiceNow-style My Work workflow: assignment, review, CAPA, state guards, audit trail.
Day 8: Professional ISO 27001 readiness report PDF/DOCX with SoA, control matrix, issues, risks, approvals and limitations.
Day 9: Integrated role-based UI, dashboard with drilldowns; no placeholder buttons or fictitious scores.
Day 10: E2E demo with two organizations, two users and independent reviewer; verify isolation, negative tests, exports, persistence and clean retest.

Days 11–15 (contingency / expansion): GitHub read-only evidence connector; scheduled monitoring; auditor workspace; accessibility, performance, threat modeling, operational backup/restore, security fixes and staged deployment.

## Demo acceptance tests (must be reproducible)
1. Register Org A and Org B; Org B cannot list, mutate, download or infer Org A records.
2. Org A control owner creates a control implementation and evidence task; uploads genuine evidence; audit history retains original version.
3. Deterministic test executes with defined expected input; valid test FAIL opens a linked issue and remediation.
4. Owner submits fix; retest passes; independent reviewer approves closure. Invalid transitions and self-approval return 403/409.
5. Expired evidence makes control status NOT_TESTED or REVIEW_REQUIRED; never PASS.
6. Risk acceptance requires a distinct authorized approver and expiry.
7. ISO 27001 SoA/report reflects actual scope, applicability, evidence, risks, issues, exceptions, and reviewer state; no fabricated certification.
8. Restart services; all records and versions persist.
9. Invalid connector credentials show ERROR, never CONNECTED/REAL.
10. Run automated tests and produce recorded output; build and API smoke tests pass before deploying.

## Stop-ship criteria
Any cross-tenant leak, arbitrary approval, fabricated evidence/result, self-approved high-risk closure, report claiming certification, or inability to reproduce the demo means do not deploy as customer-ready.

## References reviewed (public)
- https://www.scrut.io/platform/compliance-automation
- https://help.scrut.io/docs/evidence-automation-workflow
- https://help.scrut.io/docs/evidence-tasks-walkthrough
- https://www.servicenow.com/in/products/policy-compliance-management.html
- https://www.servicenow.com/community/grc-articles/irm-policy-and-compliance-management-architecture-and-data-model/ta-p/3605503

This document defines engineering acceptance criteria, not a statement that the features are already implemented.
