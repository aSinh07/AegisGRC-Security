# Enterprise Proof Matrix

This matrix distinguishes implemented controls from proof that must be collected in a controlled deployed environment.

| Gap | Automated/repository gate | Deployment/independent evidence |
|---|---|---|
| Authenticated tenant/MFA E2E | Real PostgreSQL registration, TOTP, session, tenant isolation and logout integration test | Controlled production test accounts still required |
| External integrations | Fail-closed freshness, permission and outage/duplicate-connector tests | Real provider credentials and successful sync evidence required |
| Scanner execution | Production image must contain declared scanner binaries; execution/input-boundary tests | Controlled target scans and finding/retest evidence required |
| Load/performance | 10k-node architecture benchmark; bounded readiness load script | Run optional load smoke on deployed release; larger capacity test for sizing |
| Backup/recovery/faults | Isolated disposable PostgreSQL restore drill and backup-first deployment assertions | Execute restore drill on current backup; operational RTO/RPO exercise for formal SLA |
| Supply chain | npm high+ audit, Gitleaks, SBOM, Trivy CRITICAL image gate, reproducible npm ci | Review/retain SBOM artifact per release |
| Independent security | Claim boundary test and required assessment scope | Independent assessor report and retest required |
| Architecture accuracy | Large deterministic benchmark and fail-closed external accuracy qualification | Representative independently labelled corpus required for accuracy claim |
| CSP/browser hardening | Existing CSP/security-header tests | Remove unsafe-inline only through dedicated nonce/hash migration with browser regression testing |

AegisGRC must not convert a missing external evidence item into a PASS. A 95+ internal engineering milestone can be reported only with the exact scope of automated gates stated. A 95+ independently validated enterprise claim requires the external evidence column as well.
