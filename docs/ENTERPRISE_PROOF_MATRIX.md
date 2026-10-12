# Enterprise Proof Matrix

This matrix distinguishes implemented controls from proof that must be collected in a controlled deployed environment.

| Gap | Automated/repository gate | Deployment/independent evidence |
|---|---|---|
| Authenticated tenant/MFA E2E | Real PostgreSQL registration, TOTP, session, tenant isolation and logout integration test; protected export routes statically gate current-user step-up before tenant report rendering; browser regression checks same-origin session, password/TOTP headers, structured failures and empty-download rejection | Controlled production test accounts still required |
| External integrations | Fail-closed freshness, permission and outage/duplicate-connector tests | Real provider credentials and successful sync evidence required |
| Scanner execution | Production image must contain declared scanner binaries; execution/input-boundary tests | Controlled target scans and finding/retest evidence required |
| Load/performance | 10k-node architecture benchmark; bounded readiness load script | Run optional load smoke on deployed release; larger capacity test for sizing |
| Backup/recovery/faults | Isolated disposable PostgreSQL restore drill and backup-first deployment assertions | Execute restore drill on current backup; operational RTO/RPO exercise for formal SLA |
| Supply chain | npm high+ audit, Gitleaks, SBOM and Trivy CRITICAL image gate; dependency resolution is not yet lockfile-pinned | Review/retain SBOM artifact per release |
| Independent security | Claim boundary test and required assessment scope | Independent assessor report and retest required |
| Architecture accuracy | Large deterministic benchmark and fail-closed external accuracy qualification | Representative independently labelled corpus required for accuracy claim |
| CSP/browser hardening | CSP baseline now enforces self-only defaults/connections, no object embedding, no framing, self-only base/form actions and upgrade-insecure-requests; production-boundary regression test enforced | Remove unsafe-inline only through dedicated nonce/hash migration with browser regression testing |

AegisGRC must not convert a missing external evidence item into a PASS. A 95+ internal engineering milestone can be reported only with the exact scope of automated gates stated. A 95+ independently validated enterprise claim requires the external evidence column as well.


## Latest verified repository release gate

Commit `e7fa47d91509fd6406f5ce6511fbe7ec395d601e` passed Aegis Build, AegisGRC CI and the hardened `verify` workflow. The verify workflow passed TypeScript build, full test suite, production dependency audit, secret scan and exact production image build, CycloneDX SBOM generation, Trivy CRITICAL image scan, bundled security-engine verification and SBOM upload. This is repository/CI evidence only; it is not a substitute for the deployment/independent evidence column above.
