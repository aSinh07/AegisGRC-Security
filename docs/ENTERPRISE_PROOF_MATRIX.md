# Enterprise Proof Matrix

This matrix distinguishes implemented controls from proof that must be collected in a controlled deployed environment.

| Gap | Automated/repository gate | Deployment/independent evidence |
|---|---|---|
| Authenticated tenant/MFA E2E | Real PostgreSQL registration, TOTP, session, tenant isolation and logout integration test; protected export routes statically gate current-user step-up before tenant report rendering; browser regression checks same-origin session, password/TOTP headers, structured failures and empty-download rejection | Controlled production test accounts still required |
| External integrations | Fail-closed freshness, permission and outage/duplicate-connector tests | Real provider credentials and successful sync evidence required |
| Scanner execution | Production image must contain declared scanner binaries; execution/input-boundary tests | Controlled target scans and finding/retest evidence required |
| Load/performance | 10k-node architecture benchmark; bounded readiness load script | Run bounded load smoke on the deployed release; production sizing still requires representative authenticated workload and concurrency |
| Database connection scale | Runtime GRC modules use one bounded shared PostgreSQL pool with connection/idle/lifetime limits and regression gating | Tune DB_POOL_MAX from measured production workload and PostgreSQL capacity; validate saturation/queue latency under representative authenticated load |\n| HTTP lifecycle | API request IDs, no-store responses, bounded body size, request/header/keep-alive timeouts, malformed-body handling and SIGTERM/SIGINT connection draining are regression gated | Validate behavior behind the production Caddy/GCE path under representative load and rolling restart |\n| Backup/recovery/faults | Isolated disposable PostgreSQL restore drill and backup-first deployment assertions | Execute restore drill on current backup; operational RTO/RPO exercise for formal SLA |
| Supply chain | npm high+ audit, Gitleaks, SBOM and Trivy CRITICAL image gate; dependency resolution is pinned by package-lock.json and installed with npm ci | Review/retain SBOM artifact per release |
| Independent security | Claim boundary test and required assessment scope | Independent assessor report and retest required |
| Architecture accuracy | Large deterministic benchmark and fail-closed external accuracy qualification | Representative independently labelled corpus required for accuracy claim |
| CSP/browser hardening | CSP baseline now enforces self-only defaults/connections, no object embedding, no framing, self-only base/form actions and upgrade-insecure-requests; production-boundary regression test enforced | Caddy still permits style-src unsafe-inline; removing it requires a separately deployed proxy-policy change and browser regression testing |

AegisGRC must not convert a missing external evidence item into a PASS. A 95+ internal engineering milestone can be reported only with the exact scope of automated gates stated. A 95+ independently validated enterprise claim requires the external evidence column as well.


## Release-candidate verification rule\n\nThe deployable commit is the final `main` revision for which Aegis Build, AegisGRC CI and `verify` all complete successfully. Repository/CI evidence is not a substitute for the deployment/independent evidence column above.\n