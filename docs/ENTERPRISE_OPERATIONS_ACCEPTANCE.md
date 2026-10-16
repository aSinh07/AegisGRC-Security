# Enterprise Operations Acceptance

This runbook defines evidence required before an AegisGRC release is described as production-ready. It does not constitute certification or independent assurance.

## Release evidence
- Exact Git commit is recorded.
- Aegis Build, AegisGRC CI, and verify workflows succeed for that exact commit.
- SBOM and production-image vulnerability scan are retained by CI.
- `scripts/production-acceptance.sh` passes against the deployed endpoint.

## Backup and restore drill
Production PostgreSQL is never dropped or recreated for a drill. Create a logical backup with `pg_dump` from the running database, record its SHA-256, restore it only into a temporary isolated PostgreSQL instance/database, run `pg_isready`, schema/table-count checks, and representative read-only queries, then destroy only the temporary restore target. Record start/end time, backup hash, restore result, operator, and release commit.

Recommended targets: RPO <= 24 hours for scheduled backups and RTO <= 4 hours until measured operational data supports tighter objectives. These are operational targets, not guarantees.

## Load and soak acceptance
CI provides a bounded concurrency smoke gate. Before a major enterprise release, run a longer authorized test against a non-destructive readiness endpoint and record request count, concurrency, elapsed time, non-2xx count, p95/p99 latency, application memory/CPU, PostgreSQL connection saturation, and restarts. Zero failed readiness requests and zero unexpected restarts are release blockers.

## Monitoring and alert evidence
Monitor public readiness, container restart count, CPU/memory/disk pressure, PostgreSQL health/connection pressure, HTTP 5xx rate, authentication 429/401 anomalies, scanner queue depth, scanner failures/timeouts, and TLS certificate expiry. Alerts require an owner, severity, acknowledgement path, and tested escalation.

## Scanner isolation
Active scanners operate only on explicitly authorized targets. Scanner jobs are tenant-bound, bounded by leases/attempts/timeouts/output limits, and revalidate public DNS immediately before execution. Production deployments should isolate active scanner workers from the web process and deny scanner-worker access to PostgreSQL except through the application-controlled evidence handoff. Network egress should be restricted to authorized public targets where infrastructure supports enforcement.

## Disaster recovery
Keep deployment rollback instructions and database recovery independent. Application rollback must not replace or recreate the PostgreSQL volume. Record last successful restore drill, configuration prerequisites, secret recovery ownership, DNS/TLS recovery steps, and RTO/RPO observations.

## Independent assurance
A qualified reviewer should perform an external penetration/security assessment after material architecture changes. Findings must be tracked to remediation and retest evidence. AegisGRC reports and this runbook are not a substitute for independent audit or certification.
