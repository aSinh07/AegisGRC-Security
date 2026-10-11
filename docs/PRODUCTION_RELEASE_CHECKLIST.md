# Production Release Checklist

This checklist is evidence-oriented; passing it does not guarantee security, legal compliance, or ISO certification.

## Before deployment
- Exact release commit has green Aegis Build, AegisGRC CI, and verify workflows.
- `.env.production` contains non-placeholder secrets and is not committed.
- Preserve `aegis-db`; never deploy with `docker compose down -v`.
- Preserve the existing `REPORT_SIGNING_KEY` or previously signed reports will no longer verify with the same key.
- Confirm the VM has enough disk space for the scanner-heavy Docker image and PostgreSQL backup.
- Confirm DNS for the production hostname resolves to the intended VM and Caddy still terminates HTTPS.

## Deployment acceptance
- `/api/ready` returns HTTP 200 and `"mode":"postgres"`.
- `/api/health` returns expected scanner availability; unavailable optional scanners are not treated as successful coverage.
- Existing user login and TOTP work after deployment.
- Existing assessment/evidence records remain present.
- Create a controlled authorized assessment and verify queue → evidence → finding → report flow.
- Verify GRC recommendation remains advisory and issue promotion requires analyst confirmation.
- Verify framework outputs identify version/source/effective-date limitations and do not claim external certification.

## Rollback
If readiness or smoke tests fail, inspect application/PostgreSQL logs first. Re-deploy the previously known-good Git commit without deleting the `aegis-db` volume. Restore the pre-deploy PostgreSQL dump only when a database migration/data problem actually requires restoration; restoration is destructive and should not be the first rollback action.

## Certification boundary
AegisGRC can support readiness assessment, evidence organization, control testing, CAPA, and audit preparation. Accredited ISO/IEC 27001 or ISO/IEC 42001 certification requires an independent accredited certification body and is not granted by this software or by passing its automated tests.
