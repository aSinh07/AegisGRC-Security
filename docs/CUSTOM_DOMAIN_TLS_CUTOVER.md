# Production Domain and TLS Cutover

A custom domain is an external infrastructure action; this checklist prevents the application release from depending on a specific DNS provider.

1. Create the DNS A/AAAA record for the approved production hostname pointing only to the production ingress address.
2. Configure the Caddy site label for that exact hostname. Keep the application bound to loopback; do not expose port 8080 publicly.
3. Allow Caddy to obtain/renew the public certificate and verify the certificate SAN matches the hostname.
4. Set the public application origin/configuration to the HTTPS custom origin where applicable and keep `COOKIE_SECURE=true`.
5. Run `scripts/production-acceptance.sh` against the HTTPS hostname.
6. Verify HSTS, CSP, frame denial, no-sniff, referrer policy, and anonymous protection of `/index.html` and protected assets.
7. Verify MFA login, logout, password recovery, one real assessment, reviewer-only operational health, and one step-up protected report download.
8. Keep the previous DNS hostname available only for the agreed rollback window, then retire it deliberately.

Do not delete/recreate PostgreSQL or its named volume during a domain cutover. DNS/TLS changes and application rollback are independent of database recovery.
