# External Security Review Scope

This document prepares an independent reviewer to assess AegisGRC without treating internal test results as independent assurance.

## In scope
Authentication and TOTP enrollment/recovery; tenant and assessment authorization; report step-up authentication; evidence integrity and approval separation; public/private asset boundaries; scanner-job authorization and target validation; SSRF/DNS-rebinding defenses; scanner execution limits; report and export access; API input limits; PostgreSQL isolation; container hardening; security headers; audit trails; CI/release controls; backup/restore and operational monitoring.

## Required reviewer tests
Perform authenticated and unauthenticated authorization tests, cross-tenant object access attempts, session/recovery abuse cases, input-boundary testing, safe SSRF validation against controlled infrastructure, report authorization bypass attempts, scanner scope validation, dependency/container review, configuration review, and business-logic review of evidence approval and GRC assurance claims.

## Evidence requested from reviewer
For every finding record severity, affected component, reproducible evidence, preconditions, impact, remediation recommendation, and retest result. Record tool versions and assessment date. Do not mark a finding closed until retest evidence exists.

## Rules of engagement
Only explicitly authorized targets are permitted. Avoid destructive testing, denial-of-service, production data modification, persistence, credential harvesting, or third-party targeting. Coordinate load testing separately with bounded limits.

## Acceptance
Critical and High findings are release blockers until remediated and independently retested. Medium findings require remediation or documented risk acceptance with owner and due date. Low/Informational findings are tracked. Completion of this scope is not certification; the independent review report and retest evidence are the assurance artifacts.
