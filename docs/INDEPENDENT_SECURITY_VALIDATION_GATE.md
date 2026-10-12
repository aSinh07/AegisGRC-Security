# AegisGRC Independent Security Validation Gate

AegisGRC must not claim an independent penetration test merely because its internal security tests pass.

## Required independent scope before an externally stated 95+ enterprise validation claim

An assessor who did not implement the tested controls must validate, at minimum:

- authentication, password reset, TOTP enrollment/login/recovery boundaries and session invalidation;
- organization/tenant isolation, RBAC, IDOR/BOLA and cross-tenant object access;
- Evidence Vault upload, integrity state, independent validation, custody history and forged evidence rejection;
- TPRM closure gates and approval separation;
- report authentication, export authorization and approval/snapshot integrity;
- SSRF/DNS rebinding and scanner target restrictions;
- file/document upload parsing and content-type/size boundaries;
- injection classes relevant to the HTTP/API surface;
- CSRF/cross-site state-change protections and browser security policy;
- scanner job authorization, command/option injection boundaries and controlled workspace mounts;
- AI/copilot authorization boundaries and untrusted-content handling;
- rate/abuse behavior and denial-of-service observations.

## Evidence required

Record assessor identity/organization, dates, exact release SHA, environment, scope, methodology, findings, retest status, exclusions and final report digest.

**Fail-closed rule:** until that evidence exists, product language may say "internal automated security gates passed" but must not say "independently penetration tested", "100% secure", or equivalent.
