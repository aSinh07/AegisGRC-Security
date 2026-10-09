import type { Finding } from './models.js';

export type ControlAssessment={control:string;status:'GAP'|'OBSERVED'|'NOT_TESTED';findings:string[];evidence:string[];rationale:string;requiredEvidence:string};
type Rule={control:string;match:(f:Finding)=>boolean;rationale:string;requiredEvidence:string};
const txt=(f:Finding)=>(f.title+' '+f.description+' '+(f.cwe||'')).toLowerCase();
const any=(...p:RegExp[])=>(f:Finding)=>p.some(x=>x.test(txt(f)));

const rules:Record<string,Rule[]>={
 ISO27001:[
  {control:'A.5.15 Access control',match:any(/auth|access|permission|session|authorization/),rationale:'Access-control evidence indicates a control condition requiring review.',requiredEvidence:'Access policy, role matrix, authentication configuration and retest evidence.'},
  {control:'A.8.5 Secure authentication',match:any(/auth|login|password|session|mfa|totp/),rationale:'Authentication-related findings map to secure authentication implementation.',requiredEvidence:'Authentication configuration, MFA evidence, session controls and successful retest.'},
  {control:'A.8.8 Management of technical vulnerabilities',match:any(/vulnerab|cve|open port|service|xss|sql|injection|tls|header|misconfig|exposure/),rationale:'Technical assessment evidence identified an exposure or vulnerability-management input.',requiredEvidence:'Scanner evidence, asset owner, treatment decision, remediation ticket and clean retest.'},
  {control:'A.8.9 Configuration management',match:any(/header|configuration|misconfig|csp|hsts|server technology|open port/),rationale:'Observed configuration/hardening conditions require configuration-management review.',requiredEvidence:'Approved baseline, configuration evidence, exception record if applicable and retest.'},
  {control:'A.8.20 Networks security',match:any(/port|network|service|firewall|dns|tcp/),rationale:'Network/service exposure is relevant to network security controls.',requiredEvidence:'Network diagram, firewall/security-group rules, service owner and exposure validation.'},
  {control:'A.8.24 Use of cryptography',match:any(/tls|crypto|certificate|https|cleartext/),rationale:'Transport or cryptographic evidence is relevant to cryptographic control implementation.',requiredEvidence:'TLS configuration, certificate evidence, cryptographic standard and retest.'},
  {control:'A.8.26 Application security requirements',match:any(/xss|sql|injection|application|web|cwe-79|cwe-89/),rationale:'Application-security findings require review against application security requirements.',requiredEvidence:'Security requirements, test evidence, remediation record and application retest.'},
  {control:'A.8.28 Secure coding',match:any(/xss|sql|injection|semgrep|source|code|cwe/),rationale:'Code/application weakness evidence is relevant to secure coding practices.',requiredEvidence:'Source finding, code review/fix reference, secure coding standard and verification scan.'}
 ],
 NIST_CSF:[
  {control:'ID.RA',match:any(/./),rationale:'Assessment findings are inputs to cybersecurity risk assessment.',requiredEvidence:'Risk record, affected asset, likelihood/impact rationale and treatment decision.'},
  {control:'PR.AA',match:any(/auth|access|session|password|permission/),rationale:'Identity and access evidence relates to identity management, authentication and access control.',requiredEvidence:'Identity configuration, access matrix and authentication/retest evidence.'},
  {control:'PR.PS',match:any(/configuration|misconfig|vulnerab|patch|header|service|port/),rationale:'Platform security findings relate to secure configuration and vulnerability handling.',requiredEvidence:'Configuration baseline, patch/treatment record and retest evidence.'},
  {control:'PR.DS',match:any(/tls|crypto|https|data|cleartext/),rationale:'Data security evidence relates to protection of data in transit/processing.',requiredEvidence:'Data-flow evidence, encryption configuration and validation.'}
 ],
 CIS:[
  {control:'4 Secure Configuration of Enterprise Assets and Software',match:any(/configuration|header|misconfig|service|port/),rationale:'Observed hardening conditions map to secure configuration safeguards.',requiredEvidence:'Secure baseline, configuration proof and retest.'},
  {control:'7 Continuous Vulnerability Management',match:any(/vulnerab|cve|scan|service|port|xss|sql|injection/),rationale:'Technical findings are vulnerability-management inputs.',requiredEvidence:'Scan evidence, remediation ownership, SLA/treatment and clean retest.'},
  {control:'16 Application Software Security',match:any(/xss|sql|injection|application|semgrep|source|code/),rationale:'Application/source findings relate to secure software practices.',requiredEvidence:'Application test/source evidence, fix reference and verification.'}
 ],
 OWASP:[
  {control:'A01:2025 Broken Access Control',match:any(/access|authorization|permission|idor/),rationale:'Access-control weakness evidence maps to broken access control.',requiredEvidence:'Request/response or authorization evidence and retest.'},
  {control:'A04:2025 Cryptographic Failures',match:any(/tls|crypto|cleartext|https/),rationale:'Cryptographic/transport weakness evidence maps to cryptographic failures.',requiredEvidence:'TLS/cryptographic configuration and retest.'},
  {control:'A05:2025 Injection',match:any(/sql|injection|xss|cwe-79|cwe-89/),rationale:'Injection-family evidence maps to injection risk.',requiredEvidence:'Scanner/request evidence, affected parameter/code and clean retest.'},
  {control:'A02:2025 Security Misconfiguration',match:any(/header|configuration|misconfig|csp|hsts|server technology/),rationale:'Configuration evidence maps to security misconfiguration.',requiredEvidence:'Configuration baseline and retest.'}
 ],
 PCI:[
  {control:'6.3 Security vulnerabilities',match:any(/vulnerab|cve|scan|xss|sql|injection/),rationale:'Technical vulnerabilities are relevant to vulnerability identification and treatment.',requiredEvidence:'In-scope system evidence, vulnerability record, treatment and retest.'},
  {control:'6.2 Secure software development',match:any(/xss|sql|injection|source|code|semgrep/),rationale:'Application/source findings relate to secure software development.',requiredEvidence:'Development control evidence, fix and verification.'},
  {control:'7 Restrict access',match:any(/access|authorization|permission/),rationale:'Access findings relate to restriction of access.',requiredEvidence:'Role/access matrix and access-control validation.'},
  {control:'8 Identify users and authenticate access',match:any(/auth|login|password|session|mfa/),rationale:'Authentication evidence relates to user identification and authentication.',requiredEvidence:'Identity/MFA configuration and authentication test evidence.'}
 ],
 GDPR:[
  {control:'Art. 32 Security of processing',match:any(/tls|crypto|access|auth|vulnerab|security|data/),rationale:'Security findings may affect technical and organisational security measures where personal data is in scope.',requiredEvidence:'Personal-data scope, risk assessment, technical control evidence and treatment.'}
 ],
 DPDP:[
  {control:'Section 8 reasonable security safeguards',match:any(/tls|crypto|access|auth|vulnerab|security|data/),rationale:'Security findings may be relevant where digital personal data is in scope.',requiredEvidence:'Data scope, safeguard evidence, risk/treatment record and retest.'}
 ],
 HIPAA:[
  {control:'164.312(a) Access control',match:any(/access|auth|permission|session/),rationale:'Access evidence may be relevant where ePHI systems are in scope.',requiredEvidence:'ePHI scope, access-control configuration and validation.'},
  {control:'164.312(e) Transmission security',match:any(/tls|https|crypto|cleartext/),rationale:'Transport-security evidence may be relevant where ePHI is transmitted.',requiredEvidence:'ePHI data flow, transmission protection configuration and validation.'}
 ],
 ISO42001:[
  {control:'A.5 Assessing impacts of AI systems',match:any(/ai|llm|model|prompt/),rationale:'AI-system evidence requires impact assessment consideration.',requiredEvidence:'AI system inventory, impact assessment and treatment evidence.'},
  {control:'A.6 AI system life cycle',match:any(/ai|llm|model|prompt/),rationale:'AI-system evidence relates to lifecycle governance.',requiredEvidence:'Lifecycle controls, ownership, testing and monitoring evidence.'}
 ],
 NIST_AI_RMF:[
  {control:'MAP',match:any(/ai|llm|model|prompt/),rationale:'AI-system evidence contributes to context and risk mapping.',requiredEvidence:'AI context, intended use, stakeholders and impact evidence.'},
  {control:'MEASURE',match:any(/ai|llm|model|prompt/),rationale:'AI-system evidence requires measurement and evaluation.',requiredEvidence:'Test methodology, metrics, results and limitations.'},
  {control:'MANAGE',match:any(/ai|llm|model|prompt/),rationale:'AI risk evidence requires treatment and prioritization.',requiredEvidence:'Risk treatment, owner, acceptance criteria and monitoring.'}
 ],
 SOC2:[
  {control:'CC6 Logical and Physical Access Controls',match:any(/auth|access|permission|session/),rationale:'Access findings relate to logical access control criteria.',requiredEvidence:'Access policy/configuration and validation.'},
  {control:'CC7 System Operations',match:any(/vulnerab|scan|incident|monitor|service|port/),rationale:'Technical security findings are relevant to system operations and vulnerability response.',requiredEvidence:'Monitoring/vulnerability process, ticket, owner and retest.'}
 ]
};

export function assessFramework(frameworkId:string,findings:Finding[]):ControlAssessment[]{
 const rs=rules[frameworkId]||[];
 return rs.map(r=>{
  const hit=findings.filter(r.match);
  // Scanner observations are review inputs, not proof that an organizational control failed.
  // In particular, an open port or informational observation is not a vulnerability by itself.
  const actionable=hit.filter(f=>f.severity!=='INFO'&&f.status!=='FALSE_POSITIVE'&&f.status!=='ACCEPTED'&&f.status!=='REMEDIATED'&&f.source!=='nmap');
  const status:ControlAssessment['status']=actionable.length?'GAP':hit.length?'OBSERVED':'NOT_TESTED';
  const rationale=actionable.length
   ? 'Potential technical control gap identified by automated evidence; analyst verification and organizational control review required. This is not a conformity determination.'
   : hit.length
    ? 'Relevant technical observations exist, but available evidence does not establish a failed control. Validate applicability and obtain further evidence.'
    : 'No relevant technical evidence was collected for this control. Untested does not mean compliant.';
  return {control:r.control,status,findings:hit.map(x=>x.id),evidence:[...new Set(hit.map(x=>x.evidenceHash).filter(Boolean))],rationale,requiredEvidence:r.requiredEvidence};
 })
}
export function controlRefs(frameworkId:string,f:Finding[]){return assessFramework(frameworkId,f).filter(x=>x.findings.length)}
