export type CapabilityMode='NATIVE'|'EVIDENCE_IMPORT'|'CONNECTOR_READY';
export type SecurityDomain='OFFENSIVE'|'DEFENSIVE';

export type SecurityCapability={
 id:string; domain:SecurityDomain; category:string; mode:CapabilityMode;
 engines:string[]; purpose:string; authorizationRequired:boolean;
};

export const securityCapabilityCatalog:SecurityCapability[]=[
 {id:'attack-surface',domain:'OFFENSIVE',category:'Attack Surface',mode:'NATIVE',engines:['Nmap','Nuclei','testssl.sh'],purpose:'Network, service, TLS and exposed-surface discovery',authorizationRequired:true},
 {id:'web-dast',domain:'OFFENSIVE',category:'Web / API DAST',mode:'NATIVE',engines:['OWASP ZAP','Wapiti','Nuclei'],purpose:'Dynamic application and API vulnerability assessment',authorizationRequired:true},
 {id:'sqli-validation',domain:'OFFENSIVE',category:'Injection Validation',mode:'NATIVE',engines:['SQLmap'],purpose:'Controlled SQL injection validation against explicitly authorized targets',authorizationRequired:true},
 {id:'source-sast',domain:'OFFENSIVE',category:'Source / SAST',mode:'NATIVE',engines:['Semgrep','Trivy','Gitleaks'],purpose:'Static analysis, dependency and secret-risk discovery',authorizationRequired:true},
 {id:'infra-vulnerability',domain:'OFFENSIVE',category:'Infrastructure Vulnerability',mode:'EVIDENCE_IMPORT',engines:['Greenbone/OpenVAS'],purpose:'Infrastructure vulnerability evidence ingestion and correlation',authorizationRequired:true},
 {id:'manual-pentest',domain:'OFFENSIVE',category:'Manual Penetration Testing',mode:'EVIDENCE_IMPORT',engines:['Analyst evidence','Finding import'],purpose:'Preserve manual validation evidence, analyst decisions and retest traceability',authorizationRequired:true},
 {id:'commercial-offensive',domain:'OFFENSIVE',category:'Commercial / External Platforms',mode:'CONNECTOR_READY',engines:['Burp Suite Enterprise','Tenable','Qualys','Rapid7 InsightVM','Acunetix/Invicti'],purpose:'Adapter boundary for licensed external scanners; credentials and vendor APIs are required before status can become connected',authorizationRequired:true},

 {id:'endpoint-defense',domain:'DEFENSIVE',category:'Endpoint / Detection',mode:'EVIDENCE_IMPORT',engines:['Wazuh'],purpose:'Endpoint posture, security telemetry and breach evidence',authorizationRequired:false},
 {id:'cloud-posture',domain:'DEFENSIVE',category:'Cloud Security Posture',mode:'NATIVE',engines:['Prowler'],purpose:'AWS, Azure and GCP configuration, IAM, encryption and exposure posture',authorizationRequired:false},
 {id:'host-hardening',domain:'DEFENSIVE',category:'Host Hardening',mode:'NATIVE',engines:['Lynis'],purpose:'Server and host hardening assessment',authorizationRequired:false},
 {id:'container-supply-chain',domain:'DEFENSIVE',category:'Container / Supply Chain',mode:'NATIVE',engines:['Trivy','Grype','Syft'],purpose:'Vulnerability, SBOM and dependency assurance',authorizationRequired:false},
 {id:'kubernetes-iac',domain:'DEFENSIVE',category:'Kubernetes / IaC',mode:'NATIVE',engines:['Kubescape','Checkov'],purpose:'Cluster and infrastructure-as-code posture validation',authorizationRequired:false},
 {id:'defense-operations',domain:'DEFENSIVE',category:'Risk Reduction',mode:'NATIVE',engines:['Finding correlation','Exposure prioritization','CAPA','Retest'],purpose:'Prioritize, remediate, retest and govern observed exposure',authorizationRequired:false},
 {id:'commercial-defense',domain:'DEFENSIVE',category:'SIEM / EDR / ITSM Ecosystem',mode:'CONNECTOR_READY',engines:['Microsoft Sentinel','Microsoft Defender','CrowdStrike','Splunk','ServiceNow'],purpose:'Adapter boundary for enterprise telemetry and workflow systems; never reported as connected until health is observed',authorizationRequired:false}
];

export function capabilitiesFor(domain:SecurityDomain){return securityCapabilityCatalog.filter(x=>x.domain===domain)}
export function capabilitySummary(domain:SecurityDomain){const rows=capabilitiesFor(domain);return {
 total:rows.length,
 native:rows.filter(x=>x.mode==='NATIVE').length,
 evidenceImport:rows.filter(x=>x.mode==='EVIDENCE_IMPORT').length,
 connectorReady:rows.filter(x=>x.mode==='CONNECTOR_READY').length
}}
