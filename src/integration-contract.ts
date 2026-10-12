import crypto from 'node:crypto';

export type IntegrationKind='SCANNER'|'CLOUD'|'SIEM'|'EDR'|'FIREWALL'|'REPOSITORY'|'WORKFLOW'|'IDENTITY'|'CUSTOM_API'|'WEBHOOK';
export type IntegrationAvailability='AVAILABLE'|'UNAVAILABLE'|'DISABLED';
export type IntegrationRuntimeState='NOT_CONFIGURED'|'CONFIGURED'|'HEALTHY'|'DEGRADED'|'FAILED'|'UNSUPPORTED'|'DISABLED';
export type CollectionMode='LOCAL_EXECUTION'|'REPORT_IMPORT'|'AUTHENTICATED_API'|'SIGNED_WEBHOOK';
export type AuthMode='NONE'|'API_KEY'|'OAUTH2'|'SERVICE_ACCOUNT'|'TOKEN'|'MTLS'|'LOCAL_EXECUTION'|'WEBHOOK_SIGNATURE';
export type EvidenceProvenance={integrationId:string;integrationKind:IntegrationKind;collectorVersion:string;collectedAt:string;sourceRef:string;sha256:string;verified:boolean;verificationMethod:'LOCAL_EXECUTION'|'AUTHENTICATED_API'|'SIGNED_WEBHOOK'|'IMPORTED_REPORT';limitations:string[]};
export type IntegrationCapability={id:string;name:string;kind:IntegrationKind;auth:AuthMode[];capabilities:string[];availability:IntegrationAvailability;implemented:boolean;collectionModes:CollectionMode[];limitations:string[]};
export type IntegrationRuntimeHealth={integrationId:string;state:IntegrationRuntimeState;checkedAt:string;message?:string};

export const integrationCatalog:ReadonlyArray<IntegrationCapability>=Object.freeze([
 {id:'nmap',name:'Nmap',kind:'SCANNER',auth:['LOCAL_EXECUTION'],capabilities:['NETWORK_DISCOVERY','PORTS','SERVICES'],availability:'AVAILABLE',implemented:true,collectionModes:['LOCAL_EXECUTION'],limitations:[]},
 {id:'zap',name:'OWASP ZAP',kind:'SCANNER',auth:['LOCAL_EXECUTION'],capabilities:['WEB_DAST'],availability:'AVAILABLE',implemented:true,collectionModes:['LOCAL_EXECUTION'],limitations:['Local scanner execution only; no remote authenticated ZAP API collection is claimed']},
 {id:'nuclei',name:'Nuclei',kind:'SCANNER',auth:['LOCAL_EXECUTION'],capabilities:['TEMPLATE_FINDINGS','CVE_SIGNALS'],availability:'AVAILABLE',implemented:true,collectionModes:['LOCAL_EXECUTION'],limitations:[]},
 {id:'trivy',name:'Trivy',kind:'SCANNER',auth:['LOCAL_EXECUTION'],capabilities:['DEPENDENCY_VULNERABILITIES','CONTAINER','MISCONFIGURATION'],availability:'AVAILABLE',implemented:true,collectionModes:['LOCAL_EXECUTION'],limitations:[]},
 {id:'semgrep',name:'Semgrep',kind:'SCANNER',auth:['LOCAL_EXECUTION'],capabilities:['SAST'],availability:'AVAILABLE',implemented:true,collectionModes:['LOCAL_EXECUTION'],limitations:[]},
 {id:'prowler',name:'Prowler',kind:'CLOUD',auth:['NONE'],capabilities:['CLOUD_POSTURE'],availability:'AVAILABLE',implemented:true,collectionModes:['REPORT_IMPORT'],limitations:['Current implementation parses Prowler evidence; authenticated cloud collection is not claimed by this catalog entry']},
 {id:'wazuh',name:'Wazuh',kind:'SIEM',auth:['NONE'],capabilities:['ENDPOINT_ALERTS','SIEM_FINDINGS'],availability:'AVAILABLE',implemented:true,collectionModes:['REPORT_IMPORT'],limitations:['Current ingestion supports evidence/report input; live API verification is not implemented']},
 {id:'openvas',name:'Greenbone/OpenVAS',kind:'SCANNER',auth:['NONE'],capabilities:['VULNERABILITY_MANAGEMENT'],availability:'AVAILABLE',implemented:true,collectionModes:['REPORT_IMPORT'],limitations:['Report import only. No authenticated GMP session, task scheduling, scan execution, polling, or remote collection is implemented']}
]);

export function integrationById(id:string){return integrationCatalog.find(x=>x.id===String(id||'').toLowerCase())||null}
export function assertEvidenceProvenance(x:EvidenceProvenance){if(!integrationById(x.integrationId))throw new Error('Unknown evidence integration');if(!/^[a-f0-9]{64}$/.test(x.sha256))throw new Error('Evidence provenance requires lowercase SHA-256');if(!x.sourceRef||!x.collectorVersion||!x.collectedAt)throw new Error('Evidence provenance is incomplete');if(x.verified&&!['LOCAL_EXECUTION','AUTHENTICATED_API','SIGNED_WEBHOOK','IMPORTED_REPORT'].includes(x.verificationMethod))throw new Error('Invalid evidence verification method');return x}
export function evidenceTrust(x:EvidenceProvenance){assertEvidenceProvenance(x);return x.verified&&x.limitations.length===0?'VERIFIED':x.verified?'VERIFIED_WITH_LIMITATIONS':'UNVERIFIED'}
export function provenanceFingerprint(x:EvidenceProvenance){assertEvidenceProvenance(x);return crypto.createHash('sha256').update(JSON.stringify({integrationId:x.integrationId,collectorVersion:x.collectorVersion,collectedAt:x.collectedAt,sourceRef:x.sourceRef,sha256:x.sha256,verificationMethod:x.verificationMethod})).digest('hex')}
