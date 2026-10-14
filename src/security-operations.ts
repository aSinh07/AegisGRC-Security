import type {Assessment,Finding,Evidence} from './models.js';
import {ASSESSMENT_LAYERS} from './assessment-coverage.js';
import {scannerPlan,type AssetType} from './scanner-orchestration.js';

export const SECURITY_DOMAINS=[
 {id:'WEB_API',label:'Web & API Security',assetTypes:['WEB_APP','API'],topics:['attack surface','authentication/session exposure','injection and input handling','TLS/headers','known exposures']},
 {id:'NETWORK_INFRA',label:'Network & Infrastructure',assetTypes:['DOMAIN','IP','HOST','SERVER','NETWORK_DEVICE'],topics:['ports/services','host vulnerabilities','hardening','network exposure','service configuration']},
 {id:'CLOUD',label:'Cloud Security',assetTypes:['CLOUD_ACCOUNT','STORAGE'],topics:['IAM','logging','encryption','storage exposure','cloud configuration']},
 {id:'CONTAINER',label:'Container & Kubernetes',assetTypes:['CONTAINER'],topics:['image vulnerabilities','packages/SBOM','secrets','misconfiguration','Kubernetes posture']},
 {id:'SOURCE_SUPPLY_CHAIN',label:'Source & Software Supply Chain',assetTypes:['REPOSITORY'],topics:['SAST','dependency risk','secrets','IaC','SBOM']},
 {id:'ENDPOINT_IDENTITY',label:'Endpoint & Identity',assetTypes:['WORKSTATION','MOBILE','IDENTITY_PROVIDER'],topics:['endpoint telemetry','authentication events','identity posture','privilege signals']},
 {id:'DATA',label:'Data & Database Security',assetTypes:['DATABASE','STORAGE'],topics:['service exposure','access posture','encryption','data exposure','security telemetry']},
] as const;

export function offensiveCapabilityCatalog(){
 return SECURITY_DOMAINS.map(domain=>({ ...domain,
  engines:[...new Set(domain.assetTypes.flatMap(t=>scannerPlan(t as AssetType).map(x=>x.engine)))],
  layers:[...new Set(domain.assetTypes.flatMap(t=>scannerPlan(t as AssetType).flatMap(x=>x.layers)))]
 }));
}

function severityWeight(s:string){return ({CRITICAL:10,HIGH:7,MEDIUM:4,LOW:2,INFO:0}[s]??0)}
export function defensiveAssessment(a:Assessment,findings:Finding[],evidence:Evidence[]){
 const open=findings.filter(f=>!['REMEDIATED','FALSE_POSITIVE'].includes(String(f.status||'OPEN')));
 const prioritized=[...open].sort((x,y)=>severityWeight(y.severity)-severityWeight(x.severity)||Number(y.cvss||0)-Number(x.cvss||0));
 const actions=prioritized.map(f=>({
  findingId:f.id,status:f.status||'OPEN',source:f.source,severity:f.severity,title:f.title,asset:f.asset,
  mitigation:f.remediation||'Analyst remediation required from validated technical evidence.',
  validation:'Apply the mitigation in a controlled change, then run a targeted retest against the same asset/fingerprint before closure.',
  residualRisk:f.severity==='CRITICAL'||f.severity==='HIGH'?'HIGH UNTIL SUCCESSFUL RETEST':'REVIEW AFTER RETEST',
  evidenceHash:f.evidenceHash
 }));
 const sources=[...new Set(evidence.map(e=>String(e.source||'unknown').toUpperCase()))];
 return {
  assessment:{id:a.id,target:a.target,status:a.status},
  posture:{openFindings:open.length,critical:open.filter(x=>x.severity==='CRITICAL').length,high:open.filter(x=>x.severity==='HIGH').length,evidenceRecords:evidence.length,evidenceSources:sources},
  lifecycle:['OBSERVE','PRIORITIZE','MITIGATE','HARDEN','RETEST','MONITOR'],
  actions,
  detectionAndHardening:{
   telemetryAvailable:sources.filter(x=>['WAZUH','PROWLER','HTTP','NMAP','TRIVY'].includes(x)),
   recommendations:[
    'Preserve scanner and telemetry evidence before remediation.',
    'Prioritize internet-exposed critical/high findings and identity/data exposure.',
    'Apply least privilege, secure configuration, patching and segmentation appropriate to the affected asset.',
    'Retest the exact affected asset after change and retain the new evidence hash.',
    'Keep unresolved or partially tested exposure visible as residual risk.'
   ]
  },
  limitations:['Defensive recommendations are derived from stored assessment evidence. They do not assert that an unobserved attack occurred.','A finding is not considered remediated until a successful targeted retest and governed closure.']
 };
}

export function securityWorkspaceSummary(a:Assessment,findings:Finding[],evidence:Evidence[]){
 const sources=[...new Set(evidence.map(e=>String(e.source||'unknown').toUpperCase()))];
 return {
  assessment:{id:a.id,target:a.target,status:a.status,authorizedAt:a.authorizedAt},
  offensive:{findings:findings.length,bySeverity:Object.fromEntries(['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s=>[s,findings.filter(f=>f.severity===s).length])),evidenceRecords:evidence.length,evidenceSources:sources},
  defensive:defensiveAssessment(a,findings,evidence),
  assuranceLayers:ASSESSMENT_LAYERS,
  reuse:{sameAssessment:true,reuploadRequired:false,note:'Offensive and Defensive workspaces consume the same assessment, findings, documents and evidence records.'}
 };
}
