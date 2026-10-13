/**
 * Enterprise cyber operations handoff contracts.
 * Pure validation/normalization only: no vendor calls, shell execution, or
 * claims that imported evidence proves compliance.
 */
export type SecuritySource='OFFENSIVE'|'DEFENSIVE'|'INCIDENT_RESPONSE'|'IDENTITY_DETECTION_RESPONSE'|'TPRM';
export type HandoffStatus='DRAFT'|'EVIDENCE_RECORDED'|'REVIEW_REQUIRED';
export type EvidenceHandoff={
 organizationId:string;assessmentId:string;source:SecuritySource;
 reportId:string;sha256:string;recordedAt:string;status:HandoffStatus;
 evidenceRefs:string[];frameworksRequested:string[];
};
const hex=/^[a-f0-9]{64}$/i;
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const sources=new Set<SecuritySource>(['OFFENSIVE','DEFENSIVE','INCIDENT_RESPONSE','IDENTITY_DETECTION_RESPONSE','TPRM']);
export function prepareEvidenceHandoff(input:EvidenceHandoff){
 if(!input||!uuid.test(input.organizationId)||!uuid.test(input.assessmentId)||!uuid.test(input.reportId))throw new Error('Tenant, assessment and report UUIDs required');
 if(!sources.has(input.source)||!hex.test(input.sha256))throw new Error('Recognized source and SHA-256 integrity digest required');
 if(!Number.isFinite(Date.parse(input.recordedAt)))throw new Error('Valid evidence timestamp required');
 if(!Array.isArray(input.evidenceRefs)||!input.evidenceRefs.length||input.evidenceRefs.length>200||input.evidenceRefs.some(x=>typeof x!=='string'||x.length>200||!x.trim()))throw new Error('Bounded evidence references required');
 if(!Array.isArray(input.frameworksRequested)||input.frameworksRequested.length>30||input.frameworksRequested.some(x=>typeof x!=='string'||!/^[a-z0-9 _.-]{2,80}$/i.test(x)))throw new Error('Invalid framework references');
 return {...input,status:'REVIEW_REQUIRED' as const,canAutoCertify:false,canAutoCloseRisk:false,
  gates:['TENANT_OWNERSHIP','EVIDENCE_INTEGRITY','SOURCE_PROVENANCE','ANALYST_REVIEW','FRAMEWORK_APPLICABILITY','CONTROL_TEST','INDEPENDENT_APPROVAL'],
  note:'A report is technical evidence. Framework mappings and compliance conclusions require verified scope, applicability, evidence review and control tests.'};
}

export type IncidentPhase='DETECTED'|'TRIAGED'|'CONTAINMENT'|'ERADICATION'|'RECOVERY'|'POST_INCIDENT_REVIEW'|'CLOSED';
export type IncidentEvent={phase:IncidentPhase;occurredAt:string;actorId:string;evidenceRefs:string[];reason:string};
const phases:IncidentPhase[]=['DETECTED','TRIAGED','CONTAINMENT','ERADICATION','RECOVERY','POST_INCIDENT_REVIEW','CLOSED'];
export function validateIncidentTransition(current:IncidentPhase,next:IncidentPhase,evt:IncidentEvent){
 if(!phases.includes(current)||!phases.includes(next)||!evt||evt.phase!==next)throw new Error('Invalid incident state');
 if(phases.indexOf(next)!==phases.indexOf(current)+1)throw new Error('Incident lifecycle cannot skip stages or regress');
 if(!evt.actorId||!evt.reason?.trim()||!Number.isFinite(Date.parse(evt.occurredAt)))throw new Error('Accountable incident actor, reason and time required');
 if(!Array.isArray(evt.evidenceRefs)||!evt.evidenceRefs.length)throw new Error('Incident transition requires evidence');
 return {accepted:true,from:current,to:next,requiresAuditLog:true,requiresTenantAuthorization:true};
}

export type IdentitySignal={kind:'IMPOSSIBLE_TRAVEL'|'MFA_FATIGUE'|'PRIVILEGE_ESCALATION'|'SUSPICIOUS_LOGIN'|'DORMANT_ACCOUNT';principalId:string;observedAt:string;source:string;evidenceRefs:string[]};
export function normalizeIdentitySignal(signal:IdentitySignal){
 if(!signal||!['IMPOSSIBLE_TRAVEL','MFA_FATIGUE','PRIVILEGE_ESCALATION','SUSPICIOUS_LOGIN','DORMANT_ACCOUNT'].includes(signal.kind)||!signal.principalId?.trim()||!signal.source?.trim()||!Number.isFinite(Date.parse(signal.observedAt))||!Array.isArray(signal.evidenceRefs)||!signal.evidenceRefs.length)throw new Error('Identity detection requires source-backed evidence');
 return {...signal,triage:'REVIEW_REQUIRED',automaticAccountDisable:false,automaticCompromiseAssertion:false};
}
