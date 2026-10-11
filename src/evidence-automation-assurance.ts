/** Deterministic evidence-automation coverage; never equate automated collection with audit approval. */
export type Connection={provider:string;state:'CONNECTED'|'DISCONNECTED'|'ERROR'|'SETUP_REQUIRED';lastSuccessAt?:string|null};
export type EvidenceSource={id:string;provider:string;kind:'MONITOR'|'TEST';state:'PASS'|'FAIL'|'UNKNOWN';collectedAt?:string|null;hash?:string|null;systems:string[]};
export type EvidenceRequirement={id:string;systems:string[];supportedProviders:string[];maxAgeHours:number;requiresManualProof?:boolean};
export type EvidenceAutomationInput={requirement:EvidenceRequirement;connections:Connection[];sources:EvidenceSource[];review?:{decision:'APPROVED'|'REJECTED';reviewerId:string;reviewedAt:string}|null;now?:string};
export function evaluateEvidenceAutomation(input:EvidenceAutomationInput){
 const {requirement:r,connections,sources}=input,now=new Date(input.now||Date.now()).getTime();
 if(!Number.isFinite(now))throw Error('Invalid evaluation timestamp');
 if(!Number.isFinite(r.maxAgeHours)||r.maxAgeHours<=0)throw Error('Invalid freshness window');
 const systems=[...new Set(r.systems.map(s=>s.trim()).filter(Boolean))];
 const providers=new Set(r.supportedProviders);
 const connected=new Set(connections.filter(c=>c.state==='CONNECTED'&&providers.has(c.provider)).map(c=>c.provider));
 const active=sources.filter(s=>connected.has(s.provider));
 const accepted=active.filter(s=>s.state==='PASS'&&!!s.hash&&/^[a-f0-9]{64}$/i.test(s.hash)&&!!s.collectedAt&&Number.isFinite(Date.parse(s.collectedAt))&&Date.parse(s.collectedAt!)<=now&&now-Date.parse(s.collectedAt!)<=r.maxAgeHours*3600000);
 const covered=new Set(accepted.flatMap(s=>s.systems.filter(system=>systems.includes(system))));
 const uncovered=systems.filter(s=>!covered.has(s));
 const available=r.supportedProviders.length>0;
 const status: 'MANUAL_ONLY'|'AUTOMATION_READY'|'PARTIALLY_AUTOMATED'|'FULLY_AUTOMATED'=
  !available?'MANUAL_ONLY':!active.length?'AUTOMATION_READY':uncovered.length||r.requiresManualProof?'PARTIALLY_AUTOMATED':'FULLY_AUTOMATED';
 const failed=active.filter(s=>s.state==='FAIL').map(s=>s.id);
 const stale=active.filter(s=>s.state==='PASS'&&!accepted.includes(s)).map(s=>s.id);
 const evidenceReady=status==='FULLY_AUTOMATED'&&failed.length===0&&stale.length===0;
 const approved=evidenceReady&&input.review?.decision==='APPROVED';
 return {status,evidenceReady,approved,coveredSystems:[...covered],uncoveredSystems:uncovered,failedSources:failed,staleOrUnverifiableSources:stale,reviewRequired:!approved,reason:!available?'No supported automation providers':!connected.size?'Required integrations unavailable':!active.length?'No active evidence sources':!evidenceReady?'Missing, stale, failed or manual evidence':'Evidence current; independent review still required'};
}
