/** Advisory, deterministic evidence-automation coverage.
 * All inputs to the public evaluation API are caller-supplied and untrusted.
 * This function NEVER grants audit approval; that requires DB-backed reviewer
 * identity, separation of duties, evidence integrity and an immutable audit trail.
 */
export type Connection={provider:string;state:'CONNECTED'|'DISCONNECTED'|'ERROR'|'SETUP_REQUIRED';lastSuccessAt?:string|null};
export type EvidenceSource={id:string;provider:string;kind:'MONITOR'|'TEST';state:'PASS'|'FAIL'|'UNKNOWN';collectedAt?:string|null;hash?:string|null;systems:string[];integrityVerified?:boolean};
export type EvidenceRequirement={id:string;systems:string[];supportedProviders:string[];maxAgeHours:number;requiresManualProof?:boolean};
export type EvidenceAutomationInput={requirement:EvidenceRequirement;connections:Connection[];sources:EvidenceSource[];review?:{decision:'APPROVED'|'REJECTED';reviewerId:string;reviewedAt:string}|null;now?:string};
export function evaluateEvidenceAutomation(input:EvidenceAutomationInput){
 if(!input||!input.requirement||!Array.isArray(input.requirement.systems)||!Array.isArray(input.requirement.supportedProviders)||!Array.isArray(input.connections)||!Array.isArray(input.sources))throw Error('Invalid evidence evaluation input');
 const {requirement:r,connections,sources}=input,now=new Date(input.now||Date.now()).getTime();
 if(!Number.isFinite(now))throw Error('Invalid evaluation timestamp');
 if(!Number.isFinite(r.maxAgeHours)||r.maxAgeHours<=0)throw Error('Invalid freshness window');
 const systems=[...new Set(r.systems.map(s=>String(s).trim()).filter(Boolean))];
 const providers=new Set(r.supportedProviders.map(s=>String(s).trim()).filter(Boolean));
 const connected=new Set(connections.filter(c=>c?.state==='CONNECTED'&&providers.has(c.provider)&&!!c.lastSuccessAt&&Number.isFinite(Date.parse(c.lastSuccessAt))&&Date.parse(c.lastSuccessAt)<=now&&now-Date.parse(c.lastSuccessAt)<=r.maxAgeHours*3600000).map(c=>c.provider));
 const active=sources.filter(s=>s&&connected.has(s.provider)&&Array.isArray(s.systems));
 // SHA-256 text is only a digest claim. A trusted backend must verify the
 // digest against the stored bytes and origin before marking integrityVerified.
 const accepted=active.filter(s=>s.state==='PASS'&&s.integrityVerified===true&&!!s.hash&&/^[a-f0-9]{64}$/i.test(s.hash)&&!!s.collectedAt&&Number.isFinite(Date.parse(s.collectedAt))&&Date.parse(s.collectedAt!)<=now&&now-Date.parse(s.collectedAt!)<=r.maxAgeHours*3600000);
 const covered=new Set(accepted.flatMap(s=>s.systems.filter(system=>systems.includes(system))));
 const uncovered=systems.filter(s=>!covered.has(s));
 const available=providers.size>0;
 const status:'MANUAL_ONLY'|'AUTOMATION_READY'|'PARTIALLY_AUTOMATED'|'FULLY_AUTOMATED'=
  !available?'MANUAL_ONLY':!active.length?'AUTOMATION_READY':!systems.length||!accepted.length||uncovered.length||r.requiresManualProof?'PARTIALLY_AUTOMATED':'FULLY_AUTOMATED';
 const failed=active.filter(s=>s.state==='FAIL').map(s=>s.id);
 const stale=active.filter(s=>s.state==='PASS'&&!accepted.includes(s)).map(s=>s.id);
 const evidenceReady=status==='FULLY_AUTOMATED'&&failed.length===0&&stale.length===0;
 const reviewClaimed=input.review?.decision==='APPROVED';
 return {status,evidenceReady,approved:false,reviewClaimed,reviewVerified:false,advisoryOnly:true,coveredSystems:[...covered],uncoveredSystems:uncovered,failedSources:failed,staleOrUnverifiableSources:stale,reviewRequired:true,reason:!available?'No supported automation providers':!connected.size?'Required integrations unavailable or stale':!active.length?'No active evidence sources':!evidenceReady?'Missing, stale, failed, unverifiable or manual evidence':'Evidence inputs appear current; independent server-side approval still required'};
}
