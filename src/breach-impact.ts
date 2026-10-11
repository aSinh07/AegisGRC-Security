import crypto from 'node:crypto';

/** Evidence-derived breach exposure assessment. Never claims a breach occurred without corroboration. */
export type BreachSignal = {
  source: string;
  evidenceSha256: string;
  observedAt: string;
  category: 'EXFILTRATION'|'UNAUTHORIZED_ACCESS'|'PUBLIC_EXPOSURE'|'SENSITIVE_DATA'|'CREDENTIAL_LEAK'|'CONTROL_FAILURE';
  verified: boolean;
  assetId?: string;
  details?: string;
};
export type BreachImpactInput = {
  organizationId: string;
  assessmentId: string;
  assetId: string;
  classification: 'PUBLIC'|'INTERNAL'|'CONFIDENTIAL'|'RESTRICTED';
  containsPii: boolean;
  criticality: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL';
  signals: BreachSignal[];
};
const sha256=(v:string)=>crypto.createHash('sha256').update(v).digest('hex');
const weight:Record<BreachImpactInput['classification'],number>={PUBLIC:0,INTERNAL:1,CONFIDENTIAL:2,RESTRICTED:3};
const critical:Record<BreachImpactInput['criticality'],number>={LOW:0,MEDIUM:1,HIGH:2,CRITICAL:3};
export function assessBreachImpact(input:BreachImpactInput){
  if(!input.organizationId||!input.assessmentId||!input.assetId)throw new Error('Organization, assessment and asset are required');
  if(!(input.classification in weight)||!(input.criticality in critical))throw new Error('Invalid asset classification or criticality');
  if(!Array.isArray(input.signals))throw new Error('Signals must be an array');
  const verified=input.signals.filter(s=>s.verified&&/^[a-f0-9]{64}$/i.test(s.evidenceSha256)&&!Number.isNaN(Date.parse(s.observedAt))&&(!s.assetId||s.assetId===input.assetId));
  const categories=[...new Set(verified.map(s=>s.category))].sort();
  const impact=Math.min(100,weight[input.classification]*15+critical[input.criticality]*10+(input.containsPii?15:0));
  const observed=categories.includes('EXFILTRATION');
  const unauthorized=categories.includes('UNAUTHORIZED_ACCESS');
  const exposure=categories.includes('PUBLIC_EXPOSURE')||categories.includes('CREDENTIAL_LEAK');
  const breachConfirmed=observed&&unauthorized; // conservative heuristic; not a legal or forensic determination
  const status=breachConfirmed?'SUSPECTED_BREACH_REQUIRES_REVIEW':verified.length?'EXPOSURE_SIGNALS_PRESENT':'INSUFFICIENT_EVIDENCE';
  const evidence=verified.map(s=>({source:s.source,sha256:s.evidenceSha256,category:s.category,observedAt:s.observedAt})).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const fingerprint=sha256(JSON.stringify({organizationId:input.organizationId,assessmentId:input.assessmentId,assetId:input.assetId,evidence}));
  return {status,breachConfirmed:false,requiresHumanReview:breachConfirmed||exposure||observed,impactScore:impact,impactBand:impact>=75?'CRITICAL':impact>=50?'HIGH':impact>=25?'MEDIUM':'LOW',verifiedSignalCount:verified.length,categories,evidence,fingerprint,limitations:['This is an evidence correlation aid, not proof of a breach or a regulatory notification determination.']};
}
