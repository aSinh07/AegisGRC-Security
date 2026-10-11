export const ASSESSMENT_LAYERS = [
  'ATTACK_SURFACE','INFRASTRUCTURE','ENDPOINT','WEB','API','SOURCE_CODE','DEPENDENCIES','CONTAINER','CLOUD','IDENTITY','DATA_SECURITY','PRIVACY','BREACH_TELEMETRY'
] as const;
export type AssessmentLayer = typeof ASSESSMENT_LAYERS[number];
export type LayerStatus='NOT_STARTED'|'RUNNING'|'COMPLETE'|'PARTIAL'|'FAILED'|'NOT_APPLICABLE';
export type LayerCoverage={layer:AssessmentLayer;status:LayerStatus;required:boolean;engines:string[];evidenceCount:number;failureReasons:string[]};

export function assessmentCoverage(rows:LayerCoverage[]){
 const declared=new Map(rows.map(x=>[x.layer,x]));
 const missing=ASSESSMENT_LAYERS.filter(layer=>!declared.has(layer));
 const unjustifiedNA=rows.filter(x=>x.required&&x.status==='NOT_APPLICABLE'&&!(x.failureReasons||[]).some(r=>String(r).trim().length>=10));
 const required=rows.filter(x=>x.required&&x.status!=='NOT_APPLICABLE');
 const complete=required.filter(x=>x.status==='COMPLETE');
 const failed=required.filter(x=>x.status==='FAILED'||x.status==='PARTIAL'||x.status==='NOT_STARTED'||x.status==='RUNNING');
 return {
  declaredLayers:rows.length,requiredLayers:required.length,completeLayers:complete.length,
  coveragePercent:required.length?Math.round(complete.length/required.length*100):0,
  status:rows.length===ASSESSMENT_LAYERS.length&&required.length>0&&failed.length===0&&missing.length===0&&unjustifiedNA.length===0?'COMPLETE':'PARTIAL',
  missingLayers:missing,unjustifiedNotApplicable:unjustifiedNA.map(x=>x.layer),
  incompleteLayers:failed.map(x=>({layer:x.layer,status:x.status,reasons:x.failureReasons}))
 };
}

export type DataExposureState='VULNERABILITY'|'EXPOSURE'|'SUSPECTED_BREACH'|'CONFIRMED_BREACH';
export function dataExposureState(x:{vulnerability:boolean;dataExposed:boolean;telemetryIndicators:boolean;confirmedExfiltration:boolean}):DataExposureState{
 if(x.confirmedExfiltration)return 'CONFIRMED_BREACH';
 if(x.telemetryIndicators)return 'SUSPECTED_BREACH';
 if(x.dataExposed)return 'EXPOSURE';
 return 'VULNERABILITY';
}

export function assuranceStatement(rows:LayerCoverage[]){
 const coverage=assessmentCoverage(rows);const allRequiredComplete=coverage.status==='COMPLETE'&&coverage.coveragePercent===100;
 return {
  scannerCoveragePercent:coverage.coveragePercent,
  assuranceLevel:allRequiredComplete?'HIGH':'LIMITED',
  claim:allRequiredComplete?'All declared required assessment layers have completed evidence-derived checks. This is high scanner coverage, not a guarantee that no vulnerability exists.':'Assessment coverage is incomplete. Security or compliance completeness must not be claimed.',
  vulnerabilityFreeGuaranteed:false,
  residualRiskNotice:'No combination of automated scanners can prove that a system is 100% vulnerability-free. Results are bounded by declared scope, credentials, scanner capabilities, configuration, timing, and supplied evidence.'
 };
}
