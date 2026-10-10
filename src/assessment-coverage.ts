export const ASSESSMENT_LAYERS = [
  'ATTACK_SURFACE','INFRASTRUCTURE','ENDPOINT','WEB','API','SOURCE_CODE','DEPENDENCIES','CONTAINER','CLOUD','IDENTITY','DATA_SECURITY','PRIVACY','BREACH_TELEMETRY'
] as const;
export type AssessmentLayer = typeof ASSESSMENT_LAYERS[number];
export type LayerStatus='NOT_STARTED'|'RUNNING'|'COMPLETE'|'PARTIAL'|'FAILED'|'NOT_APPLICABLE';
export type LayerCoverage={layer:AssessmentLayer;status:LayerStatus;required:boolean;engines:string[];evidenceCount:number;failureReasons:string[]};

export function assessmentCoverage(rows:LayerCoverage[]){
 const required=rows.filter(x=>x.required&&x.status!=='NOT_APPLICABLE');
 const complete=required.filter(x=>x.status==='COMPLETE');
 const failed=required.filter(x=>x.status==='FAILED'||x.status==='PARTIAL'||x.status==='NOT_STARTED'||x.status==='RUNNING');
 return {
  declaredLayers:rows.length,requiredLayers:required.length,completeLayers:complete.length,
  coveragePercent:required.length?Math.round(complete.length/required.length*100):0,
  status:failed.length===0?'COMPLETE':'PARTIAL',
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
