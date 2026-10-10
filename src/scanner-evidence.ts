import crypto from 'node:crypto';
export type ExecutionState='SUCCESS'|'FAILED'|'TIMEOUT'|'TRUNCATED'|'UNAVAILABLE';
export type ScannerExecution={engine:string;assetId:string;assessmentId:string;startedAt:string;finishedAt:string;state:ExecutionState;exitCode:number|null;rawEvidence:string;stderr?:string};
export function scannerEvidenceRecord(x:ScannerExecution){
 const raw=String(x.rawEvidence||'');const stderr=String(x.stderr||'');
 return {engine:x.engine,assetId:x.assetId,assessmentId:x.assessmentId,startedAt:x.startedAt,finishedAt:x.finishedAt,state:x.state,exitCode:x.exitCode,
  rawSha256:crypto.createHash('sha256').update(raw).digest('hex'),rawBytes:Buffer.byteLength(raw),stderrSha256:stderr?crypto.createHash('sha256').update(stderr).digest('hex'):null,
  successful:x.state==='SUCCESS'&&x.exitCode===0};
}
export function coverageStateForExecutions(xs:ScannerExecution[],requiredEngines:string[]){
 const by=new Map(xs.map(x=>[x.engine,x]));const missing=requiredEngines.filter(e=>!by.has(e));const failed=requiredEngines.filter(e=>by.has(e)&&!(by.get(e)!.state==='SUCCESS'&&by.get(e)!.exitCode===0&&String(by.get(e)!.rawEvidence||'').length>0));
 if(!requiredEngines.length)return {status:'NOT_APPLICABLE' as const,reasons:[]};
 if(!missing.length&&!failed.length)return {status:'COMPLETE' as const,reasons:[]};
 return {status:'PARTIAL' as const,reasons:[...missing.map(e=>e+': not executed'),...failed.map(e=>e+': failed, incomplete, or produced no evidence')]};
}
