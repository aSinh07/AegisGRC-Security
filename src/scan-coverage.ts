export type ScannerRunStatus='SUCCEEDED'|'FAILED'|'NOT_RUN';
export interface ScannerRunSummary{tool:string;status:ScannerRunStatus;exitCode?:number|null;error?:string;timedOut?:boolean;incomplete?:boolean}
export interface ScannerFailureDetail{tool:string;reason:'TIMEOUT'|'SPAWN_OR_SERVICE_ERROR'|'NON_ZERO_EXIT'|'INCOMPLETE_EVIDENCE'|'UNKNOWN_FAILURE';exitCode?:number|null;error?:string}
export interface ScanCoverage{required:string[];succeeded:string[];failed:string[];notRun:string[];complete:boolean;failureDetails?:ScannerFailureDetail[]}

export function scannerRunStatus(exitCode:number|null|undefined,error?:string,incomplete=false):ScannerRunStatus{
 if(error||incomplete)return 'FAILED';
 return exitCode===0?'SUCCEEDED':'FAILED';
}
export function scanCoverage(required:string[],runs:ScannerRunSummary[]):ScanCoverage{
 const byTool=new Map(runs.map(x=>[x.tool,x]));
 const succeeded:string[]=[],failed:string[]=[],notRun:string[]=[],failureDetails:ScannerFailureDetail[]=[];
 for(const tool of required){
  const run=byTool.get(tool);
  if(!run||run.status==='NOT_RUN')notRun.push(tool);
  else if(run.status==='SUCCEEDED')succeeded.push(tool);
  else {failed.push(tool);failureDetails.push({tool,reason:run.timedOut?'TIMEOUT':run.error?'SPAWN_OR_SERVICE_ERROR':run.incomplete?'INCOMPLETE_EVIDENCE':typeof run.exitCode==='number'&&run.exitCode!==0?'NON_ZERO_EXIT':'UNKNOWN_FAILURE',exitCode:run.exitCode,error:run.error});}
 }
 return {required:[...required],succeeded,failed,notRun,complete:failed.length===0&&notRun.length===0,failureDetails};
}
export function assessmentStatusForCoverage(c:ScanCoverage):'COMPLETED'|'PARTIAL'|'FAILED'{
 if(c.complete)return 'COMPLETED';
 return c.succeeded.length?'PARTIAL':'FAILED';
}
