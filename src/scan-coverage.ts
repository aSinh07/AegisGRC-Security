export type ScannerRunStatus='SUCCEEDED'|'FAILED'|'NOT_RUN';
export interface ScannerRunSummary{tool:string;status:ScannerRunStatus;exitCode?:number|null;error?:string}
export interface ScanCoverage{required:string[];succeeded:string[];failed:string[];notRun:string[];complete:boolean}

export function scannerRunStatus(exitCode:number|null|undefined,error?:string):ScannerRunStatus{
 if(error)return 'FAILED';
 return exitCode===0?'SUCCEEDED':'FAILED';
}
export function scanCoverage(required:string[],runs:ScannerRunSummary[]):ScanCoverage{
 const byTool=new Map(runs.map(x=>[x.tool,x]));
 const succeeded:string[]=[],failed:string[]=[],notRun:string[]=[];
 for(const tool of required){
  const run=byTool.get(tool);
  if(!run||run.status==='NOT_RUN')notRun.push(tool);
  else if(run.status==='SUCCEEDED')succeeded.push(tool);
  else failed.push(tool);
 }
 return {required:[...required],succeeded,failed,notRun,complete:failed.length===0&&notRun.length===0};
}
export function assessmentStatusForCoverage(c:ScanCoverage):'COMPLETED'|'PARTIAL'|'FAILED'{
 if(c.complete)return 'COMPLETED';
 return c.succeeded.length?'PARTIAL':'FAILED';
}
