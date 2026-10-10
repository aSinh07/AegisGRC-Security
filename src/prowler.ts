import crypto from 'node:crypto';

export type ProwlerFinding={checkId:string;status:string;severity:string;service?:string;region?:string;resource?:string;title:string;description:string;raw:any};
export function parseProwlerJson(raw:string):ProwlerFinding[]{
 let x:any;try{x=JSON.parse(raw)}catch{return []}const rows=Array.isArray(x)?x:Array.isArray(x?.findings)?x.findings:Array.isArray(x?.Results)?x.Results:[];
 return rows.map((r:any)=>({checkId:String(r.CheckID||r.check_id||r.checkId||r.id||''),status:String(r.Status||r.status||r.result||'').toUpperCase(),severity:String(r.Severity||r.severity||'INFO').toUpperCase(),service:r.ServiceName||r.service,region:r.Region||r.region,resource:r.ResourceId||r.resource_id||r.resource,title:String(r.CheckTitle||r.title||r.CheckID||'Prowler cloud finding'),description:String(r.StatusExtended||r.description||''),raw:r})).filter((r:any)=>r.checkId);
}
export function prowlerEvidence(raw:string,meta:{assetId:string;accountKey:string;provider:string;scanCompleted:boolean;startedAt?:string;completedAt?:string;identityAssessed?:boolean;identityAssetId?:string}){
 const sha256=crypto.createHash('sha256').update(raw).digest('hex');const findings=parseProwlerJson(raw);return {sha256,findings,metadata:{...meta,scanner:'PROWLER',format:'json',findingCount:findings.length}};
}
