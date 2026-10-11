import crypto from 'node:crypto';

export type ProwlerFinding={checkId:string;status:string;severity:string;service?:string;region?:string;resource?:string;title:string;description:string;raw:any};
export function parseProwlerReport(raw:string):{recognized:boolean;rows:number;findings:ProwlerFinding[]}{
 let x:any;try{x=JSON.parse(raw)}catch{return {recognized:false,rows:0,findings:[]}}const recognized=Array.isArray(x)||Array.isArray(x?.findings)||Array.isArray(x?.Results);const rows=Array.isArray(x)?x:Array.isArray(x?.findings)?x.findings:Array.isArray(x?.Results)?x.Results:[]; const findings=
 rows.map((r:any)=>({checkId:String(r.CheckID||r.check_id||r.checkId||r.id||''),status:String(r.Status||r.status||r.result||'').toUpperCase(),severity:String(r.Severity||r.severity||'INFO').toUpperCase(),service:r.ServiceName||r.service,region:r.Region||r.region,resource:r.ResourceId||r.resource_id||r.resource,title:String(r.CheckTitle||r.title||r.CheckID||'Prowler cloud finding'),description:String(r.StatusExtended||r.description||''),raw:r})).filter((r:any)=>r.checkId);return {recognized,rows:rows.length,findings};
}
export function parseProwlerJson(raw:string):ProwlerFinding[]{return parseProwlerReport(raw).findings}
export function prowlerEvidence(raw:string,meta:{assetId:string;accountKey:string;provider:string;scanCompleted:boolean;startedAt?:string;completedAt?:string;identityAssessed?:boolean;identityAssetId?:string;dataSecurityAssessed?:boolean;dataAssetId?:string;privacyAssessed?:boolean;privacyAssetId?:string}){
 const sha256=crypto.createHash('sha256').update(raw).digest('hex');const report=parseProwlerReport(raw);if(!report.recognized)throw new Error('Unrecognized Prowler JSON report structure');const findings=report.findings;return {sha256,findings,metadata:{...meta,scanner:'PROWLER',format:'json',reportRecognized:true,reportRowCount:report.rows,findingCount:findings.length}};
}
