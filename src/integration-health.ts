export type ConnectorState='SETUP_REQUIRED'|'CONNECTED'|'DEGRADED'|'ERROR'|'DISCONNECTED';
export type ConnectorSnapshot={provider:string;state:ConnectorState;lastSuccessAt?:string|null;lastAttemptAt?:string|null;permissions?:string[];requiredPermissions?:string[];latencyMs?:number|null;error?:string|null};
export function connectorHealth(c:ConnectorSnapshot,now=new Date()){
 const required=new Set(c.requiredPermissions||[]),granted=new Set(c.permissions||[]);
 const missing=[...required].filter(x=>!granted.has(x));
 const success=c.lastSuccessAt?Date.parse(c.lastSuccessAt):NaN,ageHours=Number.isFinite(success)?(now.getTime()-success)/3600000:null;
 const healthy=c.state==='CONNECTED'&&missing.length===0&&ageHours!==null&&ageHours>=0&&ageHours<=24;
 return {provider:c.provider,healthy,state:healthy?'HEALTHY':c.state,missingPermissions:missing,lastSuccessAgeHours:ageHours,reason:missing.length?'Least-privilege permission requirements not satisfied':ageHours===null?'No verified successful synchronization':ageHours<0?'Invalid future synchronization timestamp':ageHours>24?'Synchronization stale':c.state!=='CONNECTED'?'Connector is not connected':'Healthy'};
}
export function integrationReadiness(connectors:ConnectorSnapshot[],requiredProviders:string[],now=new Date()){
 const health=connectors.map(c=>connectorHealth(c,now));
 const required=[...new Set(requiredProviders.map(p=>String(p).trim()).filter(Boolean))];
 // A stale duplicate connection must not mask another healthy instance.
 const missing=required.filter(p=>!health.some(h=>h.provider===p&&h.healthy));
 return {ready:required.length>0&&missing.length===0,requiredProviders:required,missingOrUnhealthy:missing,health,advisoryOnly:true,reason:required.length?'Caller-provided connector snapshots require independent verification':'No required integrations configured'};
}
