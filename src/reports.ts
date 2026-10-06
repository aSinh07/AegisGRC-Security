import type { Assessment,Finding } from './models.js';
export function assessmentReport(a:Assessment,findings:Finding[]){
 const counts=Object.fromEntries(['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s=>[s,findings.filter(f=>f.severity===s).length]));
 return {generatedAt:new Date().toISOString(),assessment:{id:a.id,target:a.target,status:a.status,authorizedAt:a.authorizedAt},summary:{total:findings.length,bySeverity:counts},findings:findings.map(f=>({id:f.id,severity:f.severity,title:f.title,asset:f.asset,cwe:f.cwe,cvss:f.cvss,mappings:f.mappings,remediation:f.remediation,evidenceHash:f.evidenceHash}))};
}