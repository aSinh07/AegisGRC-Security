import type {AssessmentLayer} from './assessment-coverage.js';
export type ScannerEngine='NMAP'|'OPENVAS'|'NUCLEI'|'ZAP'|'SEMGREP'|'TRIVY'|'PROWLER'|'WAZUH';
export type AssetType='DOMAIN'|'IP'|'HOST'|'SERVER'|'WORKSTATION'|'MOBILE'|'WEB_APP'|'API'|'CLOUD_ACCOUNT'|'CONTAINER'|'REPOSITORY'|'DATABASE'|'STORAGE'|'IDENTITY_PROVIDER'|'NETWORK_DEVICE';
export type ScannerPlan={engine:ScannerEngine;layers:AssessmentLayer[];reason:string};

const matrix:Record<AssetType,ScannerPlan[]>={
 DOMAIN:[{engine:'NMAP',layers:['ATTACK_SURFACE','INFRASTRUCTURE'],reason:'Network exposure and reachable services'},{engine:'NUCLEI',layers:['ATTACK_SURFACE','WEB'],reason:'Template-based exposed service and web checks'}],
 IP:[{engine:'NMAP',layers:['ATTACK_SURFACE','INFRASTRUCTURE'],reason:'Ports services and host exposure'},{engine:'OPENVAS',layers:['INFRASTRUCTURE'],reason:'Authenticated or remote vulnerability assessment'}],
 HOST:[{engine:'NMAP',layers:['INFRASTRUCTURE'],reason:'Network services'},{engine:'OPENVAS',layers:['INFRASTRUCTURE'],reason:'Host vulnerability assessment'},{engine:'WAZUH',layers:['ENDPOINT','BREACH_TELEMETRY'],reason:'Host configuration and security telemetry'}],
 SERVER:[{engine:'NMAP',layers:['INFRASTRUCTURE'],reason:'Server network services'},{engine:'OPENVAS',layers:['INFRASTRUCTURE'],reason:'Server vulnerabilities'},{engine:'WAZUH',layers:['ENDPOINT','BREACH_TELEMETRY'],reason:'Server endpoint telemetry'},{engine:'TRIVY',layers:['DEPENDENCIES'],reason:'Installed software and filesystem vulnerabilities'}],
 WORKSTATION:[{engine:'WAZUH',layers:['ENDPOINT','BREACH_TELEMETRY'],reason:'Endpoint posture and telemetry'},{engine:'TRIVY',layers:['DEPENDENCIES'],reason:'Local package vulnerability inventory'}],
 MOBILE:[{engine:'WAZUH',layers:['ENDPOINT','BREACH_TELEMETRY'],reason:'Endpoint telemetry when supported'}],
 WEB_APP:[{engine:'ZAP',layers:['WEB'],reason:'Dynamic web application assessment'},{engine:'NUCLEI',layers:['WEB','ATTACK_SURFACE'],reason:'Known exposure and misconfiguration checks'}],
 API:[{engine:'ZAP',layers:['API'],reason:'API dynamic assessment'},{engine:'NUCLEI',layers:['API','ATTACK_SURFACE'],reason:'API exposure and known issue checks'}],
 CLOUD_ACCOUNT:[{engine:'PROWLER',layers:['CLOUD','IDENTITY','DATA_SECURITY','PRIVACY'],reason:'Cloud configuration IAM encryption logging and data exposure posture'}],
 CONTAINER:[{engine:'TRIVY',layers:['CONTAINER','DEPENDENCIES','DATA_SECURITY'],reason:'Image vulnerabilities secrets and misconfiguration'}],
 REPOSITORY:[{engine:'SEMGREP',layers:['SOURCE_CODE','DATA_SECURITY'],reason:'Static code security and secret-risk patterns'},{engine:'TRIVY',layers:['DEPENDENCIES','SOURCE_CODE'],reason:'Dependency IaC and secret scanning'}],
 DATABASE:[{engine:'OPENVAS',layers:['INFRASTRUCTURE','DATA_SECURITY'],reason:'Database host/service vulnerabilities'},{engine:'WAZUH',layers:['BREACH_TELEMETRY'],reason:'Security events where agent/log integration exists'}],
 STORAGE:[{engine:'PROWLER',layers:['CLOUD','DATA_SECURITY','PRIVACY'],reason:'Storage access encryption exposure and privacy posture'}],
 IDENTITY_PROVIDER:[{engine:'PROWLER',layers:['IDENTITY','CLOUD'],reason:'Cloud IAM posture where supported'},{engine:'WAZUH',layers:['BREACH_TELEMETRY','IDENTITY'],reason:'Authentication/security event telemetry'}],
 NETWORK_DEVICE:[{engine:'NMAP',layers:['INFRASTRUCTURE','ATTACK_SURFACE'],reason:'Reachability and exposed network services'},{engine:'OPENVAS',layers:['INFRASTRUCTURE'],reason:'Network-device vulnerability assessment'}]
};
export function scannerPlan(assetType:AssetType){return matrix[assetType]||[]}
export function requiredEngines(assetTypes:AssetType[]){return [...new Set(assetTypes.flatMap(x=>scannerPlan(x).map(p=>p.engine)))]}
export function layerEngineMatrix(assetTypes:AssetType[]){const out=new Map<AssessmentLayer,Set<ScannerEngine>>();for(const t of assetTypes)for(const p of scannerPlan(t))for(const l of p.layers){if(!out.has(l))out.set(l,new Set());out.get(l)!.add(p.engine)}return [...out].map(([layer,engines])=>({layer,engines:[...engines]}))}
