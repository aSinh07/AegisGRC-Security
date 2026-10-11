export type ArchitectureNode={id:string;label:string;kind:string;source:'DOCUMENT';confidence:'EXPLICIT'|'INFERRED';line:number};
export type ArchitectureEdge={from:string;to:string;confidence:'EXPLICIT';line:number};
const patterns:[string,RegExp][]=[
 ['FIREWALL',/\b(firewall|waf|security gateway)\b/i],
 ['LOAD_BALANCER',/\b(load balancer|alb|nginx|reverse proxy|ingress)\b/i],
 ['DATABASE',/\b(postgres(?:ql)?|mysql|mongodb|database|redis|dynamodb|sql server)\b/i],
 ['APPLICATION',/\b(application server|app server|backend|microservice|api gateway|fastapi|express|kubernetes|k8s)\b/i],
 ['CLOUD',/\b(aws|azure|gcp|vpc|virtual private cloud)\b/i],
 ['STORAGE',/\b(s3 bucket|blob storage|object storage|file storage)\b/i],
 ['IDENTITY',/\b(okta|identity provider|active directory|keycloak|iam)\b/i],
 ['CLIENT',/\b(browser|end user|client|frontend|mobile app)\b/i],
 ['NETWORK',/\b(router|switch|subnet|vpn|dns)\b/i]
];
const sanitize=(s:string)=>s.replace(/[\x00-\x1f]/g,' ').replace(/\s+/g,' ').trim().slice(0,100);
export function inferArchitecture(text:string){
 const lines=text.split(/\r?\n/).slice(0,4000);
 const nodes:ArchitectureNode[]=[],edges:ArchitectureEdge[]=[];
 const key=(label:string)=>label.toLowerCase().replace(/[^a-z0-9]/g,'');
 const find=(label:string)=>nodes.find(n=>key(n.label)===key(label));
 const add=(label:string,kind:string,line:number,confidence:'EXPLICIT'|'INFERRED'='INFERRED')=>{
  label=sanitize(label);if(!label||label.length>100)return null;
  const existing=find(label);if(existing)return existing;
  if(nodes.length>=80)return null;
  const node={id:'n'+(nodes.length+1),label,kind,source:'DOCUMENT' as const,confidence,line};nodes.push(node);return node;
 };
 for(let i=0;i<lines.length;i++){
  const line=sanitize(lines[i]);if(!line||line.length>250)continue;
  const arrow=line.match(/^(.{2,90}?)\s*(?:-->|->|→|=>|connects to|flows to)\s*(.{2,90}?)$/i);
  if(arrow){
   const fromLabel=sanitize(arrow[1]),toLabel=sanitize(arrow[2]);
   const classify=(s:string)=>patterns.find(([,re])=>re.test(s))?.[0]||'COMPONENT';
   const a=add(fromLabel,classify(fromLabel),i+1,'EXPLICIT'),b=add(toLabel,classify(toLabel),i+1,'EXPLICIT');
   if(a&&b&&a.id!==b.id&&edges.length<120&&!edges.some(e=>e.from===a.id&&e.to===b.id))edges.push({from:a.id,to:b.id,confidence:'EXPLICIT',line:i+1});
   continue;
  }
  if(line.length>110)continue;
  for(const [kind,re] of patterns){const match=line.match(re);if(match){add(match[0],kind,i+1);break}}
 }
 return {nodes,edges,summary:{components:nodes.length,documentedFlows:edges.length,unverifiedComponents:nodes.filter(n=>n.confidence==='INFERRED').length},limitations:[
 'This is an evidence-labelled visualization of extracted text, not a verified infrastructure discovery or engineering CAD simulation.',
 'PDF diagrams consisting only of images and scanned pages may not be extractable; OCR or human correction is required.',
 'An arrow is drawn only for a relationship explicitly written in the document. Component mentions do not prove deployment.',
 'Confirm topology, data flows, trust boundaries and asset ownership before using this as audit evidence.'
 ]};
}
