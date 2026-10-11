export type TruthGraph={nodes:{label:string;kind:string}[];edges:{from:string;to:string}[]};
export type PredictedGraph={nodes:{label:string;kind:string}[];edges:{from:string;to:string}[]};
const norm=(s:string)=>s.trim().toLowerCase().replace(/\s+/g,' ');
const nodeKey=(n:{label:string;kind:string})=>norm(n.label)+'|'+norm(n.kind);
const edgeKey=(e:{from:string;to:string})=>norm(e.from)+'->'+norm(e.to);
function score<T>(expected:T[],actual:T[],key:(x:T)=>string){
 const a=new Set(actual.map(key)),e=new Set(expected.map(key));
 const tp=[...a].filter(x=>e.has(x)).length,fp=[...a].filter(x=>!e.has(x)).length,fn=[...e].filter(x=>!a.has(x)).length;
 const precision=tp+fp?tp/(tp+fp):e.size===0?1:0;
 const recall=tp+fn?tp/(tp+fn):1;
 return {truePositive:tp,falsePositive:fp,falseNegative:fn,precision,recall,f1:precision+recall?2*precision*recall/(precision+recall):0};
}
export function architectureAccuracy(reference:TruthGraph,predicted:PredictedGraph){
 const nodes=score(reference.nodes,predicted.nodes,nodeKey);
 const edges=score(reference.edges,predicted.edges,edgeKey);
 return {nodes,edges,metric:'Exact normalized component/type and directed-edge precision/recall/F1',verifiedSample:false,claimableAccuracyPercent:null,warning:'Do not advertise 90% or 95% accuracy until independently labeled representative document benchmarks with confidence intervals pass.'};
}
export function benchmarkArchitecture(cases:{id:string;reference:TruthGraph;predicted:PredictedGraph}[]){
 if(!cases.length)throw Error('No labeled benchmark documents');
 const totals={nodes:{tp:0,fp:0,fn:0},edges:{tp:0,fp:0,fn:0}};
 for(const c of cases){const s=architectureAccuracy(c.reference,c.predicted);for(const part of ['nodes','edges'] as const){totals[part].tp+=s[part].truePositive;totals[part].fp+=s[part].falsePositive;totals[part].fn+=s[part].falseNegative}}
 const metrics=(x:{tp:number;fp:number;fn:number})=>{const p=x.tp+x.fp?x.tp/(x.tp+x.fp):0,r=x.tp+x.fn?x.tp/(x.tp+x.fn):0;return {precision:p,recall:r,f1:p+r?2*p*r/(p+r):0}};
 return {documentCount:cases.length,component:metrics(totals.nodes),connections:metrics(totals.edges),qualifiedForExternalAccuracyClaim:false,reason:'Representative independent labeled corpus, diagram/OCR/CAD format stratification, and uncertainty estimates required.'};
}
