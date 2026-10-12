export type TruthGraph={nodes:{label:string;kind:string}[];edges:{from:string;to:string}[]};
export type PredictedGraph={nodes:{label:string;kind:string}[];edges:{from:string;to:string}[]};
export type BenchmarkCase={id:string;format?:string;independentlyLabeled?:boolean;reference:TruthGraph;predicted:PredictedGraph};
const norm=(s:string)=>s.trim().toLowerCase().replace(/\s+/g,' ');
const nodeKey=(n:{label:string;kind:string})=>norm(n.label)+'|'+norm(n.kind);
const edgeKey=(e:{from:string;to:string})=>norm(e.from)+'->'+norm(e.to);
function score<T>(expected:T[],actual:T[],key:(x:T)=>string){
 const a=new Set(actual.map(key)),e=new Set(expected.map(key));
 const tp=[...a].filter(x=>e.has(x)).length,fp=[...a].filter(x=>!e.has(x)).length,fn=[...e].filter(x=>!a.has(x)).length;
 const precision=tp+fp?tp/(tp+fp):e.size===0?1:0,recall=tp+fn?tp/(tp+fn):1;
 return {truePositive:tp,falsePositive:fp,falseNegative:fn,precision,recall,f1:precision+recall?2*precision*recall/(precision+recall):0};
}
function wilson(successes:number,total:number,z=1.96){
 if(!total)return {low:0,high:0};const p=successes/total,z2=z*z,d=1+z2/total,c=(p+z2/(2*total))/d,m=z*Math.sqrt((p*(1-p)+z2/(4*total))/total)/d;
 return {low:Math.max(0,c-m),high:Math.min(1,c+m)};
}
export function architectureAccuracy(reference:TruthGraph,predicted:PredictedGraph){
 const nodes=score(reference.nodes,predicted.nodes,nodeKey),edges=score(reference.edges,predicted.edges,edgeKey);
 return {nodes,edges,metric:'Exact normalized component/type and directed-edge precision/recall/F1',verifiedSample:false,claimableAccuracyPercent:null,warning:'Do not advertise 90% or 95% accuracy until independently labeled representative document benchmarks with confidence intervals pass.'};
}
export function benchmarkArchitecture(cases:BenchmarkCase[]){
 if(!cases.length)throw Error('No labeled benchmark documents');
 const totals={nodes:{tp:0,fp:0,fn:0},edges:{tp:0,fp:0,fn:0}},formats=new Map<string,BenchmarkCase[]>();
 for(const c of cases){const s=architectureAccuracy(c.reference,c.predicted);for(const part of ['nodes','edges'] as const){totals[part].tp+=s[part].truePositive;totals[part].fp+=s[part].falsePositive;totals[part].fn+=s[part].falseNegative}const f=(c.format||'UNSPECIFIED').toUpperCase();formats.set(f,[...(formats.get(f)||[]),c])}
 const metrics=(x:{tp:number;fp:number;fn:number})=>{const p=x.tp+x.fp?x.tp/(x.tp+x.fp):0,r=x.tp+x.fn?x.tp/(x.tp+x.fn):0,f1=p+r?2*p*r/(p+r):0;return {precision:p,recall:r,f1,precision95:wilson(x.tp,x.tp+x.fp),recall95:wilson(x.tp,x.tp+x.fn)}};
 const component=metrics(totals.nodes),connections=metrics(totals.edges);
 const stratified=[...formats].map(([format,items])=>({format,documentCount:items.length,independentlyLabeled:items.every(x=>x.independentlyLabeled===true)}));
 const independentlyLabeled=cases.every(x=>x.independentlyLabeled===true),minimumCorpus=cases.length>=30,formatCoverage=stratified.length>=2&&!stratified.some(x=>x.documentCount<5);
 const threshold=.90,lowerBoundsPass=component.precision95.low>=threshold&&component.recall95.low>=threshold&&connections.precision95.low>=threshold&&connections.recall95.low>=threshold;
 const qualifiedForExternalAccuracyClaim=independentlyLabeled&&minimumCorpus&&formatCoverage&&lowerBoundsPass;
 return {documentCount:cases.length,component,connections,stratified,qualification:{independentlyLabeled,minimumCorpus,formatCoverage,lowerBoundsPass,threshold},qualifiedForExternalAccuracyClaim,claimableAccuracyPercent:qualifiedForExternalAccuracyClaim?Math.floor(Math.min(component.precision,component.recall,connections.precision,connections.recall)*100):null,reason:qualifiedForExternalAccuracyClaim?'Independent representative benchmark passed conservative 95% confidence lower-bound gates.':'External accuracy claim blocked until independent labels, >=30 documents, >=2 formats with >=5 samples each, and 95% confidence lower bounds all meet the threshold.'};
}
