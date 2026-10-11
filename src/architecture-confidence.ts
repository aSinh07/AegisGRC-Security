export type ArchitectureConfidenceInput={components:{confidence:'EXPLICIT'|'INFERRED'}[];connections:{confidence:'EXPLICIT'|'INFERRED'}[];sourceQuality?:number;ocrUsed?:boolean;humanVerified?:boolean};
export function architectureConfidence(x:ArchitectureConfidenceInput){
 const q=Math.max(0,Math.min(1,Number(x.sourceQuality??1))),all=[...x.components,...x.connections];
 const explicit=all.filter(i=>i.confidence==='EXPLICIT').length,ratio=all.length?explicit/all.length:0;
 let score=(.55*ratio+.45*q)*100;if(x.ocrUsed)score-=8;if(x.humanVerified)score=Math.min(100,score+8);score=Math.round(Math.max(0,score));
 const band=score>=90?'HIGH':score>=70?'MEDIUM':'LOW';
 return {score,band,meaning:'Confidence is evidence quality/provenance, not measured extraction accuracy.',requiresReview:!x.humanVerified||score<90};
}
