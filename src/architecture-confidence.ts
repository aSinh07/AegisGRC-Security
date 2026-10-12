export type ArchitectureConfidenceInput={components:{confidence:'EXPLICIT'|'INFERRED'}[];connections:{confidence:'EXPLICIT'|'INFERRED'}[];sourceQuality?:number;ocrUsed?:boolean;humanVerified?:boolean};
export function architectureConfidence(x:ArchitectureConfidenceInput){
 if(!x||!Array.isArray(x.components)||!Array.isArray(x.connections))throw Error('Invalid architecture confidence input');
 const raw=Number(x.sourceQuality??1),q=Number.isFinite(raw)?Math.max(0,Math.min(1,raw)):0;
 const all=[...x.components,...x.connections],explicit=all.filter(i=>i?.confidence==='EXPLICIT').length,ratio=all.length?explicit/all.length:0;
 // User-reported human verification cannot substitute for a server-side review record.
 let score=(.55*ratio+.45*q)*100;if(x.ocrUsed)score-=8;score=Math.round(Math.max(0,Math.min(100,score)));
 const band=score>=90?'HIGH':score>=70?'MEDIUM':'LOW';
 return {score,band,meaning:'Confidence is evidence quality/provenance, not measured extraction accuracy.',requiresReview:true,advisoryOnly:true,humanReviewClaimed:x.humanVerified===true};
}
