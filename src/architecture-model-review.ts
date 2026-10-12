import crypto from 'node:crypto';
import type { ArchitectureNode,ArchitectureEdge } from './architecture-document-model.js';

export type ArchitectureReviewStatus='DRAFT'|'IN_REVIEW'|'VERIFIED'|'REJECTED';
export type ArchitectureModelRecord={
 id:string;organizationId:string;name:string;sourceName:string;sourceSha256:string;
 nodes:ArchitectureNode[];edges:ArchitectureEdge[];status:ArchitectureReviewStatus;
 createdBy:string;createdAt:string;reviewedBy?:string;reviewedAt?:string;reviewNote?:string;
};

export function normalizeArchitectureModel(input:any,ctx:{organizationId:string;userId:string;sourceName:string;sourceSha256:string}):ArchitectureModelRecord{
 const nodes=Array.isArray(input?.nodes)?input.nodes:[];
 const edges=Array.isArray(input?.edges)?input.edges:[];
 if(!nodes.length)throw new Error('Architecture model must contain at least one extracted component');
 const ids=new Set(nodes.map((n:any)=>String(n.id)));
 if(edges.some((e:any)=>!ids.has(String(e.from))||!ids.has(String(e.to))))throw new Error('Architecture connection references an unknown component');
 return {
  id:crypto.randomUUID(),organizationId:ctx.organizationId,name:String(input?.name||ctx.sourceName||'Architecture model').trim().slice(0,160),
  sourceName:ctx.sourceName.replace(/[\\/\0]/g,'_').slice(0,240),sourceSha256:ctx.sourceSha256,
  nodes,edges,status:'DRAFT',createdBy:ctx.userId,createdAt:new Date().toISOString()
 };
}
export function transitionArchitectureReview(model:ArchitectureModelRecord,next:ArchitectureReviewStatus,actor:string,note=''){
 if(next==='VERIFIED'&&actor===model.createdBy)throw new Error('Independent reviewer required to verify an architecture model');
 const allowed:Record<ArchitectureReviewStatus,ArchitectureReviewStatus[]>={DRAFT:['IN_REVIEW'],IN_REVIEW:['VERIFIED','REJECTED'],VERIFIED:['IN_REVIEW'],REJECTED:['IN_REVIEW']};
 if(!allowed[model.status].includes(next))throw new Error('Invalid architecture review transition');
 return {...model,status:next,reviewedBy:next==='VERIFIED'||next==='REJECTED'?actor:model.reviewedBy,reviewedAt:next==='VERIFIED'||next==='REJECTED'?new Date().toISOString():model.reviewedAt,reviewNote:String(note||'').slice(0,1000)};
}
export function architectureModelDigest(model:ArchitectureModelRecord){
 const canonical=JSON.stringify({organizationId:model.organizationId,sourceSha256:model.sourceSha256,nodes:model.nodes,edges:model.edges});
 return crypto.createHash('sha256').update(canonical).digest('hex');
}
