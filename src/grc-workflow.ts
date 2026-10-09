/**
 * ServiceNow-style GRC workflow transition policy.
 * Pure logic: authorization and persistence must be checked by the API layer.
 */
export type GrcWorkflowType='EVIDENCE'|'ISSUE'|'REMEDIATION'|'CONTROL_REVIEW'|'RISK_ACCEPTANCE';
export type GrcWorkflowRole='OWNER'|'REVIEWER'|'RISK_OWNER'|'GRC_MANAGER'|'ADMIN';
type StateMap=Record<string,Partial<Record<string,readonly GrcWorkflowRole[]>>>;
const policy:Record<GrcWorkflowType,StateMap>={
 EVIDENCE:{
  DRAFT:{SUBMITTED:['OWNER','ADMIN']},
  SUBMITTED:{APPROVED:['REVIEWER','GRC_MANAGER'],CHANGES_REQUESTED:['REVIEWER','GRC_MANAGER']},
  CHANGES_REQUESTED:{DRAFT:['OWNER','ADMIN']},
  APPROVED:{EXPIRED:['GRC_MANAGER','ADMIN']}
 },
 ISSUE:{
  OPEN:{ASSIGNED:['GRC_MANAGER','ADMIN']},
  ASSIGNED:{IN_PROGRESS:['OWNER','ADMIN']},
  IN_PROGRESS:{REMEDIATION_SUBMITTED:['OWNER','ADMIN']},
  REMEDIATION_SUBMITTED:{CLOSED:['REVIEWER','GRC_MANAGER'],CHANGES_REQUESTED:['REVIEWER','GRC_MANAGER']},
  CHANGES_REQUESTED:{IN_PROGRESS:['OWNER','ADMIN']},
  CLOSED:{REOPENED:['REVIEWER','GRC_MANAGER']},
  REOPENED:{ASSIGNED:['GRC_MANAGER','ADMIN']}
 },
 REMEDIATION:{
  OPEN:{IN_PROGRESS:['OWNER','ADMIN']},
  IN_PROGRESS:{RETEST_PENDING:['OWNER','ADMIN']},
  RETEST_PENDING:{VALIDATION:['REVIEWER','GRC_MANAGER']},
  VALIDATION:{CLOSED:['REVIEWER','GRC_MANAGER'],CHANGES_REQUESTED:['REVIEWER','GRC_MANAGER']},
  CHANGES_REQUESTED:{IN_PROGRESS:['OWNER','ADMIN']}
 },
 CONTROL_REVIEW:{
  DRAFT:{SUBMITTED:['OWNER','ADMIN']},
  SUBMITTED:{IN_REVIEW:['REVIEWER','GRC_MANAGER']},
  IN_REVIEW:{APPROVED:['REVIEWER','GRC_MANAGER'],CHANGES_REQUESTED:['REVIEWER','GRC_MANAGER'],REJECTED:['REVIEWER','GRC_MANAGER']},
  CHANGES_REQUESTED:{DRAFT:['OWNER','ADMIN']}
 },
 RISK_ACCEPTANCE:{
  DRAFT:{SUBMITTED:['RISK_OWNER','ADMIN']},
  SUBMITTED:{IN_REVIEW:['GRC_MANAGER']},
  IN_REVIEW:{APPROVED:['GRC_MANAGER'],REJECTED:['GRC_MANAGER'],CHANGES_REQUESTED:['GRC_MANAGER']},
  CHANGES_REQUESTED:{DRAFT:['RISK_OWNER','ADMIN']},
  APPROVED:{EXPIRED:['GRC_MANAGER','ADMIN']}
 }
};
export function allowedTransitions(type:GrcWorkflowType,from:string){
 return Object.keys(policy[type]?.[from]||{});
}
export function authorizeGrcTransition(input:{
 type:GrcWorkflowType;from:string;to:string;role:GrcWorkflowRole;
 actorId:string;ownerId?:string|null;submitterId?:string|null;
 evidenceValidated?:boolean;retestPassed?:boolean;reason?:string;
 expiry?:string|null;
}):{ok:boolean;reason:string}{
 const {type,from,to,role,actorId,ownerId,submitterId}=input;
 const roles=policy[type]?.[from]?.[to];
 if(!roles||!roles.includes(role))return {ok:false,reason:'Transition or role not permitted'};
 if(!actorId)return {ok:false,reason:'Authenticated actor required'};
 if(role==='OWNER'&&ownerId!==actorId)return {ok:false,reason:'Record owner required'};
 if(['APPROVED','CLOSED'].includes(to)&&submitterId===actorId)
   return {ok:false,reason:'Separation of duties: self-approval is prohibited'};
 if(type==='EVIDENCE'&&to==='APPROVED'&&!input.evidenceValidated)
   return {ok:false,reason:'Validated evidence required'};
 if(type==='REMEDIATION'&&to==='CLOSED'&&!input.retestPassed)
   return {ok:false,reason:'Passing retest required'};
 if(type==='ISSUE'&&to==='CLOSED'&&!input.retestPassed)
   return {ok:false,reason:'Passing retest or approved exception required'};
 if(type==='RISK_ACCEPTANCE'&&to==='APPROVED'&&(!input.expiry||Date.parse(input.expiry)<=Date.now()))
   return {ok:false,reason:'Future expiry date required'};
 if(['CHANGES_REQUESTED','REJECTED','REOPENED'].includes(to)&&!input.reason?.trim())
   return {ok:false,reason:'Reason required'};
 return {ok:true,reason:'Allowed by workflow policy; persist in an authorized transaction'};
}
