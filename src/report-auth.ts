import crypto from 'node:crypto';

function canonicalize(value:any):any {
  if(Array.isArray(value)) return value.map(canonicalize);
  if(value && typeof value==='object'){
    return Object.keys(value).sort().reduce((out:any,key)=>{
      if(value[key]!==undefined) out[key]=canonicalize(value[key]);
      return out;
    },{});
  }
  return value;
}

export function canonicalReportSnapshot(model:any){
  return JSON.stringify(canonicalize(model));
}

export function reportSnapshotDigest(model:any){
  // Exclude presentation-only clock fields; the governed report content remains signed.
  const {generatedAt,documentControl,executiveSummary,...rest}=model||{};
  const stableDocumentControl=documentControl?Object.fromEntries(Object.entries(documentControl).filter(([key])=>key!=='generatedAt')):documentControl;
  const stable={...rest,documentControl:stableDocumentControl,executiveSummary:executiveSummary?Object.fromEntries(Object.entries(executiveSummary).filter(([key])=>key!=='overdueIssues')):executiveSummary};
  return crypto.createHash('sha256').update(canonicalReportSnapshot(stable)).digest('hex');
}

function signingKey(){
  const key=String(process.env.REPORT_SIGNING_KEY||'');
  if(key.length<32) throw new Error('REPORT_SIGNING_KEY must be configured with at least 32 characters');
  return key;
}

export function signApprovedReport(input:{reviewId:string;assessmentId:string;framework:string;snapshotDigest:string;reviewerId:string;approvedAt:string}){
  const payload=[
    'AEGISGRC_REPORT_APPROVAL_V1',
    input.reviewId,input.assessmentId,input.framework,input.snapshotDigest,input.reviewerId,input.approvedAt
  ].join('|');
  return crypto.createHmac('sha256',signingKey()).update(payload).digest('hex');
}

export function verifyApprovedReportSignature(input:{reviewId:string;assessmentId:string;framework:string;snapshotDigest:string;reviewerId:string;approvedAt:string;signature:string}){
  const expected=signApprovedReport(input);
  const actual=String(input.signature||'');
  if(!/^[a-f0-9]{64}$/i.test(actual)||expected.length!==actual.length) return false;
  const expectedBytes=Buffer.from(expected,'hex'),actualBytes=Buffer.from(actual,'hex');
  if(expectedBytes.length!==actualBytes.length)return false;
  return crypto.timingSafeEqual(expectedBytes,actualBytes);
}
