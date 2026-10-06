import crypto from 'node:crypto';
const secret=()=>process.env.ASSESSMENT_SESSION_SECRET||process.env.EVIDENCE_HMAC_KEY||'dev-only-change-me';
export function issueSession(assessmentId:string,targetOrigin:string,ttlMs=4*60*60*1000){
 const payload={assessmentId,targetOrigin,exp:Date.now()+ttlMs}; const body=Buffer.from(JSON.stringify(payload)).toString('base64url');
 const sig=crypto.createHmac('sha256',secret()).update(body).digest('base64url'); return body+'.'+sig;
}
export function verifySession(token:string){
 const [body,sig]=token.split('.'); if(!body||!sig) throw new Error('Missing assessment session');
 const expected=crypto.createHmac('sha256',secret()).update(body).digest('base64url');
 if(sig.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))) throw new Error('Invalid assessment session');
 const p=JSON.parse(Buffer.from(body,'base64url').toString()); if(Date.now()>p.exp) throw new Error('Assessment session expired'); return p as {assessmentId:string;targetOrigin:string;exp:number};
}