import { GoogleGenAI } from '@google/genai';
import type { Assessment,Finding } from './models.js';
import { frameworkCatalog } from './grc.js';

export type CopilotMode='beginner'|'technical'|'developer'|'grc'|'executive';
const modes=new Set<CopilotMode>(['beginner','technical','developer','grc','executive']);

export async function askCopilot(question:string,mode:string,assessment?:Assessment|null,findings:Finding[]=[]){
 const key=process.env.GEMINI_API_KEY;
 if(!key) return {mode:'UNAVAILABLE',message:'Gemini is not configured.'};
 const view:modesView={mode:modes.has(mode as CopilotMode)?mode as CopilotMode:'beginner'};
 const evidence=findings.slice(0,100).map(f=>({id:f.id,source:f.source,title:f.title,severity:f.severity,cwe:f.cwe,cvss:f.cvss,asset:f.asset,evidenceHash:f.evidenceHash,mappings:f.mappings,remediation:f.remediation,status:f.status}));
 const system=`You are Aegis AI, a READ-ONLY cybersecurity and GRC explanation assistant.
Act as a helpful conversational AI for the AegisGRC platform. Reply naturally to greetings and ordinary questions, and answer general cybersecurity, GRC, CVSS, OWASP, secure-development, defensive-security, compliance, platform-usage, and assessment questions. When assessment evidence is available, use it for assessment-specific answers.
Never claim certification, compliance, exploitability, breach, or scanner evidence that is not present in CONTEXT.
Never provide attack commands, payloads, exploit instructions, credential attacks, persistence, evasion, or instructions to operate security tools.
Do not reproduce copyrighted ISO standard text. Explain referenced controls at a high level.
Clearly distinguish scanner evidence, GRC cross-reference, and AI interpretation.
For general knowledge questions you may answer from your model knowledge. For claims about the user's current assessment, never invent evidence: if the required assessment evidence is missing, say what evidence is missing.
Adapt language to audience MODE:
beginner=simple language and define jargon; technical=precise security explanation; developer=fix and validation focus; grc=control/risk/evidence/audit focus; executive=business impact and priorities.
When referring to a finding, include its finding id/source/evidence hash when useful so the answer is traceable.`;
 const context={assessment:assessment?{id:assessment.id,target:assessment.target,status:assessment.status,authorizedAt:assessment.authorizedAt}:null,findings:evidence,frameworkCatalog,platform:'AegisGRC Security'};
 const ai=new GoogleGenAI({apiKey:key});
 const preferred=process.env.GEMINI_MODEL||'gemini-2.5-flash';let model=preferred,r:any;
 try{r=await ai.models.generateContent({model,contents:system+'\nMODE: '+view.mode+'\nCONTEXT: '+JSON.stringify(context)+'\nUSER QUESTION: '+question})}
 catch(e){if(preferred==='gemini-2.5-flash')throw e;model='gemini-2.5-flash';r=await ai.models.generateContent({model,contents:system+'\nMODE: '+view.mode+'\nCONTEXT: '+JSON.stringify(context)+'\nUSER QUESTION: '+question})}
 return {mode:'AI_EXPLANATION',audience:view.mode,model,text:r.text||'',evidenceFindingIds:evidence.map(x=>x.id)};
}
type modesView={mode:CopilotMode};
