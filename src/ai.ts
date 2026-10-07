import { GoogleGenAI } from '@google/genai';
import type { Finding } from './models.js';

function deterministic(findings:Finding[]){
 return findings.slice(0,50).map(f=>({
  id:f.id,severity:f.severity,title:f.title,cvss:f.cvss??null,cwe:f.cwe??null,
  remediation:f.remediation||'Review the affected control, apply the least disruptive secure configuration or code fix, then retest the original evidence path.',
  validation:'Retest the original finding and confirm the evidence no longer reproduces.',
  mappings:f.mappings
 }));
}
export async function explainFindings(findings:Finding[]){
 const base=deterministic(findings);
 const key=process.env.GEMINI_API_KEY;
 if(!key||!findings.length)return {mode:'INSTANT_REMEDIATION',source:'stored-evidence',items:base,aiStatus:key?'NO_FINDINGS':'NOT_CONFIGURED'};
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),850);
 try{
  const ai=new GoogleGenAI({apiKey:key});
  const safe=findings.slice(0,12).map(f=>({id:f.id,severity:f.severity,title:f.title,cvss:f.cvss,cwe:f.cwe,remediation:f.remediation,mappings:f.mappings}));
  const prompt='Return only a compact JSON array. Improve remediation for these defensive security findings. Never invent evidence. Each item: id, remediation, validation. Maximum 35 words per remediation and 20 per validation. Findings: '+JSON.stringify(safe);
  const model=(process.env.GEMINI_FAST_MODEL||process.env.GEMINI_MODEL||'gemini-3.8-flash').trim();
  const r=await ai.models.generateContent({model,contents:prompt,config:{maxOutputTokens:900,temperature:0.1},signal:controller.signal} as any);
  clearTimeout(timer);
  const raw=r.text||'';let enhanced:any[]=base;
  try{const parsed=JSON.parse(raw.replace(/^\`\`\`json\s*|\`\`\`$/g,''));if(Array.isArray(parsed)){const by=new Map(parsed.map((x:any)=>[x.id,x]));enhanced=base.map(x=>({...x,...(by.get(x.id)||{})}))}}catch{}
  return {mode:'AI_REMEDIATION',source:'stored-evidence+gemini',model,items:enhanced};
 }catch(e:any){
  clearTimeout(timer);
  return {mode:'INSTANT_REMEDIATION',source:'stored-evidence',aiStatus:e?.name==='AbortError'?'AI_TIMEOUT_FALLBACK':'AI_FALLBACK',items:base};
 }
}
