import { GoogleGenAI } from '@google/genai';
import type { Finding } from './models.js';
export async function explainFindings(findings:Finding[]){
 const key=process.env.GEMINI_API_KEY;
 if(!key) return {mode:'UNAVAILABLE',message:'GEMINI_API_KEY is not configured. Scanner evidence remains available without AI.',items:[]};
 const ai=new GoogleGenAI({apiKey:key});
 const safe=findings.slice(0,50).map(f=>({id:f.id,severity:f.severity,title:f.title,cwe:f.cwe,mappings:f.mappings}));
 const prompt='You are a defensive GRC remediation assistant. For each finding return concise remediation and validation guidance. Do not invent evidence. Findings: '+JSON.stringify(safe);
 const r=await ai.models.generateContent({model:process.env.GEMINI_MODEL||'gemini-2.5-flash',contents:prompt});
 return {mode:'AI_ANALYSIS',model:process.env.GEMINI_MODEL||'gemini-2.5-flash',text:r.text||''};
}