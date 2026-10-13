export type ReadinessPackDefinition={
 key:string;title:string;framework:string;frameworkVersion:string;sourceClass:'IMPLEMENTATION_AID'|'EDUCATIONAL';
 disclaimer:string;items:{key:string;type:'ASSESSMENT_QUESTION'|'EVIDENCE_EXPECTATION'|'RISK_PATTERN';title:string;prompt:string;sourceLocator:string}[];
};

const readinessDisclaimer='Derived readiness guidance from a supplied reference document. It does not reproduce or replace an official standard and does not establish certification, conformity, or legal compliance.';

export const SOURCE_GROUNDED_READINESS_PACKS:ReadinessPackDefinition[]=[
 {key:'ISO27001_ISMS_READINESS',title:'ISO 27001 ISMS Readiness',framework:'ISO27001',frameworkVersion:'2022',sourceClass:'IMPLEMENTATION_AID',disclaimer:readinessDisclaimer,items:[
  {key:'ISO-CONTEXT',type:'ASSESSMENT_QUESTION',title:'Context and interested parties',prompt:'Has the organization documented relevant internal/external issues, interested parties and their applicable requirements?',sourceLocator:'ISO 27001 gap questionnaire: clauses 4.1-4.2'},
  {key:'ISO-SCOPE',type:'ASSESSMENT_QUESTION',title:'ISMS scope',prompt:'Are the ISMS boundaries, applicability, interfaces, dependencies and locations documented?',sourceLocator:'ISO 27001 gap questionnaire: clause 4.3'},
  {key:'ISO-LEADERSHIP',type:'ASSESSMENT_QUESTION',title:'Leadership and policy',prompt:'Can leadership commitment, resources, information-security policy and communicated responsibilities be evidenced?',sourceLocator:'ISO 27001 gap questionnaire: clauses 5.1-5.3'},
  {key:'ISO-RISK-SOA',type:'EVIDENCE_EXPECTATION',title:'Risk and applicability evidence',prompt:'Collect the risk assessment methodology, risk register, Statement of Applicability, risk treatment plan and risk assessment report.',sourceLocator:'ISMS implementation guide: master documents register / certification roadmap'},
  {key:'ISO-ASSETS',type:'EVIDENCE_EXPECTATION',title:'Asset inventory',prompt:'Collect an inventory of information, processes and associated assets with ownership, CIA classification and criticality.',sourceLocator:'ISMS implementation checklist: Inventory of Assets'}
 ]},
 {key:'NIST_EVIDENCE_READINESS',title:'NIST Evidence Readiness',framework:'NIST-CSF',frameworkVersion:'2.0',sourceClass:'IMPLEMENTATION_AID',disclaimer:readinessDisclaimer,items:[
  {key:'NIST-GOVERN',type:'ASSESSMENT_QUESTION',title:'Governance',prompt:'Are cybersecurity strategy, responsibilities, risk appetite, third-party risk and leadership oversight documented?',sourceLocator:'NIST audit checklist: GOVERN'},
  {key:'NIST-IDENTIFY',type:'EVIDENCE_EXPECTATION',title:'Identify evidence',prompt:'Collect asset inventory, ownership/classification, recent risk assessment, vulnerability reports and supply-chain risk records.',sourceLocator:'NIST audit checklist: IDENTIFY'},
  {key:'NIST-PROTECT',type:'EVIDENCE_EXPECTATION',title:'Protection evidence',prompt:'Collect evidence for MFA, least privilege/RBAC review, joiner-mover-leaver controls, service accounts, training, encryption, backups and data-loss controls.',sourceLocator:'NIST audit checklist: PROTECT'},
  {key:'NIST-DETECT-RESPOND',type:'EVIDENCE_EXPECTATION',title:'Detection and response',prompt:'Collect centralized logging/alert evidence and the documented, tested incident-response process.',sourceLocator:'NIST audit checklist: DETECT and RESPOND'},
  {key:'NIST-RECOVER',type:'EVIDENCE_EXPECTATION',title:'Recovery evidence',prompt:'Collect DR/BCP test evidence, RTO/RPO definitions and post-incident lessons-learned records.',sourceLocator:'NIST audit checklist: RECOVER'}
 ]},
 {key:'AI_IMPACT_READINESS',title:'AI System Impact Assessment Readiness',framework:'ISO42001/ISO42005',frameworkVersion:'42001:2023;42005:2025',sourceClass:'IMPLEMENTATION_AID',disclaimer:readinessDisclaimer,items:[
  {key:'AI-CONTEXT',type:'ASSESSMENT_QUESTION',title:'Context-sensitive impact assessment',prompt:'Has the impact assessment been adapted to organizational context, obligations and risk criteria before consequential deployment?',sourceLocator:'GCAI AI System Impact Assessment v1.0: Intended use'},
  {key:'AI-LIFECYCLE',type:'ASSESSMENT_QUESTION',title:'Lifecycle reassessment',prompt:'Is the assessment updated when system context, capability, scale or evidence changes?',sourceLocator:'GCAI AI System Impact Assessment v1.0: Intended use'},
  {key:'AI-EVIDENCE',type:'EVIDENCE_EXPECTATION',title:'Controlled evidence and uncertainty',prompt:'Link assessment statements to controlled evidence and record uncertainty, dissent and unresolved assumptions.',sourceLocator:'GCAI AI System Impact Assessment v1.0: Intended use'},
  {key:'AI-COORDINATION',type:'ASSESSMENT_QUESTION',title:'Cross-domain review',prompt:'Where applicable, is AI impact assessment coordinated with privacy, security, safety, human-rights, accessibility, environmental and sector-specific reviews?',sourceLocator:'GCAI AI System Impact Assessment v1.0: Intended use'}
 ]},
 {key:'OWASP_LLM_2026_READINESS',title:'OWASP LLM 2026 Security Readiness',framework:'OWASP-LLM',frameworkVersion:'2026',sourceClass:'EDUCATIONAL',disclaimer:readinessDisclaimer,items:[
  {key:'LLM01',type:'RISK_PATTERN',title:'Prompt Injection',prompt:'Assess direct, retrieved, tool-output, multimodal and persistent-memory inputs for unintended instruction influence and propagation.',sourceLocator:'OWASP LLM01:2026 Prompt Injection'},
  {key:'LLM02',type:'RISK_PATTERN',title:'Sensitive Information Disclosure',prompt:'Assess whether model outputs can expose sensitive information, private retrieved content, secrets or internal reasoning/context.',sourceLocator:'OWASP LLM02:2026 Sensitive Information Disclosure'},
  {key:'LLM03',type:'RISK_PATTERN',title:'Excessive Agency',prompt:'Assess excessive functionality, permissions and autonomy for model-driven tool actions.',sourceLocator:'OWASP LLM03:2026 Excessive Agency'},
  {key:'LLM04',type:'RISK_PATTERN',title:'Supply Chain',prompt:'Assess dependencies, models, datasets, adapters, plugins and external components for provenance, integrity and supply-chain compromise.',sourceLocator:'OWASP LLM04:2026 Supply Chain'},
  {key:'LLM05',type:'RISK_PATTERN',title:'Data and Model Poisoning',prompt:'Assess training, fine-tuning, retrieval and feedback data as well as model artifacts for poisoning that can alter behavior, integrity or security.',sourceLocator:'OWASP LLM05:2026 Data and Model Poisoning'},
  {key:'LLM06',type:'RISK_PATTERN',title:'Unbounded Consumption',prompt:'Assess controls that bound model, agent, tool and infrastructure resource consumption and limit denial-of-service or unexpected cost exposure.',sourceLocator:'OWASP LLM06:2026 Unbounded Consumption'},
  {key:'LLM07',type:'RISK_PATTERN',title:'Misinformation',prompt:'Assess incorrect, incomplete, unsupported or misleading outputs that could drive human, workflow or agent actions.',sourceLocator:'OWASP LLM07:2026 Misinformation'},
  {key:'LLM08',type:'RISK_PATTERN',title:'Hidden Context Exposure',prompt:'Assess whether hidden prompts, system context, retrieved context, metadata or other non-user-visible instructions and data can be exposed or improperly inferred.',sourceLocator:'OWASP LLM08:2026 Hidden Context Exposure'},
  {key:'LLM09',type:'RISK_PATTERN',title:'Vector and Embedding Weaknesses',prompt:'Assess vector stores, embeddings and retrieval pipelines for unauthorized access, cross-tenant leakage, manipulation and unsafe retrieval behavior.',sourceLocator:'OWASP LLM09:2026 Vector and Embedding Weaknesses'},
  {key:'LLM10',type:'RISK_PATTERN',title:'Improper Output Handling',prompt:'Assess validation and sanitization of model outputs before they reach downstream components.',sourceLocator:'OWASP LLM10:2026 Improper Output Handling'}
 ]}
];

export function validateReadinessPackDefinitions(){
 const keys=new Set<string>();
 for(const pack of SOURCE_GROUNDED_READINESS_PACKS){
  if(!pack.disclaimer.includes('does not establish certification'))throw new Error('Readiness pack disclaimer required');
  for(const item of pack.items){
   const id=pack.key+':'+item.key;if(keys.has(id))throw new Error('Duplicate readiness item '+id);keys.add(id);
   if(!item.sourceLocator.trim())throw new Error('Source locator required for '+id);
  }
 }
 return {packs:SOURCE_GROUNDED_READINESS_PACKS.length,items:keys.size};
}


export function readinessPackCatalog(){
 return SOURCE_GROUNDED_READINESS_PACKS.map(pack=>({
  key:pack.key,title:pack.title,framework:pack.framework,frameworkVersion:pack.frameworkVersion,
  sourceClass:pack.sourceClass,itemCount:pack.items.length,disclaimer:pack.disclaimer
 }));
}

export function readinessPackDefinition(key:string){
 const normalized=String(key||'').trim().toUpperCase();
 const pack=SOURCE_GROUNDED_READINESS_PACKS.find(x=>x.key===normalized);
 if(!pack)return null;
 return {...pack,items:pack.items.map(item=>({...item}))};
}
