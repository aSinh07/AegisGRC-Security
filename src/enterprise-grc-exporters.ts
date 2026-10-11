import PDFDocument from 'pdfkit';
import {Document,Packer,Paragraph,HeadingLevel,Table,TableRow,TableCell,WidthType} from 'docx';
import * as XLSX from 'xlsx';

const s=(v:any)=>v===null||v===undefined?'':String(v);
const docTable=(headers:string[],rows:any[][])=>new Table({width:{size:100,type:WidthType.PERCENTAGE},rows:[
 new TableRow({children:headers.map(h=>new TableCell({children:[new Paragraph(h)]}))}),
 ...rows.map(r=>new TableRow({children:r.map(v=>new TableCell({children:[new Paragraph(s(v))]}))}))
]});

export async function enterpriseGrcDocx(m:any){
 const controls=(m.controlAssurance||[]).map((x:any)=>[x.controlKey,x.title,x.applicability,x.implementation,x.readiness,(x.gaps||[]).join('; ')]);
 const risks=(m.riskRegister||[]).map((x:any)=>[x.risk_key,x.title,x.inherent_rating,x.treatment,x.status,x.acceptance_expires_at]);
 const issues=(m.issueRegister||[]).map((x:any)=>[x.issue_key,x.title,x.priority,x.status,x.due_at]);
 const children:any[]=[
  new Paragraph({text:'Enterprise Governance, Risk & Compliance Assurance Report',heading:HeadingLevel.TITLE}),
  new Paragraph('Organization: '+s(m.organization?.name)+' | Scope: '+s(m.scope?.name)),
  new Paragraph('Document ID: '+s(m.documentControl?.documentId)+' | Version: '+s(m.documentControl?.version)+' | '+s(m.documentControl?.classification)),
  new Paragraph('Generated: '+s(m.documentControl?.generatedAt)),
  new Paragraph({text:'Management Assurance Conclusion',heading:HeadingLevel.HEADING_1}),
  new Paragraph(s(m.managementOpinion?.conclusion)+' — '+s(m.managementOpinion?.statement)),
  new Paragraph('Evidence-readiness: '+s(m.managementOpinion?.evidenceReadinessPercent)+'% (internal readiness metric, not a compliance/certification score).'),
  new Paragraph({text:'Executive Summary',heading:HeadingLevel.HEADING_1}),
  ...Object.entries(m.executiveSummary||{}).map(([k,v])=>new Paragraph(k+': '+s(v))),
  new Paragraph({text:'Frameworks & Methodology',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Frameworks: '+((m.frameworks||[]).join(', ')||'No mapped framework recorded')),
  ...(m.methodology||[]).map((x:string)=>new Paragraph('• '+x)),
  new Paragraph({text:'Control Assurance & Gap Register',heading:HeadingLevel.HEADING_1}),
  docTable(['Control','Title','Applicability','Implementation','Readiness','Auditor Action / Gap'],controls),
  new Paragraph({text:'Risk Register',heading:HeadingLevel.HEADING_1}),
  docTable(['Risk','Title','Rating','Treatment','Status','Acceptance Expiry'],risks),
  new Paragraph({text:'Issue Register',heading:HeadingLevel.HEADING_1}),
  docTable(['Issue','Title','Priority','Status','Due'],issues),
  new Paragraph({text:'Priority Management Actions',heading:HeadingLevel.HEADING_1}),
  ...(m.priorityActions||[]).map((x:any)=>new Paragraph('• ['+s(x.priority)+'] '+s(x.type)+' '+s(x.key)+': '+s(x.action))),
  new Paragraph({text:'Assurance Boundary & Limitations',heading:HeadingLevel.HEADING_1}),
  ...(m.assuranceBoundary||[]).map((x:string)=>new Paragraph('• '+x))
 ];
 return Packer.toBuffer(new Document({sections:[{children}]}));
}

export function enterpriseGrcXlsx(m:any){
 const wb=XLSX.utils.book_new();
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet([{Organization:m.organization?.name,Scope:m.scope?.name,Conclusion:m.managementOpinion?.conclusion,ReadinessPercent:m.managementOpinion?.evidenceReadinessPercent,...m.executiveSummary}]),'Executive');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.controlAssurance||[]),'Control Assurance');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.statementOfApplicability||[]),'SoA');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.riskRegister||[]),'Risk Register');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.issueRegister||[]),'Issue Register');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.correctivePreventiveActions||[]),'CAPA');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.evidenceRegister||[]),'Evidence Register');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.technicalAssuranceCoverage||[]),'Technical Coverage');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.thirdPartyRisk?.vendors||[]),'Third Parties');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.thirdPartyRisk?.incidents||[]),'Vendor Incidents');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.architectureAssurance?.components||[]),'Architecture');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.architectureAssurance?.firewallReviews||[]),'Firewall Reviews');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.architectureAssurance?.gaps||[]),'Architecture Gaps');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.continuousCompliance?.obligations||[]),'Obligations');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.continuousCompliance?.exceptions||[]),'Exceptions');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.priorityActions||[]),'Priority Actions');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.assuranceBoundary||[]).map((x:string)=>({Limitation:x}))),'Limitations');
 return Buffer.from(XLSX.write(wb,{type:'buffer',bookType:'xlsx'}));
}

export function enterpriseGrcPdf(m:any){return new Promise<Buffer>((resolve,reject)=>{
 const d=new PDFDocument({margin:44,bufferPages:true}),chunks:Buffer[]=[];
 d.on('data',x=>chunks.push(x));d.on('end',()=>resolve(Buffer.concat(chunks)));d.on('error',reject);
 const h=(n:string,t:string)=>{d.moveDown().fontSize(15).text(n+' '+t).moveDown(.25)};
 d.fontSize(8).text('AEGISGRC | ENTERPRISE ASSURANCE | CONFIDENTIAL',{align:'right'});
 d.moveDown(2).fontSize(21).text('Enterprise Governance, Risk & Compliance Assurance Report');
 d.fontSize(10).text('Organization: '+s(m.organization?.name)).text('Scope: '+s(m.scope?.name))
  .text('Document ID: '+s(m.documentControl?.documentId)+' | Version: '+s(m.documentControl?.version))
  .text('Generated: '+s(m.documentControl?.generatedAt));
 h('1.','Management Assurance Conclusion');
 d.fontSize(12).text(s(m.managementOpinion?.conclusion)).fontSize(9).text(s(m.managementOpinion?.statement))
  .text('Internal evidence-readiness: '+s(m.managementOpinion?.evidenceReadinessPercent)+'% — not a certification score.');
 h('2.','Executive Summary');Object.entries(m.executiveSummary||{}).forEach(([k,v])=>d.fontSize(9).text(k+': '+s(v)));
 h('3.','Scope, Frameworks & Methodology');d.fontSize(9).text('Frameworks: '+((m.frameworks||[]).join(', ')||'No mapped framework recorded'));
 for(const x of m.methodology||[])d.text('• '+x);
 d.addPage();h('4.','Control Assurance & Gap Register');
 for(const c of m.controlAssurance||[]){d.fontSize(10).text(s(c.controlKey)+' · '+s(c.title)).fontSize(8)
  .text('Applicability: '+s(c.applicability)+' | Implementation: '+s(c.implementation)+' | Readiness: '+s(c.readiness))
  .text('Evidence: '+s(c.validEvidence)+' | Latest passing tests: '+s(c.passedLatestTests)+' | Open issues: '+s(c.openIssues))
  .text('Auditor action / gap: '+((c.gaps||[]).join(' ')||'No automated readiness gap recorded.')).moveDown(.5)}
 d.addPage();h('5.','Enterprise Risk Register');
 for(const r of m.riskRegister||[])d.fontSize(9).text(s(r.risk_key)+' | '+s(r.inherent_rating)+' | '+s(r.status)+' | '+s(r.title)).fontSize(8).text('Treatment: '+s(r.treatment)+' | Acceptance expiry: '+s(r.acceptance_expires_at||'N/A'));
 h('6.','Issues & CAPA');
 for(const i of m.issueRegister||[])d.fontSize(9).text(s(i.issue_key)+' | '+s(i.priority)+' | '+s(i.status)+' | '+s(i.title));
 for(const c of m.correctivePreventiveActions||[])d.fontSize(8).text('CAPA '+s(c.capa_key)+' | '+s(c.status)+' | Due '+s(c.due_at)+' | '+s(c.corrective_action));
 d.addPage();h('7.','Technical & Firewall/Security Evidence Coverage');
 if(!(m.technicalAssuranceCoverage||[]).length)d.fontSize(9).text('No linked assessment trace was supplied for this scope.');
 for(const x of m.technicalAssuranceCoverage||[])d.fontSize(8).text('Assessment '+s(x.assessmentId)+' | INFRA '+s(x.infrastructure)+' | WEB '+s(x.web)+' | API '+s(x.api)+' | CLOUD '+s(x.cloud)+' | ENDPOINT '+s(x.endpoint)+' | IDENTITY '+s(x.identity)+' | DATA '+s(x.dataSecurity)+' | PRIVACY '+s(x.privacy)+' | CODE '+s(x.sourceCode)+' | DEP '+s(x.dependencies)+' | CONTAINER '+s(x.container)+' | ATTACK SURFACE '+s(x.attackSurface)+' | BREACH TELEMETRY '+s(x.breachTelemetry));
 h('8.','Third-Party / Vendor Risk');
 d.fontSize(9).text('Vendors: '+s(m.thirdPartyRisk?.summary?.vendors||0)+' | Tier 1: '+s(m.thirdPartyRisk?.summary?.tier1||0)+' | Due review: '+s(m.thirdPartyRisk?.summary?.dueReview||0)+' | Open incidents: '+s(m.thirdPartyRisk?.summary?.openIncidents||0));
 for(const v of m.thirdPartyRisk?.vendors||[])d.fontSize(8).text(s(v.vendor_key)+' | '+s(v.tier)+' | '+s(v.criticality)+' | '+s(v.status)+' | '+s(v.name)+' | '+s(v.service));
 h('9.','Architecture & Firewall Assurance');
 d.fontSize(9).text('Components: '+s(m.architectureAssurance?.summary?.components||0)+' | Flows: '+s(m.architectureAssurance?.summary?.flows||0)+' | Security gateways: '+s(m.architectureAssurance?.summary?.securityGateways||0)+' | Reviewed gateways: '+s(m.architectureAssurance?.summary?.reviewedGateways||0));
 for(const g of m.architectureAssurance?.gaps||[])d.fontSize(8).text('• '+s(g.severity)+' '+s(g.type)+' '+s(g.component||g.componentId||g.edgeId||''));
 h('10.','Continuous Compliance, Obligations & Exceptions');
 d.fontSize(9).text('Obligations: '+s(m.continuousCompliance?.summary?.obligations||0)+' | Overdue: '+s(m.continuousCompliance?.summary?.overdueObligations||0)+' | Open exceptions: '+s(m.continuousCompliance?.summary?.openExceptions||0)+' | Expired exceptions: '+s(m.continuousCompliance?.summary?.expiredExceptions||0));
 h('11.','Priority Management Actions');for(const x of m.priorityActions||[])d.fontSize(9).text('• ['+s(x.priority)+'] '+s(x.type)+' '+s(x.key)+': '+s(x.action));
 h('12.','Assurance Boundary & Limitations');for(const x of m.assuranceBoundary||[])d.fontSize(9).text('• '+x);
 d.end();
})}
