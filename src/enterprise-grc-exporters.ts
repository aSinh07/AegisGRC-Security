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
  new Paragraph({text:'Third-Party, Architecture & Continuous Compliance',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Vendors: '+s(m.thirdPartyRisk?.summary?.vendors||0)+' | Architecture gaps: '+s(m.architectureAssurance?.summary?.gaps||0)+' | Overdue obligations: '+s(m.continuousCompliance?.summary?.overdueObligations||0)),
  new Paragraph({text:'Operational Resilience',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Business services: '+s(m.operationalResilience?.summary?.services||0)+' | Tested: '+s(m.operationalResilience?.summary?.tested||0)+' | Resilience gaps: '+s(m.operationalResilience?.summary?.gaps||0)),
  docTable(['Service','Gap','Severity'],(m.operationalResilience?.gaps||[]).map((x:any)=>[x.service,x.type,x.severity])),
  new Paragraph({text:'Policy Governance',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Policies: '+s(m.policyGovernance?.summary?.total||0)+' | Approved: '+s(m.policyGovernance?.summary?.approved||0)+' | Overdue review: '+s(m.policyGovernance?.summary?.overdueReview||0)+' | Unmapped: '+s(m.policyGovernance?.summary?.unmapped||0)),
  new Paragraph({text:'Audit Management',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Audits: '+s(m.auditManagement?.summary?.total||0)+' | Active: '+s(m.auditManagement?.summary?.active||0)+' | Complete: '+s(m.auditManagement?.summary?.complete||0)+' | Unreviewed workpapers: '+s(m.auditManagement?.summary?.unreviewed||0)),
  new Paragraph('ISO 42001 audit evidence requests: '+s(m.iso42001AuditEvidenceReadiness?.summary?.evidenced||0)+'/'+s(m.iso42001AuditEvidenceReadiness?.summary?.total||0)+' evidenced | Action required: '+s(m.iso42001AuditEvidenceReadiness?.summary?.actionRequired||0)),
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
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.operationalResilience?.services||[]),'Resilience Services');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.operationalResilience?.latestExercises||[]),'Resilience Tests');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.operationalResilience?.gaps||[]),'Resilience Gaps');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.policyGovernance?.policies||[]),'Policies');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.auditManagement?.audits||[]),'Audits');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.iso42001AuditEvidenceReadiness?.requests||[]),'ISO42001 Audit Evidence');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.priorityActions||[]),'Priority Actions');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.assuranceBoundary||[]).map((x:string)=>({Limitation:x}))),'Limitations');
 return Buffer.from(XLSX.write(wb,{type:'buffer',bookType:'xlsx'}));
}

export function enterpriseGrcPdf(m:any){return new Promise<Buffer>((resolve,reject)=>{
 const d=new PDFDocument({size:'A4',margin:42,bufferPages:true,info:{Title:s(m.documentControl?.title),Author:'AegisGRC Security',Subject:'Enterprise GRC internal assurance report'}}),chunks:Buffer[]=[];
 d.on('data',x=>chunks.push(x));d.on('end',()=>resolve(Buffer.concat(chunks)));d.on('error',reject);
 const navy='#17365D',blue='#2F75B5',pale='#D9EAF7',ink='#202833',muted='#5B6573',line='#AAB7C4',good='#2E7D32',warn='#9A6700',bad='#B42318';
 const pageW=595.28,left=42,right=42,width=pageW-left-right;
 let sectionNo=0;
 const pageChrome=()=>{d.rect(0,0,pageW,12).fill(navy);d.rect(left,28,30,4).fill(blue);d.fillColor(navy).font('Helvetica-Bold').fontSize(9).text('AEGISGRC',left,38,{width:150,lineBreak:false});d.fillColor(muted).font('Helvetica').fontSize(6).text('SECURITY ASSURANCE PLATFORM',left,51,{width:180,lineBreak:false});d.fillColor(muted).font('Helvetica').fontSize(7).text('CONFIDENTIAL',pageW-right-120,40,{width:120,align:'right',lineBreak:false});d.y=78;d.x=left};
 const addContentPage=()=>{d.addPage({size:'A4',margin:42});pageChrome()};
 const ensure=(h=70)=>{if(d.y+h>755)addContentPage()};
 const rule=()=>{d.strokeColor(blue).lineWidth(1).moveTo(left,d.y).lineTo(pageW-right,d.y).stroke();d.moveDown(.45)};
 const h1=(n:string,t:string)=>{ensure(55);sectionNo++;const num=String(Number(n.replace('.',''))||sectionNo).padStart(2,'0');const y=d.y+4;d.roundedRect(left,y,width,34,4).fill(navy);d.fillColor('#18B6C9').font('Helvetica-Bold').fontSize(10).text(num,left+12,y+11,{width:28,lineBreak:false});d.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(13).text(t,left+54,y+9,{width:width-66,lineBreak:false});d.y=y+43;d.x=left};
 const h2=(t:string)=>{ensure(38);d.moveDown(.35).fillColor(blue).font('Helvetica-Bold').fontSize(10).text(t);d.moveDown(.2)};
 const p=(t:any,size=8.5)=>{ensure(28);d.fillColor(ink).font('Helvetica').fontSize(size).text(s(t),{lineGap:2});d.moveDown(.35)};
 const kv=(k:string,v:any)=>{ensure(22);d.fillColor(muted).font('Helvetica-Bold').fontSize(7.5).text(k.toUpperCase(),{continued:true});d.fillColor(ink).font('Helvetica').text('  '+s(v));};
 const badge=(label:string,value:any)=>{const x=d.x,y=d.y;d.roundedRect(x,y,118,38,4).fillAndStroke('#F5F8FB',line);d.fillColor(navy).font('Helvetica-Bold').fontSize(14).text(s(value),x+8,y+7,{width:102});d.fillColor(muted).font('Helvetica').fontSize(6.7).text(label.toUpperCase(),x+8,y+24,{width:102});d.x=x+126;d.y=y};
 const table=(headers:string[],data:any[][],widths:number[])=>{
  const draw=(vals:any[],header=false)=>{const fs=header?7:6.8,pad=4;const heights=vals.map((v,i)=>d.heightOfString(s(v),{width:widths[i]-pad*2,lineGap:1}));const rh=Math.max(header?20:18,...heights.map(x=>x+pad*2));ensure(rh+8);let x=left,y=d.y;for(let i=0;i<vals.length;i++){d.rect(x,y,widths[i],rh).fillAndStroke(header?pale:'#FFFFFF',line);d.fillColor(header?navy:ink).font(header?'Helvetica-Bold':'Helvetica').fontSize(fs).text(s(vals[i]),x+pad,y+pad,{width:widths[i]-pad*2,height:rh-pad*2,lineGap:1});x+=widths[i]}d.y=y+rh;d.x=left;};
  draw(headers,true);for(const row of data)draw(row,false);d.moveDown(.45);
 };
 const conclusion=s(m.managementOpinion?.conclusion),statusColor=conclusion==='AUDIT_READY'?good:conclusion==='INSUFFICIENT_EVIDENCE'?warn:bad;
 d.rect(0,0,pageW,12).fill(navy);d.rect(left,30,34,4).fill(blue);d.fillColor(navy).font('Helvetica-Bold').fontSize(10).text('AEGISGRC',left,42,{width:160,lineBreak:false});d.fillColor(muted).font('Helvetica').fontSize(6.5).text('SECURITY ASSURANCE PLATFORM',left,56,{width:190,lineBreak:false});d.fillColor(muted).font('Helvetica').fontSize(7).text('CONFIDENTIAL',pageW-right-120,44,{width:120,align:'right',lineBreak:false});
 d.y=142;d.fillColor(blue).font('Helvetica-Bold').fontSize(11).text('AEGIS GRC',{characterSpacing:1.2});d.moveDown(.35).fillColor(navy).font('Helvetica-Bold').fontSize(26).text('ENTERPRISE GRC\nASSURANCE REPORT',{lineGap:5});
 d.moveDown(.55);d.x=left;d.fillColor(blue).font('Helvetica').fontSize(11).text('Governance · Risk · Compliance · Evidence Assurance',left,d.y,{width:width});
 d.moveDown(.4);d.x=left;d.fillColor(muted).fontSize(9).text('Evidence-led readiness, risk, control assurance and accountable management action',left,d.y,{width:width});
 d.moveDown(1.2);rule();
 kv('Organization',m.organization?.name||'Not recorded');kv('Scope',m.scope?.name||'Not recorded');kv('Frameworks',(m.frameworks||[]).join(', ')||'No mapped framework recorded');kv('Document ID',m.documentControl?.documentId);kv('Version / status',s(m.documentControl?.version)+' / '+s(m.documentControl?.status));kv('Generated',m.documentControl?.generatedAt);
 d.moveDown(1.2).fillColor(statusColor).font('Helvetica-Bold').fontSize(16).text(conclusion||'INTERNAL ASSESSMENT');
 d.fillColor(ink).font('Helvetica').fontSize(9).text(s(m.managementOpinion?.statement),{lineGap:2});
 d.moveDown(.8).fillColor(muted).fontSize(8).text('This package is an internal readiness and control-assurance artifact. It is not certification, accreditation, legal advice or an external audit opinion.');
 addContentPage();
 h1('1.','Executive GRC Summary');
 const e=m.executiveSummary||{};badge('Evidence readiness',s(m.managementOpinion?.evidenceReadinessPercent)+'%');badge('Applicable controls',e.controlsApplicable||0);badge('High/Critical risks',e.highCriticalRisks||0);badge('Open CAPA',e.openCapa||0);d.x=left;d.y+=48;
 table(['Indicator','Current position','Management interpretation'],[
  ['Control assurance',s(e.controlsEvidenceReady||0)+' evidence-ready / '+s(e.controlsTotal||0)+' total','Missing, stale or unapproved evidence remains action-required.'],
  ['Risk posture',s(e.openRisks||0)+' open; '+s(e.highCriticalRisks||0)+' high/critical','Residual risk requires accountable treatment or acceptance.'],
  ['Issues & CAPA',s(e.openIssues||0)+' issues; '+s(e.openCapa||0)+' CAPA','Closure requires evidence and governed retest/review.'],
  ['Enterprise workflows',s(e.enterpriseWorkflowGaps||0)+' disclosed gaps','Includes architecture, resilience, policy, obligations, audit and supplier signals.']
 ],[112,118,281]);
 h1('2.','Scope, Frameworks & Assessment Methodology');p('Frameworks: '+((m.frameworks||[]).join(', ')||'No framework mappings recorded for the scoped controls.'));
 for(const x of m.methodology||[])p('• '+x,8);
 h1('3.','Statement of Applicability / Applicability Record');
 const soa=(m.statementOfApplicability||[]).slice(0,80);
 if(!soa.length)p('No approved applicability records were supplied for this scope.');
 else table(['Control','Applicability','Implementation','Approval'],soa.map((x:any)=>[x.control_key||x.controlKey,x.applicability,x.implementation,x.approved_at?'APPROVED':'PENDING']),[126,110,135,140]);
 h1('4.','Control Assurance & Framework Traceability');
 for(const c of m.controlAssurance||[]){ensure(78);h2(s(c.controlKey)+' · '+s(c.title));p('Domain: '+s(c.domain)+'   |   Applicability: '+s(c.applicability)+'   |   Implementation: '+s(c.implementation)+'   |   Readiness: '+s(c.readiness),7.8);p('Validated evidence: '+s(c.validEvidence)+'   |   Latest passing tests: '+s(c.passedLatestTests)+'   |   Open issues: '+s(c.openIssues),7.8);const maps=[...new Map((c.frameworkMappings||[]).map((x:any)=>[s(x.framework).trim().toUpperCase()+'|'+s(x.requirementKey||x.requirement_key).trim().toUpperCase(),x])).values()].map((x:any)=>s(x.framework)+(s(x.requirementKey||x.requirement_key)?' > '+s(x.requirementKey||x.requirement_key):'')).join('; ');if(maps)p('Framework traceability: '+maps+' → Evidence '+s(c.validEvidence)+' → Test '+(Number(c.passedLatestTests)>0?'PASS':'NOT_TESTED/ACTION_REQUIRED')+' > '+s(c.readiness),7.6);if((c.gaps||[]).length)p('Required action: '+c.gaps.join(' '),7.8)}
 h1('5.','Enterprise Risk Register');
 const risks=(m.riskRegister||[]).slice(0,80);if(!risks.length)p('No enterprise risks recorded in the selected scope.');
 else table(['Risk','Scenario / title','Rating','Treatment','Status'],risks.map((x:any)=>[x.risk_key,x.title,x.inherent_rating,x.treatment,x.status]),[72,205,70,95,69]);
 h1('6.','Issues, Corrective Action & Retest');
 const actions=(m.correctivePreventiveActions||[]).slice(0,80);if(!actions.length)p('No CAPA records supplied.');
 else table(['CAPA','Corrective action','Priority','Due','Status'],actions.map((x:any)=>[x.capa_key,x.corrective_action||x.title,x.priority,x.due_at,x.status]),[70,220,70,82,69]);
 h1('7.','Evidence Register & Technical Assurance');
 const ev=(m.evidenceRegister||[]).slice(0,100);if(!ev.length)p('No linked technical evidence provenance was supplied for this scope.');
 else table(['Evidence','Source','Recorded','Integrity / trust'],ev.map((x:any)=>[x.id,x.source,x.createdAt,x.integrityVerifiedAt?'VERIFIED':x.trust||'UNVERIFIED']),[100,120,145,146]);
 h1('8.','Third-Party Risk & Supply Chain');p('Vendors: '+s(m.thirdPartyRisk?.summary?.vendors||0)+' | Tier 1: '+s(m.thirdPartyRisk?.summary?.tier1||0)+' | Reviews due: '+s(m.thirdPartyRisk?.summary?.dueReview||0)+' | Open incidents: '+s(m.thirdPartyRisk?.summary?.openIncidents||0));
 h1('9.','Architecture, Continuous Compliance & Resilience');p('Architecture components: '+s(m.architectureAssurance?.summary?.components||0)+' | Architecture gaps: '+s(m.architectureAssurance?.summary?.gaps||0));p('Overdue obligations: '+s(m.continuousCompliance?.summary?.overdueObligations||0)+' | Open exceptions: '+s(m.continuousCompliance?.summary?.openExceptions||0));p('Business services: '+s(m.operationalResilience?.summary?.services||0)+' | Resilience gaps: '+s(m.operationalResilience?.summary?.gaps||0));
 h1('10.','Governance Performance & Management Oversight');p('Approved risk appetite statements: '+s(m.governancePerformance?.summary?.approvedAppetites||0)+' | KPI/KRI/KCI metrics: '+s(m.governancePerformance?.summary?.metrics||0)+' | Warning/Critical metrics: '+s((m.governancePerformance?.summary?.metricsWarning||0)+(m.governancePerformance?.summary?.metricsCritical||0))+' | Approved management reviews: '+s(m.governancePerformance?.summary?.approvedManagementReviews||0));const gm=(m.governancePerformance?.metrics||[]).slice(0,50);if(gm.length)table(['Metric','Type','Latest','State'],gm.map((x:any)=>[x.metric_key,x.metric_type,x.latest_value??'NO DATA',x.state]),[140,80,100,191]);h1('11.','Policy Governance & Independent Review');p('Policies: '+s(m.policyGovernance?.summary?.total||0)+' | Approved: '+s(m.policyGovernance?.summary?.approved||0)+' | Overdue review: '+s(m.policyGovernance?.summary?.overdueReview||0));p('Audits: '+s(m.auditManagement?.summary?.total||0)+' | Active: '+s(m.auditManagement?.summary?.active||0)+' | Complete: '+s(m.auditManagement?.summary?.complete||0)+' | Unreviewed workpapers: '+s(m.auditManagement?.summary?.unreviewed||0));p('ISO 42001 audit evidence requests: '+s(m.iso42001AuditEvidenceReadiness?.summary?.evidenced||0)+'/'+s(m.iso42001AuditEvidenceReadiness?.summary?.total||0)+' evidenced | Action required: '+s(m.iso42001AuditEvidenceReadiness?.summary?.actionRequired||0));const ar=(m.iso42001AuditEvidenceReadiness?.requests||[]).slice(0,20);if(ar.length)table(['Request','Status','Records'],ar.map((x:any)=>[x.title,x.status,x.supportingRecords]),[300,120,71]);
 h1('12.','Priority Management Action Plan');
 const pa=(m.priorityActions||[]).slice(0,100);if(!pa.length)p('No priority management actions were generated from the recorded evidence state.');
 else table(['Priority','Type / key','Required management action'],pa.map((x:any)=>[x.priority,s(x.type)+' '+s(x.key),x.action]),[72,105,334]);
 h1('13.','Assurance Boundary & Final Conclusion');for(const x of m.assuranceBoundary||[])p('• '+x,8);p('Final internal conclusion: '+conclusion+'. '+s(m.managementOpinion?.statement),9);
 const pages=d.bufferedPageRange();for(let i=0;i<pages.count;i++){d.switchToPage(pages.start+i);d.fillColor(muted).font('Helvetica').fontSize(7).text('AegisGRC Security  |  '+s(m.documentControl?.classification)+'  |  '+s(m.documentControl?.documentId),left,780,{width:380,lineBreak:false});d.text('Page '+(i+1)+' of '+pages.count,440,780,{width:110,align:'right',lineBreak:false})}
 d.end();
})}

