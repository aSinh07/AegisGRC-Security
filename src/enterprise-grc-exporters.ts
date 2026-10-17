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
  new Paragraph('Governed framework mappings: '+((m.frameworks||[]).join(', ')||'None recorded')),
  new Paragraph('Frameworks declared by imported documents (mapping pending unless shown above): '+((m.documentDeclaredFrameworks||[]).join(', ')||'None recorded')),
  ...(m.methodology||[]).map((x:string)=>new Paragraph('• '+x)),
  new Paragraph({text:'Control Assurance & Gap Register',heading:HeadingLevel.HEADING_1}),
  docTable(['Control','Title','Applicability','Implementation','Readiness','Auditor Action / Gap'],controls),
  new Paragraph({text:'Risk Register',heading:HeadingLevel.HEADING_1}),
  docTable(['Risk','Title','Rating','Treatment','Status','Acceptance Expiry'],risks),
  new Paragraph({text:'Issue Register',heading:HeadingLevel.HEADING_1}),
  docTable(['Issue','Title','Priority','Status','Due'],issues),
  new Paragraph({text:'Third-Party, Architecture & Continuous Compliance',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Vendors: '+s(m.thirdPartyRisk?.summary?.vendors||0)+' | Architecture gaps: '+s(m.architectureAssurance?.summary?.gaps||0)+' | Overdue obligations: '+s(m.continuousCompliance?.summary?.overdueObligations||0)),
  docTable(['Vendor','Service','Tier','Criticality','Status'],(m.thirdPartyRisk?.vendors||[]).map((x:any)=>[x.name,x.service,x.tier,x.criticality,x.status])),
  new Paragraph({text:'Operational Resilience',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Business services: '+s(m.operationalResilience?.summary?.services||0)+' | Tested: '+s(m.operationalResilience?.summary?.tested||0)+' | Resilience gaps: '+s(m.operationalResilience?.summary?.gaps||0)),
  docTable(['Service','Gap','Severity'],(m.operationalResilience?.gaps||[]).map((x:any)=>[x.service,x.type,x.severity])),
  new Paragraph({text:'Data Governance Operations',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Processing activities: '+s(m.dataProtectionOperations?.summary?.processingActivities||0)+' | Open requests: '+s(m.dataProtectionOperations?.summary?.openRequests||0)),
  docTable(['Activity','Name','Purpose','Ground','Retention','Status'],(m.dataProtectionOperations?.activities||[]).map((x:any)=>[x.activity_key,x.name,x.purpose,x.processing_ground,x.retention_rule,x.status])),
  docTable(['Legal reference','Title','Source','Review state'],(m.dataProtectionOperations?.legalRegister||[]).map((x:any)=>[x.reference_key,x.title,x.source_reference,s(x.applicability_status)+' / '+s(x.commencement_status)])),
  new Paragraph({text:'Policy Governance',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Policies: '+s(m.policyGovernance?.summary?.total||0)+' | Approved: '+s(m.policyGovernance?.summary?.approved||0)+' | Overdue review: '+s(m.policyGovernance?.summary?.overdueReview||0)+' | Unmapped: '+s(m.policyGovernance?.summary?.unmapped||0)),
  docTable(['Policy','Title','Version','Category','Status'],(m.policyGovernance?.policies||[]).map((x:any)=>[x.policy_key,x.title,x.version,x.category,x.status])),
  new Paragraph({text:'Audit Management',heading:HeadingLevel.HEADING_1}),
  new Paragraph('Audits: '+s(m.auditManagement?.summary?.total||0)+' | Active: '+s(m.auditManagement?.summary?.active||0)+' | Complete: '+s(m.auditManagement?.summary?.complete||0)+' | Unreviewed workpapers: '+s(m.auditManagement?.summary?.unreviewed||0)),
  docTable(['Audit','Title','Type','Objective','Criteria','Findings / workpapers','Status'],(m.auditManagement?.audits||[]).map((x:any)=>[x.audit_key,x.title,x.audit_type,x.objective,x.criteria,(x.workpaper_details||[]).map((w:any)=>w.title+' ['+w.result+']').join('; '),x.status])),
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
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.documentIntakeProvenance?.intakes||[]),'Document Intakes');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.documentIntakeProvenance?.governedRecords||[]),'Document Provenance');
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
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.dataProtectionOperations?.activities||[]),'Processing Inventory');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.dataProtectionOperations?.legalRegister||[]),'Legal Register');
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
  const height=(vals:any[],header=false)=>{const fs=header?7:6.8,pad=4;return Math.max(header?20:18,...vals.map((v,i)=>d.heightOfString(s(v),{width:widths[i]-pad*2,lineGap:1})+pad*2))};
  const draw=(vals:any[],header=false,skipEnsure=false)=>{const fs=header?7:6.8,pad=4,rh=height(vals,header);if(!skipEnsure)ensure(rh+8);let x=left,y=d.y;for(let i=0;i<vals.length;i++){d.rect(x,y,widths[i],rh).fillAndStroke(header?pale:'#FFFFFF',line);d.fillColor(header?navy:ink).font(header?'Helvetica-Bold':'Helvetica').fontSize(fs).text(s(vals[i]),x+pad,y+pad,{width:widths[i]-pad*2,height:rh-pad*2,lineGap:1});x+=widths[i]}d.y=y+rh;d.x=left;};
  draw(headers,true);for(const row of data){const rh=height(row,false);if(d.y+rh+8>755){addContentPage();draw(headers,true,true)}draw(row,false,true)}d.moveDown(.45);
 };
 const conclusion=s(m.managementOpinion?.conclusion),statusColor=conclusion==='AUDIT_READY'?good:conclusion==='INSUFFICIENT_EVIDENCE'?warn:bad;
 // Cover intentionally mirrors the Offensive Security report geometry and palette.
 const H=841.89,CW=width,coverNavy='#0B1830',coverBlue='#155EEF',coverCyan='#16B8C7',coverMuted='#667085',coverSoft='#F5F8FC',coverWhite='#FFFFFF';
 d.rect(0,0,pageW,12).fill(coverNavy);d.rect(left,28,30,4).fill(coverCyan);
 d.fillColor(coverNavy).font('Helvetica-Bold').fontSize(10).text('AEGISGRC',left,38,{width:160,lineBreak:false});
 d.fillColor(coverMuted).font('Helvetica').fontSize(6).text('SECURITY ASSURANCE PLATFORM',left,51,{width:200,lineBreak:false});
 d.fillColor(coverMuted).font('Helvetica').fontSize(7).text('CONFIDENTIAL',pageW-right-120,40,{width:120,align:'right',lineBreak:false});
 d.rect(0,100,pageW,230).fill(coverNavy);d.rect(left,126,52,5).fill(coverCyan);
 d.fillColor(coverWhite).font('Helvetica-Bold').fontSize(30).text('AEGIS',left,150,{width:CW,lineBreak:false});
 d.fillColor(coverCyan).font('Helvetica-Bold').fontSize(30).text('GRC',left+108,150,{width:CW-108,lineBreak:false});
 d.fillColor('#B9C7DD').font('Helvetica').fontSize(9).text('GRC ASSURANCE REPORT',left,194,{width:CW,lineBreak:false});
 d.fillColor(coverWhite).font('Helvetica-Bold').fontSize(22).text('Enterprise Governance, Risk & Compliance Assurance',left,225,{width:CW,lineGap:3});
 d.fillColor('#D7E3F4').font('Helvetica').fontSize(10).text('Evidence-led readiness, control assurance, risk and accountable management action',left,278,{width:CW});
 const coverBadge=(label:string,x:number,w=96,color=coverBlue)=>{d.roundedRect(x,354,w,18,9).fill(color);d.fillColor(coverWhite).font('Helvetica-Bold').fontSize(7).text(label,x,359,{width:w,align:'center',lineBreak:false})};
 coverBadge('GRC ASSURANCE',left,96,coverBlue);coverBadge(conclusion||'INTERNAL',left+106,118,statusColor);
 let cy=405;const coverMeta=[['Organization',m.organization?.name||'Not recorded'],['Scope',m.scope?.name||'Not recorded'],['Frameworks',(m.frameworks||[]).join(', ')||'No mapped framework recorded'],['Document ID',m.documentControl?.documentId],['Version / Status',s(m.documentControl?.version)+' / '+s(m.documentControl?.status)],['Generated',m.documentControl?.generatedAt]];
 for(const [k,v] of coverMeta){d.fillColor(coverMuted).font('Helvetica').fontSize(7).text(String(k),left,cy,{width:112,lineBreak:false});d.fillColor(ink).font('Helvetica-Bold').fontSize(8).text(s(v),left+120,cy,{width:CW-120});cy=Math.max(cy+25,d.y+8)}
 const assuranceY=Math.max(570,cy+12);d.roundedRect(left,assuranceY,CW,92,6).fill(coverSoft);d.rect(left,assuranceY,4,92).fill(statusColor);
 d.fillColor(coverBlue).font('Helvetica-Bold').fontSize(8).text('EVIDENCE ASSURANCE STATEMENT',left+16,assuranceY+17,{width:CW-32,lineBreak:false});
 d.fillColor(ink).font('Helvetica').fontSize(9).text('Conclusion: '+(conclusion||'INTERNAL ASSESSMENT')+'. '+s(m.managementOpinion?.statement)+' This is an internal readiness and control-assurance artifact, not certification, accreditation, legal advice or an external audit opinion.',left+16,assuranceY+36,{width:CW-32,lineGap:2});
 d.x=left;d.y=assuranceY+102;
 addContentPage();
 h1('1.','Executive GRC Summary');
 const e=m.executiveSummary||{};badge('Evidence readiness',s(m.managementOpinion?.evidenceReadinessPercent)+'%');badge('Applicable controls',e.controlsApplicable||0);badge('High/Critical risks',e.highCriticalRisks||0);badge('Open CAPA',e.openCapa||0);d.x=left;d.y+=48;
 table(['Indicator','Current position','Management interpretation'],[
  ['Control assurance',s(e.controlsEvidenceReady||0)+' evidence-ready / '+s(e.controlsTotal||0)+' total','Missing, stale or unapproved evidence remains action-required.'],
  ['Risk posture',s(e.openRisks||0)+' open; '+s(e.highCriticalRisks||0)+' high/critical','Residual risk requires accountable treatment or acceptance.'],
  ['Issues & CAPA',s(e.openIssues||0)+' issues; '+s(e.openCapa||0)+' CAPA','Closure requires evidence and governed retest/review.'],
  ['Enterprise workflows',s(e.enterpriseWorkflowGaps||0)+' disclosed gaps','Includes architecture, resilience, policy, obligations, audit and supplier signals.']
 ],[112,118,281]);
 h1('2.','Scope, Frameworks & Assessment Methodology');p('Governed framework mappings: '+((m.frameworks||[]).join(', ')||'None recorded for the scoped controls.'));p('Frameworks declared by imported documents: '+((m.documentDeclaredFrameworks||[]).join(', ')||'None recorded')+'. Document declarations are provenance only until mapped to governed controls.');const di=(m.documentIntakeProvenance?.intakes||[]).slice(0,40);if(di.length)table(['Imported document','Kind','State','Imported / approved'],di.map((x:any)=>[x.filename,x.document_kind,x.status,x.approved_at||x.created_at]),[190,80,80,161]);
 for(const x of m.methodology||[])p('• '+x,8);
 h1('3.','Statement of Applicability / Applicability Record');
 const soa=(m.statementOfApplicability||[]).slice(0,80);
 if(!soa.length)p('No approved applicability records were supplied for this scope.');
 else table(['Control','Applicability','Implementation','Approval'],soa.map((x:any)=>[x.control_key||x.controlKey,x.applicability,x.implementation,x.approved_at?'APPROVED':'PENDING']),[126,110,135,140]);
 h1('4.','Control Assurance & Framework Traceability');
 for(const c of m.controlAssurance||[]){ensure(78);h2(s(c.controlKey)+' · '+s(c.title));p('Domain: '+s(c.domain)+'   |   Applicability: '+s(c.applicability)+'   |   Implementation: '+s(c.implementation)+'   |   Readiness: '+s(c.readiness),7.8);p('Validated evidence: '+s(c.validEvidence)+'   |   Latest passing tests: '+s(c.passedLatestTests)+'   |   Open issues: '+s(c.openIssues),7.8);const maps=[...new Map((c.frameworkMappings||[]).map((x:any)=>[s(x.framework).trim().toUpperCase()+'|'+s(x.requirementKey||x.requirement_key).trim().toUpperCase(),x])).values()].map((x:any)=>s(x.framework)+(s(x.requirementKey||x.requirement_key)?' > '+s(x.requirementKey||x.requirement_key):'')).join('; ');if(maps)p('Framework traceability: '+maps+' -> Evidence: '+s(c.validEvidence)+' -> Test: '+(Number(c.passedLatestTests)>0?'PASS':'NOT_TESTED/ACTION_REQUIRED')+' -> Readiness: '+s(c.readiness),7.6);if((c.gaps||[]).length)p('Required action: '+c.gaps.join(' '),7.8)}
 h1('5.','Enterprise Risk Register');
 const risks=(m.riskRegister||[]).slice(0,80);if(!risks.length)p('No enterprise risks recorded in the selected scope.');
 else table(['Risk','Scenario / title','Rating','Treatment','Status'],risks.map((x:any)=>[x.risk_key,x.title,x.inherent_rating,x.treatment,x.status]),[72,205,70,95,69]);
 h1('6.','Issues, Corrective Action & Retest');
 const actions=(m.correctivePreventiveActions||[]).slice(0,80);if(!actions.length)p('No CAPA records supplied.');
 else table(['CAPA','Corrective action','Priority','Due','Status'],actions.map((x:any)=>[x.capa_key,x.corrective_action||x.title,x.priority,x.due_at,x.status]),[70,220,70,82,69]);
 h1('7.','Evidence Register & Technical Assurance');
 const ev=(m.evidenceRegister||[]).slice(0,100);if(!ev.length)p('No linked technical evidence provenance was supplied for this scope.');
 else table(['Evidence','Source','Recorded','Integrity / trust'],ev.map((x:any)=>[x.id,x.source,x.createdAt,x.integrityVerifiedAt?'VERIFIED':x.trust||'UNVERIFIED']),[100,120,145,146]);
 const sec=m.securityReportEvidence||{},accepted=(sec.accepted||[]),pending=(sec.pendingReview||[]);h2('Offensive / Defensive Security Evidence Handoff');p('Accepted technical reports: '+s(accepted.length)+'   |   Pending GRC review: '+s(pending.length)+'   |   Total handed off: '+s(sec.total||0),7.8);p(s(sec.assuranceNote||'Technical security reports are governed evidence inputs and do not automatically establish control conformity.'),7.6);if(accepted.length||pending.length)table(['Report','Source','Status','Evidence SHA-256'],[...accepted,...pending].slice(0,40).map((x:any)=>[x.report_id||x.reportId,x.source,x.status,x.sha256]),[135,80,105,191]);
 h1('8.','Third-Party Risk & Supply Chain');p('Vendors: '+s(m.thirdPartyRisk?.summary?.vendors||0)+' | Tier 1: '+s(m.thirdPartyRisk?.summary?.tier1||0)+' | Reviews due: '+s(m.thirdPartyRisk?.summary?.dueReview||0)+' | Open incidents: '+s(m.thirdPartyRisk?.summary?.openIncidents||0));const vendors=(m.thirdPartyRisk?.vendors||[]).slice(0,60);if(vendors.length)table(['Vendor','Service','Tier','Criticality','Status'],vendors.map((x:any)=>[x.name,x.service,x.tier,x.criticality,x.status]),[120,150,65,85,91]);
 h1('9.','Architecture, Continuous Compliance & Resilience');p('Architecture components: '+s(m.architectureAssurance?.summary?.components||0)+' | Architecture gaps: '+s(m.architectureAssurance?.summary?.gaps||0));p('Overdue obligations: '+s(m.continuousCompliance?.summary?.overdueObligations||0)+' | Open exceptions: '+s(m.continuousCompliance?.summary?.openExceptions||0));p('Business services: '+s(m.operationalResilience?.summary?.services||0)+' | Resilience gaps: '+s(m.operationalResilience?.summary?.gaps||0));
 h1('10.','Governance Performance & Management Oversight');p('Approved risk appetite statements: '+s(m.governancePerformance?.summary?.approvedAppetites||0)+' | KPI/KRI/KCI metrics: '+s(m.governancePerformance?.summary?.metrics||0)+' | Warning/Critical metrics: '+s((m.governancePerformance?.summary?.metricsWarning||0)+(m.governancePerformance?.summary?.metricsCritical||0))+' | Approved management reviews: '+s(m.governancePerformance?.summary?.approvedManagementReviews||0));const gm=(m.governancePerformance?.metrics||[]).slice(0,50);if(gm.length)table(['Metric','Type','Latest','State'],gm.map((x:any)=>[x.metric_key,x.metric_type,x.latest_value??'NO DATA',x.state]),[140,80,100,191]);h1('11.','Policy Governance & Independent Review');p('Policies: '+s(m.policyGovernance?.summary?.total||0)+' | Approved: '+s(m.policyGovernance?.summary?.approved||0)+' | Overdue review: '+s(m.policyGovernance?.summary?.overdueReview||0));const policies=(m.policyGovernance?.policies||[]).slice(0,60);if(policies.length)table(['Policy','Title','Version','Category','Status'],policies.map((x:any)=>[x.policy_key,x.title,x.version,x.category,x.status]),[80,180,55,95,101]);p('Audits: '+s(m.auditManagement?.summary?.total||0)+' | Active: '+s(m.auditManagement?.summary?.active||0)+' | Complete: '+s(m.auditManagement?.summary?.complete||0)+' | Unreviewed workpapers: '+s(m.auditManagement?.summary?.unreviewed||0));const audits=(m.auditManagement?.audits||[]).slice(0,50);if(audits.length)table(['Audit','Title','Type','Objective / Criteria / Findings','Status'],audits.map((x:any)=>[x.audit_key,x.title,x.audit_type,s(x.objective)+' / '+s(x.criteria)+' / '+(x.workpaper_details||[]).map((w:any)=>w.title+' ['+w.result+']').join('; '),x.status]),[75,125,65,175,71]);p('ISO 42001 audit evidence requests: '+s(m.iso42001AuditEvidenceReadiness?.summary?.evidenced||0)+'/'+s(m.iso42001AuditEvidenceReadiness?.summary?.total||0)+' evidenced | Action required: '+s(m.iso42001AuditEvidenceReadiness?.summary?.actionRequired||0));const ar=(m.iso42001AuditEvidenceReadiness?.requests||[]).slice(0,20);if(ar.length)table(['Request','Status','Records'],ar.map((x:any)=>[x.title,x.status,x.supportingRecords]),[300,120,71]);
 h1('12.','Priority Management Action Plan');
 const pa=(m.priorityActions||[]).slice(0,100);if(!pa.length)p('No priority management actions were generated from the recorded evidence state.');
 else table(['Priority','Type / key','Required management action'],pa.map((x:any)=>[x.priority,s(x.type)+' '+s(x.key),x.action]),[72,105,334]);
 h1('13.','Assurance Boundary & Final Conclusion');for(const x of m.assuranceBoundary||[])p('• '+x,8);p('Final internal conclusion: '+conclusion+'. '+s(m.managementOpinion?.statement),9);
 const pages=d.bufferedPageRange();for(let i=0;i<pages.count;i++){d.switchToPage(pages.start+i);d.fillColor(muted).font('Helvetica').fontSize(7).text('AegisGRC Security  |  '+s(m.documentControl?.classification)+'  |  '+s(m.documentControl?.documentId),left,780,{width:380,lineBreak:false});d.text('Page '+(i+1)+' of '+pages.count,440,780,{width:110,align:'right',lineBreak:false})}
 d.end();
})}

