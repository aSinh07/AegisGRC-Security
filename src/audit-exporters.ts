import PDFDocument from 'pdfkit';
import {Document,Packer,Paragraph,HeadingLevel,Table,TableRow,TableCell,WidthType} from 'docx';
import * as XLSX from 'xlsx';

export async function auditDocx(m:any){
 const lifecycle=(m.findingLifecycle||[]).map((x:any)=>new TableRow({children:[
  x.severity,x.title,x.findingStatus,x.issue?.issue_key||'',(x.risks||[]).map((r:any)=>r.risk_key).join('; '),(x.capa||[]).map((c:any)=>c.capa_key+':'+c.status).join('; ')
 ].map((v:any)=>new TableCell({children:[new Paragraph(String(v||''))]}))}));
 const headers=['Severity','Finding','Status','Issue','Risk','CAPA'];
 const d=new Document({sections:[{children:[
  new Paragraph({text:'AegisGRC Audit Traceability Package',heading:HeadingLevel.TITLE}),
  new Paragraph('Assessment: '+m.assessmentId),
  new Paragraph('Generated: '+m.generatedAt),
  new Paragraph('Document ID: '+String(m.documentControl?.documentId||'')),
  new Paragraph('Version: '+String(m.documentControl?.version||'')+' | Classification: '+String(m.documentControl?.classification||'')),
  new Paragraph({text:'Assurance Boundary',heading:HeadingLevel.HEADING_1}),
  new Paragraph(m.assuranceBoundary),
  new Paragraph({text:'Executive Summary',heading:HeadingLevel.HEADING_1}),
  ...Object.entries(m.executiveSummary||{}).map(([k,v])=>new Paragraph(k+': '+String(v))),
  new Paragraph({text:'Finding-to-Closure Trace',heading:HeadingLevel.HEADING_1}),
  new Table({width:{size:100,type:WidthType.PERCENTAGE},rows:[new TableRow({children:headers.map(x=>new TableCell({children:[new Paragraph(x)]}))}),...lifecycle]}),
  new Paragraph({text:'Audit Limitations',heading:HeadingLevel.HEADING_1}),
  ...(m.limitations||[]).map((x:string)=>new Paragraph('• '+x))
 ]}]});
 return Packer.toBuffer(d);
}
export function auditXlsx(m:any){
 const wb=XLSX.utils.book_new();
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet([{...(m.documentControl||{}),...(m.executiveSummary||{})}]),'Executive Summary');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.evidenceRegister||[]),'Evidence Register');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.findingLifecycle||[]).map((x:any)=>({
  FindingId:x.findingId,Severity:x.severity,Title:x.title,Source:x.source,EvidenceHash:x.evidenceHash,Status:x.findingStatus,
  AnalystDecision:(x.analystDecisions||[]).at(-1)?.decision||'UNREVIEWED',Issue:x.issue?.issue_key||'',
  Control:x.controlAssurance?.control_key||'',ControlTestResult:x.controlAssurance?.test_result||'NOT_TESTED',ControlTestRationale:x.controlAssurance?.test_rationale||'',
  IssueStatus:x.issue?.status||'',RiskKeys:(x.risks||[]).map((r:any)=>r.risk_key).join('; '),
  CAPA:(x.capa||[]).map((c:any)=>c.capa_key+':'+c.status).join('; ')
 }))),'Lifecycle');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.limitations||[]).map((x:string)=>({Limitation:x}))),'Limitations');
 return Buffer.from(XLSX.write(wb,{type:'buffer',bookType:'xlsx'}));
}

export function auditPdf(m:any){return new Promise<Buffer>((resolve,reject)=>{
 const d=new PDFDocument({margin:48,bufferPages:true}),chunks:Buffer[]=[];
 d.on('data',x=>chunks.push(x));d.on('end',()=>resolve(Buffer.concat(chunks)));d.on('error',reject);
 d.fontSize(8).text('AEGISGRC AUDIT TRACEABILITY | CONFIDENTIAL',{align:'right'});
 d.moveDown(2).fontSize(22).text('AegisGRC Audit Traceability Package');
 d.fontSize(10).text('Assessment: '+m.assessmentId).text('Generated: '+m.generatedAt).text('Document ID: '+String(m.documentControl?.documentId||'')).text('Version: '+String(m.documentControl?.version||'')+' | Classification: '+String(m.documentControl?.classification||''));
 d.moveDown().fontSize(15).text('1. Assurance Boundary').fontSize(9).text(m.assuranceBoundary);
 d.moveDown().fontSize(15).text('2. Executive Summary');
 Object.entries(m.executiveSummary||{}).forEach(([k,v])=>d.fontSize(9).text(k+': '+String(v)));
 d.addPage().fontSize(15).text('3. Evidence Register');
 for(const e of m.evidenceRegister||[])d.moveDown(.5).fontSize(9).text(String(e.source||'EVIDENCE')+' | '+String(e.created_at||e.createdAt||'')).fontSize(8).text('SHA-256: '+String(e.sha256||'NOT PROVIDED')).text('Hash metadata timestamp: '+String(e.integrity_verified_at||'NOT RECORDED'));
 d.addPage().fontSize(15).text('4. Finding-to-Closure Trace');
 for(const x of m.findingLifecycle||[]){const latest=(x.analystDecisions||[]).at(-1);d.moveDown().fontSize(11).text(String(x.severity)+' · '+String(x.title)).fontSize(8).text('Finding: '+x.findingId+' | Source: '+x.source).text('Evidence SHA-256: '+String(x.evidenceHash||'NOT PROVIDED')).text('Analyst decision: '+String(latest?.decision||'UNREVIEWED')).text('Issue: '+String(x.issue?.issue_key||'NOT PROMOTED')).text('Control relevance: '+String(x.controlAssurance?.control_key||'NOT LINKED')).text('Latest independent control test: '+String(x.controlAssurance?.test_result||'NOT_TESTED')+(x.controlAssurance?.test_rationale?' | '+String(x.controlAssurance.test_rationale):'')).text('Risk: '+((x.risks||[]).map((r:any)=>r.risk_key+' '+r.inherent_rating).join('; ')||'NOT LINKED')).text('CAPA: '+((x.capa||[]).map((c:any)=>c.capa_key+' '+c.status+(c.retest_run_id?' retest='+c.retest_run_id:'')).join('; ')||'NOT LINKED'));}
 d.addPage().fontSize(15).text('5. Limitations');for(const x of m.limitations||[])d.fontSize(9).text('• '+x);
 d.moveDown().fontSize(9).text('This package is an internal traceability record. It is not an ISO certificate, regulatory approval, penetration-test attestation, or external audit opinion.');
 d.end();
})}
