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
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet([m.executiveSummary||{}]),'Executive Summary');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.evidenceRegister||[]),'Evidence Register');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.findingLifecycle||[]).map((x:any)=>({
  FindingId:x.findingId,Severity:x.severity,Title:x.title,Source:x.source,EvidenceHash:x.evidenceHash,Status:x.findingStatus,
  AnalystDecision:(x.analystDecisions||[]).at(-1)?.decision||'UNREVIEWED',Issue:x.issue?.issue_key||'',
  IssueStatus:x.issue?.status||'',RiskKeys:(x.risks||[]).map((r:any)=>r.risk_key).join('; '),
  CAPA:(x.capa||[]).map((c:any)=>c.capa_key+':'+c.status).join('; ')
 }))),'Lifecycle');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.limitations||[]).map((x:string)=>({Limitation:x}))),'Limitations');
 return Buffer.from(XLSX.write(wb,{type:'buffer',bookType:'xlsx'}));
}
