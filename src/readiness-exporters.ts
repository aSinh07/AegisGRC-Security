import PDFDocument from 'pdfkit';
import {Document,Packer,Paragraph,HeadingLevel,Table,TableRow,TableCell,WidthType} from 'docx';
import * as XLSX from 'xlsx';

const str=(v:any)=>v===null||v===undefined?'':String(v);
const table=(headers:string[],rows:any[][])=>new Table({width:{size:100,type:WidthType.PERCENTAGE},rows:[
 new TableRow({children:headers.map(x=>new TableCell({children:[new Paragraph(x)]}))}),
 ...rows.map(r=>new TableRow({children:r.map(v=>new TableCell({children:[new Paragraph(str(v))]}))}))
]});

export async function readinessDocx(m:any){
 const controlRows=(m.controls||[]).map((c:any)=>[c.control_key,c.title,c.applicability,c.implementation,c.readiness,(c.gaps||[]).join('; ')]);
 const clauseRows=(m.clauses||[]).map((c:any)=>[c.framework,c.version,c.clause,c.title,c.controlKey,c.readiness]);
 const d=new Document({sections:[{children:[
  new Paragraph({text:'AegisGRC Audit Readiness Report',heading:HeadingLevel.TITLE}),
  new Paragraph('Scope: '+str(m.scope?.name)+' | Generated: '+str(m.generatedAt)),
  new Paragraph({text:'Assurance Boundary',heading:HeadingLevel.HEADING_1}),new Paragraph(str(m.assuranceBoundary)),
  new Paragraph({text:'Executive Readiness',heading:HeadingLevel.HEADING_1}),
  ...Object.entries(m.executiveSummary||{}).map(([k,v])=>new Paragraph(k+': '+str(v))),
  new Paragraph({text:'Methodology',heading:HeadingLevel.HEADING_1}),...(m.methodology||[]).map((x:string)=>new Paragraph('• '+x)),
  new Paragraph({text:'Control Gap Register',heading:HeadingLevel.HEADING_1}),
  table(['Control','Title','Applicability','Implementation','Readiness','Gap / Required Action'],controlRows),
  new Paragraph({text:'Framework Clause Traceability',heading:HeadingLevel.HEADING_1}),
  table(['Framework','Version','Clause','Requirement','Control','Readiness'],clauseRows),
  new Paragraph({text:'Audit Checklist',heading:HeadingLevel.HEADING_1}),...(m.auditChecklist||[]).map((x:string)=>new Paragraph('• '+x)),
  new Paragraph({text:'Limitations',heading:HeadingLevel.HEADING_1}),...(m.limitations||[]).map((x:string)=>new Paragraph('• '+x))
 ]}]});
 return Packer.toBuffer(d);
}

export function readinessXlsx(m:any){
 const wb=XLSX.utils.book_new();
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet([{Scope:m.scope?.name||'',Generated:m.generatedAt,...m.executiveSummary,AssuranceBoundary:m.assuranceBoundary}]),'Executive Readiness');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.controls||[]).map((c:any)=>({
  Control:c.control_key,Title:c.title,Domain:c.domain,Applicability:c.applicability,Justification:c.applicability_justification,
  Implementation:c.implementation,ApprovedAt:c.approved_at,ValidEvidence:c.valid_evidence,PassedTests:c.passed_tests,OpenIssues:c.open_issues,
  Readiness:c.readiness,Gaps:(c.gaps||[]).join(' | '),Explanation:c.explanation
 }))),'Control Gap Register');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(m.clauses||[]),'Clause Traceability');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.methodology||[]).map((x:string)=>({Methodology:x}))),'Methodology');
 XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet((m.limitations||[]).map((x:string)=>({Limitation:x}))),'Limitations');
 return Buffer.from(XLSX.write(wb,{type:'buffer',bookType:'xlsx'}));
}

export function readinessPdf(m:any){return new Promise<Buffer>((resolve,reject)=>{
 const d=new PDFDocument({margin:42,bufferPages:true}),chunks:Buffer[]=[];
 d.on('data',x=>chunks.push(x));d.on('end',()=>resolve(Buffer.concat(chunks)));d.on('error',reject);
 const heading=(n:string,t:string)=>{d.moveDown().fontSize(15).text(n+' '+t).moveDown(.25)};
 d.fontSize(8).text('AEGISGRC | INTERNAL AUDIT READINESS | CONFIDENTIAL',{align:'right'});
 d.moveDown(2).fontSize(22).text('AegisGRC Audit Readiness Report');
 d.fontSize(10).text('Scope: '+str(m.scope?.name)).text('Generated: '+str(m.generatedAt));
 heading('1.','Assurance Boundary');d.fontSize(9).text(str(m.assuranceBoundary));
 heading('2.','Executive Readiness');
 Object.entries(m.executiveSummary||{}).forEach(([k,v])=>d.fontSize(9).text(k+': '+str(v)));
 heading('3.','Methodology');for(const x of m.methodology||[])d.fontSize(9).text('• '+x);
 d.addPage();heading('4.','Control Gap Register');
 for(const c of m.controls||[]){
  d.fontSize(11).text(str(c.control_key)+' · '+str(c.title));
  d.fontSize(8).text('Applicability: '+str(c.applicability)+' | Implementation: '+str(c.implementation)+' | Readiness: '+str(c.readiness));
  d.text('Evidence: '+str(c.valid_evidence)+' valid | Tests: '+str(c.passed_tests)+' pass | Open issues: '+str(c.open_issues));
  d.text('Plain-English assessment: '+str(c.explanation));
  if((c.gaps||[]).length)d.text('Required actions: '+c.gaps.join(' '));
  const maps=(c.mappings||[]).map((x:any)=>str(x.framework)+' '+str(x.version)+' '+str(x.clause)+' '+str(x.title)).join('; ');
  d.text('Mapped clauses: '+(maps||'NONE')).moveDown(.6);
 }
 d.addPage();heading('5.','Framework Clause Traceability');
 for(const c of m.clauses||[])d.fontSize(8).text(str(c.framework)+' '+str(c.version)+' | '+str(c.clause)+' | '+str(c.title)+' → '+str(c.controlKey)+' ['+str(c.readiness)+']');
 heading('6.','Audit Checklist');for(const x of m.auditChecklist||[])d.fontSize(9).text('• '+x);
 heading('7.','Limitations');for(const x of m.limitations||[])d.fontSize(9).text('• '+x);
 d.moveDown().fontSize(9).text('This report is an internal evidence-readiness package. It is not an ISO certificate, accreditation, regulatory approval, or external audit opinion.');
 d.end();
})}
