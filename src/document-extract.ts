import mammoth from 'mammoth';
import pdf from 'pdf-parse';
import * as XLSX from 'xlsx';

export async function extractDocument(filename:string,mime:string,content:Buffer){
 const n=filename.toLowerCase();
 if(mime.startsWith('text/')||/\.(txt|md|csv|json|xml|yaml|yml|log)$/i.test(n)) return {kind:'text',text:content.toString('utf8')};
 if(mime==='application/pdf'||n.endsWith('.pdf')){const r=await pdf(content);return {kind:'pdf',text:r.text,pages:r.numpages}};
 if(mime.includes('wordprocessingml')||n.endsWith('.docx')){const r=await mammoth.extractRawText({buffer:content});return {kind:'docx',text:r.value}};
 if(mime.includes('spreadsheetml')||n.endsWith('.xlsx')||n.endsWith('.xls')){const wb=XLSX.read(content,{type:'buffer'});const text=wb.SheetNames.map(s=>'SHEET: '+s+'\n'+XLSX.utils.sheet_to_csv(wb.Sheets[s])).join('\n\n');return {kind:'spreadsheet',text}};
 throw new Error('Unsupported analysis format. Use PDF, DOCX, XLSX/XLS, TXT, Markdown, CSV, JSON, XML, YAML or logs.');
}
