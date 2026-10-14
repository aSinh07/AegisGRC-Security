import PDFDocument from 'pdfkit';
import type {Assessment,Finding,Evidence} from './models.js';

const SEVERITIES=['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const;
function priority(s:string){return s==='CRITICAL'||s==='HIGH'?'P1':s==='MEDIUM'?'P2':'P3'}
function status(f:Finding){return String(f.status||'OBSERVED').replaceAll('_',' ')}
function refs(f:Finding){const m:any=f.mappings||{};return [...(m.owasp||[]),...(m.nist||m.nistCsf||[]),...(m.iso27001||[]),...(m.iso42001||[])].join(', ')||'N/A'}

export function renderDefensiveSecurityPdf(a:Assessment,fs:Finding[],ev:Evidence[]=[],trace:any=null){return new Promise<Buffer>((resolve,reject)=>{
 const d:any=new PDFDocument({size:'A4',margin:46,bufferPages:true}),chunks:Buffer[]=[];d.on('data',(x:Buffer)=>chunks.push(x));d.on('end',()=>resolve(Buffer.concat(chunks)));d.on('error',reject);
 const ink='#172033',muted='#667085',navy='#0B1830',cyan='#16B8C7',line='#D9E2F0',soft='#F5F8FC',green='#067647',amber='#B54708',red='#B42318';
 let sectionNo=0;
 const footer=()=>{const y=805;d.strokeColor(line).moveTo(46,y).lineTo(549,y).stroke();d.fillColor(muted).font('Helvetica').fontSize(7).text('AEGISGRC | DEFENSIVE SECURITY | CONFIDENTIAL',46,y+8,{width:360});};
 const page=()=>{footer();d.addPage();};
 const ensure=(h=80)=>{if(d.y+h>790)page()};
 const h1=(s:string)=>{ensure(65);sectionNo++;d.moveDown(.5).fillColor(navy).font('Helvetica-Bold').fontSize(15).text(sectionNo+'. '+s);d.strokeColor(cyan).lineWidth(2).moveTo(46,d.y+5).lineTo(110,d.y+5).stroke();d.moveDown(1)};
 const p=(s:string)=>d.fillColor(ink).font('Helvetica').fontSize(9).text(s,{lineGap:2});
 const label=(s:string)=>d.fillColor(cyan).font('Helvetica-Bold').fontSize(8).text(s.toUpperCase());
 const row=(cells:string[],widths:number[],header=false)=>{ensure(38);const y=d.y,hs=cells.map((x,i)=>d.heightOfString(x,{width:widths[i]-10})+12),h=Math.max(25,...hs);let x=46;cells.forEach((c,i)=>{d.rect(x,y,widths[i],h).fill(header?navy:'#FFFFFF');d.strokeColor(line).rect(x,y,widths[i],h).stroke();d.fillColor(header?'#FFFFFF':ink).font(header?'Helvetica-Bold':'Helvetica').fontSize(7).text(c,x+5,y+6,{width:widths[i]-10});x+=widths[i]});d.y=y+h;};

 // Cover
 d.rect(0,0,595,245).fill(navy);d.fillColor(cyan).font('Helvetica-Bold').fontSize(10).text('AEGISGRC DEFENSIVE SECURITY',46,48);d.fillColor('#FFFFFF').fontSize(25).text('Updated Defensive Security\nRemediation & Verification Report',46,86,{width:500});d.font('Helvetica').fontSize(10).fillColor('#D7E3F4').text('Developer-readable defensive posture, remediation, hardening and retest plan',46,165,{width:480});
 d.y=292;[['Assessment',a.id],['Target',a.target],['Assessment status',String(a.status)],['Authorized',String(a.authorizedAt)],['Generated',new Date().toISOString()],['Classification','Manager + Developer Technical Security Report']].forEach(([k,v])=>{d.fillColor(muted).font('Helvetica').fontSize(8).text(k,46,d.y,{width:110});d.fillColor(ink).font('Helvetica-Bold').text(v,160,d.y-9,{width:380});d.moveDown(1.25)});
 d.moveDown();d.roundedRect(46,d.y,503,92,6).fill(soft);const sy=d.y+15;d.fillColor(cyan).font('Helvetica-Bold').fontSize(8).text('EVIDENCE-DRIVEN ASSESSMENT STATEMENT',61,sy);d.fillColor(ink).font('Helvetica').fontSize(9).text('This report separates confirmed weaknesses from scanner observations, false positives, positive controls and unproven hypotheses. No breach, exploitation or data exfiltration is claimed unless persisted evidence demonstrates that impact. Missing or failed coverage is never interpreted as PASS.',61,sy+20,{width:470,lineGap:2});
 page();

 h1('Defensive Summary');
 const open=fs.filter(f=>!['REMEDIATED','FALSE_POSITIVE'].includes(String(f.status||''))),critical=open.filter(f=>f.severity==='CRITICAL').length,high=open.filter(f=>f.severity==='HIGH').length;
 p('The current defensive posture contains '+open.length+' open evidence-backed finding(s), including '+critical+' critical and '+high+' high. Priority is assigned from persisted technical evidence. Closure remains evidence-gated: remediation requires a successful targeted retest against the same finding fingerprint; AI guidance cannot close a finding.');
 d.moveDown();label('Evidence sources');p([...new Set(ev.map(e=>String(e.source).toUpperCase()))].join(', ')||'No persisted scanner evidence');

 h1('System Architecture and Security Context');
 p('Authorized target: '+a.target+'. This report does not invent private architecture. Architecture, trust-boundary and technology conclusions require stored assessment evidence or uploaded architecture/configuration artifacts.');
 row(['LAYER / DOMAIN','DEFENSIVE SECURITY RELEVANCE'],[165,338],true);
 [['Web / API','Input handling, authentication/session controls, HTTP/TLS hardening, application exposure.'],['Network / Infrastructure','Ports, services, segmentation, host hardening and exposure.'],['Cloud / Identity','IAM, privilege, logging, encryption, storage and configuration posture.'],['Container / Supply Chain','Image/package vulnerabilities, SBOM, secrets, IaC and runtime hardening.'],['Endpoint / Detection','Endpoint telemetry, identity signals, detection and incident evidence.'],['Data / Database','Least privilege, access posture, encryption, service exposure and telemetry.']].forEach(x=>row(x,[165,338]));

 h1('Findings Register');
 row(['ID','FINDING','EVIDENCE STATUS','RISK','CVSS','MAPPING'],[38,170,92,55,48,100],true);
 fs.forEach((f,i)=>row(['F-'+String(i+1).padStart(2,'0'),f.title,status(f),f.severity,String(f.cvss??'N/A'),refs(f)],[38,170,92,55,48,100]));
 d.moveDown(.5);p('A numeric CVSS value is shown only when normalized evidence supplies one. N/A is not a zero score and is not interpreted as PASS.');

 h1('Developer Defensive Remediation Plan');
 row(['PRIORITY','ACTION','OWNER FOCUS','ACCEPTANCE EVIDENCE'],[60,205,95,143],true);
 fs.filter(f=>!['REMEDIATED','FALSE_POSITIVE'].includes(String(f.status||''))).forEach(f=>row([priority(f.severity),f.remediation||'Validate and remediate the affected defensive control.','Security / Platform','Successful same-source targeted retest bound to the same finding fingerprint, or governed residual-risk disposition.'],[60,205,95,143]));

 h1('Verification and Expected Evidence');
 p('Verification must be performed only against authorized assets. Retesting should repeat the originating defensive validation wherever possible and preserve the resulting evidence hash, scanner source, timestamp and finding fingerprint. A frontend refusal, recommendation, configuration change, or AI response alone does not prove remediation.');
 d.moveDown();row(['ENGINE / SOURCE','RECORDS','LAST EXIT','ASSURANCE'],[180,70,70,183],true);
 [...new Set(ev.map(e=>String(e.source).toUpperCase()))].forEach(src=>{const es=ev.filter(e=>String(e.source).toUpperCase()===src),last=es.at(-1);row([src,String(es.length),String(last?.exitCode??'N/A'),last?.exitCode===0?'Evidence recorded; interpret findings/coverage':'Failed/incomplete evidence must remain visible'],[180,70,70,183])});

 h1('Evidence Appendix');
 if(!ev.length)p('No persisted scanner evidence is available for this assessment.');
 ev.forEach((e,i)=>{ensure(75);label('E-'+String(i+1).padStart(2,'0')+' · '+String(e.source).toUpperCase());p('Recorded: '+e.createdAt+' | Exit: '+String(e.exitCode??'N/A'));d.fillColor(muted).fontSize(7).text('SHA-256: '+e.sha256);d.moveDown(.7)});

 h1('Analyst Decisions and Targeted Retest Traceability');
 const chains=Array.isArray(trace?.chains)?trace.chains:[];if(!chains.length)p('No governed analyst/retest trace was available. Finding status alone is not treated as independent retest proof.');else chains.forEach((c:any)=>{const latest=Array.isArray(c.reviews)&&c.reviews.length?c.reviews[c.reviews.length-1]:null,retests=Array.isArray(c.retests)?c.retests:[];label((c.findingId||'Finding')+' · '+String(c.source||'unknown').toUpperCase()+' · '+(latest?.decision||'UNREVIEWED'));p('Targeted retests: '+retests.length+(latest?.rationale?' | Analyst rationale: '+latest.rationale:''));retests.forEach((r:any)=>p('Evidence '+r.evidence_id+' | '+r.scanner_source+' | fingerprint '+String(r.fingerprint||'').slice(0,24)+'… | '+String(r.created_at||''))) });
 h1('Authoritative Assessment Coverage');
 const assurance=[['Infrastructure',trace?.infrastructureAssurance],['Endpoint',trace?.endpointAssurance],['Web',trace?.webAssurance],['API',trace?.apiAssurance],['Source Code',trace?.sourceCodeAssurance],['Dependencies',trace?.dependencyAssurance],['Container',trace?.containerAssurance],['Cloud',trace?.cloudAssurance],['Identity',trace?.identityAssurance],['Data Security',trace?.dataSecurityAssurance],['Privacy',trace?.privacyAssurance],['Attack Surface',trace?.attackSurfaceAssurance],['Breach Telemetry',trace?.breachTelemetryAssurance]];row(['LAYER','STATUS','EVIDENCE','ENGINES'],[135,90,70,208],true);assurance.forEach(([name,x]:any)=>{const y=x||{status:'NOT_STARTED',evidenceCount:0,engines:[],failureReasons:['Coverage record unavailable']};row([name,y.status,String(y.evidenceCount||0),(y.engines||[]).join(', ')||'None'],[135,90,70,208]);if(y.failureReasons?.length)p('Limitation: '+y.failureReasons.join('; '))});

 h1('Management Conclusion');
 const disposition=critical||high?'REMEDIATION REQUIRED':open.length?'REMEDIATION / RETEST REQUIRED':'NO OPEN EVIDENCE-BACKED FINDINGS';
 d.roundedRect(46,d.y,503,46,6).fill(critical||high?'#FEF3F2':'#ECFDF3');d.fillColor(critical||high?red:green).font('Helvetica-Bold').fontSize(12).text(disposition,60,d.y+16,{width:475});d.y+=60;
 p('The conclusion is bounded by stored evidence and executed coverage. Findings must not be promoted to confirmed exploitation without evidence of impact. Unobserved surfaces and failed/not-run engines remain assurance limitations.');

 h1('Production Readiness: Defensive Controls Are Necessary but Not Sufficient');
 p('Individual hardening fixes do not establish complete production readiness. Defensive approval requires evidence across the relevant trust boundaries: exposed services, identity and privilege, application/tool authorization, telemetry, data access, infrastructure configuration and retest results.');
 
 h1('Production Readiness Checklist');
 row(['CATEGORY','CONTROL','CURRENT STATUS','REQUIRED NEXT STEP'],[110,145,105,143],true);
 const cats=[['HTTP / Application Hardening','Headers, TLS, input/session controls'],['Network Segmentation','Restricted services and unnecessary exposure'],['Identity / Least Privilege','Restricted human and service identities'],['Endpoint / Detection','Telemetry and detection coverage'],['Cloud / Container','Configuration, image and runtime posture'],['Data Security','Access, encryption and exposure controls'],['Observability','Traceable security-relevant events'],['Remediation Verification','Fingerprint-bound targeted retest']];
 cats.forEach(([cat,control])=>{const related=open.filter(f=>(f.title+' '+f.description+' '+f.asset).toLowerCase().includes(cat.split(' ')[0].toLowerCase()));row([cat,control,related.length?related.length+' open related finding(s)':'REVIEW EVIDENCE','Validate applicable evidence and retain clean retest/analyst disposition.'],[110,145,105,143])});

 h1('Deployment Gate and Final Disposition');
 p('Recommended defensive deployment gate: critical/high evidence-backed findings are treated or explicitly accepted; failed/not-run coverage is visible; least-privilege and segmentation controls are validated where applicable; security telemetry is retained; and remediated findings have newer successful same-source retest evidence bound to the same vulnerability fingerprint. Final disposition: '+disposition+'.');
 d.moveDown();d.fillColor(amber).font('Helvetica-Bold').fontSize(8).text('AI ADVISORY BOUNDARY');p('AI may explain or prioritize evidence, but it cannot mark a finding remediated, manufacture successful evidence, or override the server-side closure gate.');

 footer();d.end();
})}
