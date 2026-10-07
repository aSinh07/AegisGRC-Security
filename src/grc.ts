import type { Finding } from './models.js';
const uniq=(x:string[])=>[...new Set(x)];
export const frameworkCatalog=[
 {id:'ISO27001',name:'ISO/IEC 27001:2022',scope:'Information Security Management System'},
 {id:'ISO42001',name:'ISO/IEC 42001:2023',scope:'AI Management System'},
 {id:'NIST_CSF',name:'NIST Cybersecurity Framework 2.0',scope:'Cybersecurity risk outcomes'},
 {id:'NIST_AI_RMF',name:'NIST AI RMF 1.0',scope:'AI risk management'},
 {id:'CIS',name:'CIS Critical Security Controls v8.1',scope:'Cybersecurity safeguards'},
 {id:'OWASP',name:'OWASP Top 10 / ASVS',scope:'Application security'},
 {id:'SOC2',name:'AICPA SOC 2 Trust Services Criteria',scope:'Security/availability/confidentiality'},
 {id:'PCI',name:'PCI DSS 4.0.1',scope:'Payment-card environments'},
 {id:'GDPR',name:'EU GDPR',scope:'Personal-data protection'},
 {id:'DPDP',name:'India Digital Personal Data Protection Act 2023',scope:'Digital personal-data governance'},
 {id:'HIPAA',name:'HIPAA Security Rule',scope:'US ePHI safeguards'}
] as const;
export function mapFinding(f:Finding):Finding {
 const text=(f.title+' '+f.description+' '+(f.cwe||'')).toLowerCase(),m:any={owasp:[],iso27001:['A.8.8 Management of technical vulnerabilities'],iso42001:[],nist:['ID.RA Risk Assessment'],nistCsf:['ID.RA'],nistAiRmf:[],cis:['7 Continuous Vulnerability Management'],soc2:['CC7 System Operations'],pci:['6.3 Security vulnerabilities'],gdpr:[],dpdp:[],hipaa:[]};
 if(/xss|79|sql|89|injection/.test(text)){m.owasp.push('A03:2021 Injection');m.iso27001.push('A.8.26 Application security requirements','A.8.28 Secure coding');m.nistCsf.push('PR.PS');m.cis.push('16 Application Software Security');m.pci.push('6.2 Bespoke and custom software is developed securely')}
 if(/tls|cleartext|319|crypto/.test(text)){m.owasp.push('A02:2021 Cryptographic Failures');m.iso27001.push('A.8.24 Use of cryptography');m.nistCsf.push('PR.DS');m.pci.push('4 Protect cardholder data with strong cryptography');m.gdpr.push('Art. 32 Security of processing');m.dpdp.push('Section 8 reasonable security safeguards');m.hipaa.push('164.312(e) Transmission security')}
 if(/auth|access|permission|session/.test(text)){m.owasp.push('A01:2021 Broken Access Control');m.iso27001.push('A.5.15 Access control','A.8.5 Secure authentication');m.nistCsf.push('PR.AA');m.cis.push('5 Account Management','6 Access Control Management');m.soc2.push('CC6 Logical and Physical Access Controls');m.pci.push('7 Restrict access','8 Identify users and authenticate access');m.gdpr.push('Art. 32 Security of processing');m.dpdp.push('Section 8 reasonable security safeguards');m.hipaa.push('164.312(a) Access control')}
 if(/security header|configuration|csp|hsts|misconfig/.test(text)){m.owasp.push('A05:2021 Security Misconfiguration');m.iso27001.push('A.8.9 Configuration management');m.nistCsf.push('PR.PS');m.cis.push('4 Secure Configuration of Enterprise Assets and Software')}
 if(/ai|llm|model|prompt/.test(text)){m.iso42001.push('A.5 Assessing impacts of AI systems','A.6 AI system life cycle','A.8 Information for interested parties');m.nistAiRmf.push('MAP','MEASURE','MANAGE','GOVERN')}
 for(const k of Object.keys(m))m[k]=uniq(m[k]); return {...f,mappings:{...f.mappings,...m}};
}
