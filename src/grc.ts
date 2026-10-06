import type { Finding } from './models.js';
export function mapFinding(f:Finding):Finding {
 const text=(f.title+' '+f.description+' '+(f.cwe||'')).toLowerCase();
 const owasp:string[]=[]; const iso27001:string[]=['A.8.8 Management of technical vulnerabilities'];
 const iso42001:string[]=['A.6.2.6 AI system operation and monitoring']; const nist:string[]=['ID.RA Risk Assessment'];
 if(/xss|79/.test(text)) owasp.push('A03:2021 Injection');
 if(/sql|89/.test(text)) owasp.push('A03:2021 Injection');
 if(/tls|cleartext|319/.test(text)) owasp.push('A02:2021 Cryptographic Failures');
 if(/auth|access/.test(text)) owasp.push('A01:2021 Broken Access Control');
 if(/security header|configuration|csp|hsts/.test(text)) owasp.push('A05:2021 Security Misconfiguration');
 return {...f,mappings:{owasp:[...new Set(owasp)],iso27001,iso42001,nist}};
}