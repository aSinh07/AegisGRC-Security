import {pool} from './db-pool.js';
import crypto from 'node:crypto';
import pg from 'pg';


const id=(key:string)=>{const h=crypto.createHash('sha256').update('aegis-framework-library:'+key).digest('hex').slice(0,32).split('');h[12]='4';h[16]=((parseInt(h[16],16)&3)|8).toString(16);return h.slice(0,8).join('')+'-'+h.slice(8,12).join('')+'-'+h.slice(12,16).join('')+'-'+h.slice(16,20).join('')+'-'+h.slice(20).join('')};
type Control={key:string;title:string;domain:string;description:string};
type Requirement={framework:string;version:string;key:string;title:string;summary:string;controls:string[];source:string};

const controls:Control[]=[
 {key:'GOV-01',title:'Governance, accountability and oversight',domain:'GOVERNANCE',description:'Defined accountability, oversight, decision rights and management review.'},
 {key:'SCP-01',title:'Scope, context and stakeholder obligations',domain:'GOVERNANCE',description:'Document scope, context, interested parties, obligations and system boundaries.'},
 {key:'RSK-01',title:'Risk assessment and treatment',domain:'RISK',description:'Identify, analyze, evaluate, treat and approve residual risk using a governed methodology.'},
 {key:'POL-01',title:'Policy lifecycle governance',domain:'GOVERNANCE',description:'Approve, communicate, review and retire governed policies with accountable ownership.'},
 {key:'AST-01',title:'Asset and system inventory',domain:'ASSET',description:'Maintain accountable inventory of information, technology, AI, data and supplier assets.'},
 {key:'IAM-01',title:'Identity and access governance',domain:'ACCESS',description:'Least privilege, authentication, privileged access and recurring access review.'},
 {key:'CFG-01',title:'Secure configuration and hardening',domain:'SECURITY',description:'Approved configuration baselines, hardening, drift detection and remediation.'},
 {key:'VUL-01',title:'Vulnerability and secure engineering',domain:'SECURITY',description:'Identify, prioritize, remediate and retest vulnerabilities across the technology lifecycle.'},
 {key:'LOG-01',title:'Logging, monitoring and detection',domain:'MONITORING',description:'Collect trustworthy security and operational telemetry, detect anomalies and investigate events.'},
 {key:'IR-01',title:'Incident response and recovery',domain:'RESILIENCE',description:'Prepare, detect, respond, communicate, recover and learn from incidents.'},
 {key:'BCM-01',title:'Business continuity and resilience',domain:'RESILIENCE',description:'Define resilience requirements and validate recovery through exercises and evidence.'},
 {key:'DAT-01',title:'Data governance, privacy and lifecycle',domain:'DATA',description:'Govern classification, provenance, quality, minimization, retention, deletion and privacy obligations.'},
 {key:'CRY-01',title:'Cryptographic protection',domain:'DATA',description:'Protect sensitive data in transit and at rest using governed cryptographic controls.'},
 {key:'TPRM-01',title:'Third-party and supply-chain governance',domain:'THIRD_PARTY',description:'Risk-tier suppliers, perform due diligence, monitor obligations and govern remediation.'},
 {key:'EVD-01',title:'Evidence integrity and control assurance',domain:'ASSURANCE',description:'Retain attributable, current, validated evidence and independently review control effectiveness.'},
 {key:'AUD-01',title:'Internal audit and independent review',domain:'ASSURANCE',description:'Plan risk-based independent assurance, record findings and track closure.'},
 {key:'CAPA-01',title:'Corrective action and continual improvement',domain:'ASSURANCE',description:'Root-cause issues, assign corrective actions, verify retest evidence and close independently.'},
 {key:'AI-01',title:'AI lifecycle, impact and human oversight',domain:'AI_GOVERNANCE',description:'Govern AI intended use, impact, data, lifecycle validation, human oversight and change.'},
 {key:'AI-02',title:'AI transparency, quality and monitoring',domain:'AI_GOVERNANCE',description:'Monitor AI quality, provenance, limitations, misuse, transparency and operational behavior.'},
 {key:'APP-01',title:'Application and software security',domain:'APPLICATION_SECURITY',description:'Govern secure design, development, testing, deployment and application-layer protection.'},
 {key:'PRI-01',title:'Privacy rights and accountable processing',domain:'PRIVACY',description:'Govern lawful processing, notices, data-subject rights, accountability and privacy requests.'},
 {key:'PAY-01',title:'Payment-data environment protection',domain:'PAYMENT_SECURITY',description:'Scope and protect payment-account data environments with access, monitoring, testing and secure configuration.'},
 {key:'PEO-01',title:'People security and awareness',domain:'PEOPLE',description:'Govern workforce security responsibilities, awareness, training and lifecycle access obligations.'}
];

const R=(framework:string,version:string,key:string,title:string,summary:string,controls:string[],source:string):Requirement=>({framework,version,key,title,summary,controls,source});
const requirements:Requirement[]=[
 R('ISO27001','2022','C4','Context and ISMS scope','Governed context, interested parties and ISMS boundaries.',['SCP-01','AST-01'],'https://www.iso.org/standard/27001'),
 R('ISO27001','2022','C5','Leadership and information-security governance','Leadership accountability, policy and assigned responsibilities.',['GOV-01','POL-01'],'https://www.iso.org/standard/27001'),
 R('ISO27001','2022','C6','Planning and information-security risk','Risk assessment, treatment, objectives and planned change.',['RSK-01'],'https://www.iso.org/standard/27001'),
 R('ISO27001','2022','C7','Support and documented information','Resources, competence, communication and controlled records.',['GOV-01','EVD-01'],'https://www.iso.org/standard/27001'),
 R('ISO27001','2022','C8','Operational control','Operate risk treatment and security processes under controlled conditions.',['RSK-01','CFG-01','VUL-01'],'https://www.iso.org/standard/27001'),
 R('ISO27001','2022','C9','Performance evaluation','Monitoring, measurement, internal audit and management review.',['LOG-01','AUD-01','GOV-01'],'https://www.iso.org/standard/27001'),
 R('ISO27001','2022','C10','Improvement','Nonconformity, corrective action and continual improvement.',['CAPA-01'],'https://www.iso.org/standard/27001'),
 R('ISO27001','2022','A-ORG','Organizational security control themes','Organizational governance, suppliers, incidents and continuity.',['GOV-01','TPRM-01','IR-01','BCM-01'],'https://www.iso.org/standard/27001'),
 R('ISO27001','2022','A-TECH','Technological security control themes','Access, configuration, cryptography, logging and vulnerability controls.',['IAM-01','CFG-01','CRY-01','LOG-01','VUL-01'],'https://www.iso.org/standard/27001'),

 R('ISO42001','2023','C4','AIMS context and scope','Define AI management-system context, stakeholders and boundaries.',['SCP-01','AST-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','C5','AI leadership and governance','Leadership accountability, AI policy and responsibilities.',['GOV-01','POL-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','C6','AI risk planning','AI risks, opportunities, objectives and treatment planning.',['RSK-01','AI-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','C7','AIMS support','Competence, communication, resources and documented information.',['GOV-01','EVD-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','C8','AI operational governance','Operate AI risk, impact, lifecycle and change controls.',['AI-01','DAT-01','VUL-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','C9','AIMS performance evaluation','Measure AIMS performance and perform audit and management review.',['AI-02','AUD-01','GOV-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','C10','AIMS improvement','Correct nonconformities and continually improve the AIMS.',['CAPA-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','A2-A4','AI policy, organization and resources','Govern AI policies, responsibilities and accountable resources.',['POL-01','GOV-01','AST-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','A5-A7','AI impact, lifecycle and data','Assess impacts and govern AI lifecycle and data.',['AI-01','DAT-01','RSK-01'],'https://www.iso.org/standard/81230.html'),
 R('ISO42001','2023','A8-A10','AI transparency, use and external relationships','Govern information to stakeholders, responsible use and supplier relationships.',['AI-02','TPRM-01','GOV-01'],'https://www.iso.org/standard/81230.html'),

 R('ISO27701','2019','PIMS-GOV','Privacy management governance','Establish privacy governance, accountability, scope and controlled information.',['GOV-01','SCP-01','POL-01'],'https://www.iso.org/standard/71670.html'),
 R('ISO27701','2019','PII-RISK','Privacy risk management','Assess privacy risk and link treatment to accountable controls.',['RSK-01','DAT-01'],'https://www.iso.org/standard/71670.html'),
 R('ISO27701','2019','PII-LIFE','PII processing lifecycle','Govern collection, use, sharing, retention and deletion of PII.',['DAT-01','EVD-01'],'https://www.iso.org/standard/71670.html'),
 R('ISO27701','2019','PII-SEC','Privacy security safeguards','Protect PII through access, cryptography, monitoring and incident controls.',['IAM-01','CRY-01','LOG-01','IR-01'],'https://www.iso.org/standard/71670.html'),
 R('ISO27701','2019','PII-THIRD','Processor and supplier governance','Govern processor relationships, shared responsibilities and evidence.',['TPRM-01','DAT-01'],'https://www.iso.org/standard/71670.html'),
 R('ISO27701','2019','PIMS-ASSURE','Privacy assurance and improvement','Review privacy controls, audit evidence and corrective actions.',['AUD-01','CAPA-01','EVD-01'],'https://www.iso.org/standard/71670.html'),

 R('NIST_AI_RMF','1.0','GOVERN','GOVERN','Cultivate and implement a culture of AI risk management.',['GOV-01','POL-01','RSK-01','TPRM-01'],'https://www.nist.gov/itl/ai-risk-management-framework'),
 R('NIST_AI_RMF','1.0','MAP','MAP','Establish context and identify AI risks and affected parties.',['SCP-01','AST-01','AI-01','DAT-01'],'https://www.nist.gov/itl/ai-risk-management-framework'),
 R('NIST_AI_RMF','1.0','MEASURE','MEASURE','Analyze, assess, benchmark and monitor AI risks and trustworthiness.',['AI-02','EVD-01','LOG-01'],'https://www.nist.gov/itl/ai-risk-management-framework'),
 R('NIST_AI_RMF','1.0','MANAGE','MANAGE','Prioritize, respond to and monitor AI risks over time.',['RSK-01','CAPA-01','IR-01'],'https://www.nist.gov/itl/ai-risk-management-framework'),

 R('NIST_CSF','2.0','GV','GOVERN','Establish cybersecurity strategy, expectations, policy and oversight.',['GOV-01','POL-01','RSK-01','TPRM-01'],'https://www.nist.gov/cyberframework'),
 R('NIST_CSF','2.0','ID','IDENTIFY','Understand assets, risks and improvement opportunities.',['AST-01','RSK-01'],'https://www.nist.gov/cyberframework'),
 R('NIST_CSF','2.0','PR','PROTECT','Use safeguards to manage cybersecurity risk.',['IAM-01','CFG-01','CRY-01','VUL-01','DAT-01'],'https://www.nist.gov/cyberframework'),
 R('NIST_CSF','2.0','DE','DETECT','Find and analyze possible cybersecurity attacks and compromises.',['LOG-01'],'https://www.nist.gov/cyberframework'),
 R('NIST_CSF','2.0','RS','RESPOND','Take action regarding detected cybersecurity incidents.',['IR-01'],'https://www.nist.gov/cyberframework'),
 R('NIST_CSF','2.0','RC','RECOVER','Restore affected assets and operations and communicate recovery.',['BCM-01','IR-01'],'https://www.nist.gov/cyberframework'),

 R('EU_AI_ACT','2024','RISK','Risk management and governance','Determine applicable AI obligations and maintain governed risk management.',['GOV-01','RSK-01','AI-01'],'https://eur-lex.europa.eu/eli/reg/2024/1689/oj'),
 R('EU_AI_ACT','2024','DATA','Data governance','Govern data quality, provenance and processing appropriate to the AI system.',['DAT-01','AI-01'],'https://eur-lex.europa.eu/eli/reg/2024/1689/oj'),
 R('EU_AI_ACT','2024','DOC','Technical documentation and records','Maintain attributable technical documentation, records and evidence.',['EVD-01','AST-01'],'https://eur-lex.europa.eu/eli/reg/2024/1689/oj'),
 R('EU_AI_ACT','2024','OVERSIGHT','Human oversight and transparency','Provide appropriate transparency, instructions and human oversight.',['AI-01','AI-02','GOV-01'],'https://eur-lex.europa.eu/eli/reg/2024/1689/oj'),
 R('EU_AI_ACT','2024','ROBUST','Accuracy, robustness and cybersecurity','Govern quality, resilience, monitoring and cybersecurity throughout operation.',['AI-02','VUL-01','LOG-01','IR-01'],'https://eur-lex.europa.eu/eli/reg/2024/1689/oj'),

 R('CIS','8.1','CIS-01','Inventory and control of enterprise assets','Maintain accountable inventory and authorized asset state.',['AST-01'],'https://www.cisecurity.org/controls/v8-1'),
 R('CIS','8.1','CIS-04','Secure configuration','Establish and maintain secure configuration baselines.',['CFG-01'],'https://www.cisecurity.org/controls/v8-1'),
 R('CIS','8.1','CIS-05-06','Account and access control','Govern accounts, authentication and access privileges.',['IAM-01'],'https://www.cisecurity.org/controls/v8-1'),
 R('CIS','8.1','CIS-07','Continuous vulnerability management','Continuously identify, prioritize and remediate vulnerabilities.',['VUL-01'],'https://www.cisecurity.org/controls/v8-1'),
 R('CIS','8.1','CIS-08','Audit log management','Collect, retain and review audit logs.',['LOG-01'],'https://www.cisecurity.org/controls/v8-1'),
 R('CIS','8.1','CIS-15','Service provider management','Inventory and govern service-provider risk.',['TPRM-01'],'https://www.cisecurity.org/controls/v8-1'),
 R('CIS','8.1','CIS-17','Incident response management','Maintain and exercise incident response capabilities.',['IR-01'],'https://www.cisecurity.org/controls/v8-1'),
 R('CIS','8.1','CIS-18','Penetration testing','Validate security through authorized testing and remediation.',['VUL-01','EVD-01'],'https://www.cisecurity.org/controls/v8-1'),

 R('OWASP','2025','A01-A02','Access control and security configuration','Assess application authorization boundaries and security configuration weaknesses.',['APP-01','IAM-01','CFG-01'],'https://owasp.org/Top10/2025/'),
 R('OWASP','2025','A03-A05','Supply chain, cryptography and injection','Govern software supply-chain risk, cryptographic protection and injection resistance.',['APP-01','TPRM-01','CRY-01','VUL-01'],'https://owasp.org/Top10/2025/'),
 R('OWASP','2025','A06-A08','Design, authentication and integrity','Apply secure design, strong authentication and software/data integrity controls.',['APP-01','IAM-01','VUL-01'],'https://owasp.org/Top10/2025/'),
 R('OWASP','2025','A09-A10','Logging and exceptional-condition handling','Monitor security events and handle exceptional conditions without unsafe failure.',['LOG-01','APP-01','IR-01'],'https://owasp.org/Top10/2025/'),

 R('SOC2','TSC','CC','Common Criteria governance and security','Govern the control environment, risk assessment, access, operations, change and monitoring supporting trust-services commitments.',['GOV-01','RSK-01','IAM-01','CFG-01','LOG-01','VUL-01','EVD-01'],'https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services'),
 R('SOC2','TSC','A','Availability','Govern availability commitments, resilience, recovery and operational monitoring where in scope.',['BCM-01','LOG-01','IR-01'],'https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services'),
 R('SOC2','TSC','C-P','Confidentiality and privacy','Protect confidential information and govern privacy commitments where those criteria are in scope.',['DAT-01','PRI-01','CRY-01','IAM-01'],'https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services'),

 R('PCI','4.0.1','R1-2','Network and secure configuration','Protect the cardholder-data environment with network security and secure configurations.',['CFG-01','PAY-01'],'https://www.pcisecuritystandards.org/document_library/'),
 R('PCI','4.0.1','R3-4','Protect account data','Protect stored account data and transmissions using governed data and cryptographic controls.',['PAY-01','DAT-01','CRY-01'],'https://www.pcisecuritystandards.org/document_library/'),
 R('PCI','4.0.1','R5-8','Malware, software and access security','Protect systems from malicious software, develop securely, and enforce identity and access controls.',['APP-01','VUL-01','IAM-01','PAY-01'],'https://www.pcisecuritystandards.org/document_library/'),
 R('PCI','4.0.1','R9-12','Physical, logging, testing and governance','Restrict physical access, monitor access, test security and maintain an information-security program.',['LOG-01','VUL-01','GOV-01','EVD-01','PAY-01'],'https://www.pcisecuritystandards.org/document_library/'),

 R('GDPR','2016/679','PRINCIPLES','Processing principles and accountability','Govern lawful, fair, transparent and accountable processing with appropriate lifecycle controls.',['PRI-01','DAT-01','GOV-01'],'https://eur-lex.europa.eu/eli/reg/2016/679/oj'),
 R('GDPR','2016/679','RIGHTS','Data-subject rights','Operate accountable workflows for applicable individual rights and communications.',['PRI-01','EVD-01'],'https://eur-lex.europa.eu/eli/reg/2016/679/oj'),
 R('GDPR','2016/679','SECURITY','Security and breach governance','Apply risk-appropriate security and govern personal-data incident assessment and notification.',['RSK-01','IAM-01','CRY-01','IR-01','DAT-01'],'https://eur-lex.europa.eu/eli/reg/2016/679/oj'),
 R('GDPR','2016/679','DPIA','Privacy impact and processor governance','Assess high-risk processing and govern processor/supplier relationships and evidence.',['PRI-01','RSK-01','TPRM-01'],'https://eur-lex.europa.eu/eli/reg/2016/679/oj'),

 R('DPDP','2023','NOTICE-CONSENT','Notice, consent and accountable processing','Govern notices, consent or other applicable processing grounds and maintain accountable records.',['PRI-01','DAT-01','EVD-01'],'https://www.meity.gov.in/data-protection-framework'),
 R('DPDP','2023','RIGHTS','Data-principal rights and grievance handling','Operate applicable rights, correction, erasure and grievance workflows.',['PRI-01','EVD-01'],'https://www.meity.gov.in/data-protection-framework'),
 R('DPDP','2023','SAFEGUARDS','Reasonable security safeguards and breach response','Apply reasonable safeguards and govern personal-data breach response and evidence.',['IAM-01','CRY-01','VUL-01','IR-01','DAT-01'],'https://www.meity.gov.in/data-protection-framework'),
 R('DPDP','2023','PROCESSORS','Processor and retention governance','Govern processors, retention/deletion and accountable data lifecycle obligations.',['TPRM-01','DAT-01','PRI-01'],'https://www.meity.gov.in/data-protection-framework'),

 R('HIPAA','Security Rule','ADMIN','Administrative safeguards','Govern security management, workforce access, awareness, incidents, contingency planning and evaluations.',['GOV-01','RSK-01','PEO-01','IAM-01','IR-01','BCM-01'],'https://www.hhs.gov/hipaa/for-professionals/security/index.html'),
 R('HIPAA','Security Rule','TECH','Technical safeguards','Protect electronic protected health information through access, integrity and transmission controls.',['IAM-01','DAT-01','CRY-01','LOG-01'],'https://www.hhs.gov/hipaa/for-professionals/security/index.html'),
 R('HIPAA','Security Rule','ASSURE','Risk analysis and assurance','Maintain evidence-backed risk analysis, control review and corrective action.',['RSK-01','EVD-01','AUD-01','CAPA-01'],'https://www.hhs.gov/hipaa/for-professionals/security/index.html'),

 R('NIST_800_53','Rev5','AC','Access Control','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["IAM-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','AT','Awareness and Training','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["PEO-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','AU','Audit and Accountability','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["LOG-01","EVD-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','CA','Assessment, Authorization and Monitoring','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["AUD-01","EVD-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','CM','Configuration Management','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["CFG-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','CP','Contingency Planning','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["BCM-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','IA','Identification and Authentication','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["IAM-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','IR','Incident Response','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["IR-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','MA','Maintenance','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["CFG-01","AST-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','MP','Media Protection','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["DAT-01","CRY-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','PE','Physical and Environmental Protection','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["AST-01","BCM-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','PL','Planning','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["SCP-01","GOV-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','PM','Program Management','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["GOV-01","POL-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','PS','Personnel Security','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["PEO-01","IAM-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','PT','PII Processing and Transparency','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["PRI-01","DAT-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','RA','Risk Assessment','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["RSK-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','SA','System and Services Acquisition','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["APP-01","TPRM-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','SC','System and Communications Protection','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["CFG-01","CRY-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','SI','System and Information Integrity','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["VUL-01","LOG-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
 R('NIST_800_53','Rev5','SR','Supply Chain Risk Management','Family-level implementation-aid mapping only; does not represent the full SP 800-53 control catalog or assessment procedures.',["TPRM-01"],'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final')
,
 R('CSA_AICM','1.0','A&A','Audit and Assurance','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["AUD-01","EVD-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','AIS','Application and Interface Security','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["APP-01","IAM-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','BCR','Business Continuity Management and Operational Resilience','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["BCM-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','CCC','Change Control and Configuration Management','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["CFG-01","APP-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','CEK','Cryptography, Encryption and Key Management','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["CRY-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','DCS','Datacenter Security','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["AST-01","BCM-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','DSP','Data Security and Privacy Lifecycle Management','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["DAT-01","PRI-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','GRC','Governance, Risk Management and Compliance','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["GOV-01","RSK-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','HRS','Human Resources','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["PEO-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','IAM','Identity and Access Management','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["IAM-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','IPY','Interoperability and Portability','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["AST-01","TPRM-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','I&S','Infrastructure Security','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["CFG-01","VUL-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','LOG','Logging and Monitoring','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["LOG-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','MDS','Model Security','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["AI-01","AI-02"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','SEF','Security Incident Management, E-Discovery, and Cloud Forensics','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["IR-01","EVD-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','STA','Supply Chain Management Transparency and Accountability','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["TPRM-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','TVM','Threat and Vulnerability Management','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["VUL-01","RSK-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix'),
 R('CSA_AICM','1.0','UEM','Universal Endpoint Management','Domain-level cross-framework implementation aid derived from the supplied CSA AICM v1.0 guidance; not the complete 243-control catalog.',["AST-01","IAM-01"],'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix')
];

export const builtInFrameworkLibrary={controls,requirements};

export async function initBuiltInFrameworkLibrary(){
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  for(const c of controls)await client.query(`INSERT INTO grc_canonical_controls(id,control_key,title,description,domain,version,active)
   VALUES($1,$2,$3,$4,$5,1,true) ON CONFLICT(control_key) DO UPDATE SET title=EXCLUDED.title,description=EXCLUDED.description,domain=EXCLUDED.domain,active=true,updated_at=now()`,
   [id('control:'+c.key),c.key,c.title,c.description,c.domain]);
  for(const r of requirements){
   const rid=id('requirement:'+r.framework+':'+r.version+':'+r.key);
   await client.query(`INSERT INTO grc_framework_requirements(id,framework,framework_version,requirement_key,title,summary,source_url,active)
    VALUES($1,$2,$3,$4,$5,$6,$7,true) ON CONFLICT(framework,framework_version,requirement_key) DO UPDATE SET title=EXCLUDED.title,summary=EXCLUDED.summary,source_url=EXCLUDED.source_url,active=true`,
    [rid,r.framework,r.version,r.key,r.title,r.summary,r.source]);
   for(const key of r.controls){
    const cid=(await client.query('SELECT id FROM grc_canonical_controls WHERE control_key=$1',[key])).rows[0]?.id;
    if(cid)await client.query(`INSERT INTO grc_control_framework_mappings(control_id,requirement_id,mapping_type,mapping_version)
     VALUES($1,$2,'SUPPORTS',1) ON CONFLICT(control_id,requirement_id,mapping_version) DO UPDATE SET mapping_type=EXCLUDED.mapping_type`,[cid,rid]);
   }
  }
  await client.query('COMMIT');
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
