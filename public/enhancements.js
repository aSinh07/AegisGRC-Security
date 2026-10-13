let aegisKnowledge=[];
async function loadKnowledge(){
 const box=document.getElementById('learningGrid');if(!box)return;
 try{const d=await jf('/api/knowledge');aegisKnowledge=d.modules||[];renderKnowledge()}catch(e){box.textContent=e.message}
}
function renderKnowledge(){
 const box=document.getElementById('learningGrid');if(!box)return;
 const q=(document.getElementById('knowledgeSearch')?.value||'').toLowerCase();
 const level=document.getElementById('knowledgeLevel')?.value||'';
 const rows=aegisKnowledge.filter(m=>(!level||m.level===level)&&(!q||JSON.stringify(m).toLowerCase().includes(q)));
 box.innerHTML=rows.map(m=>'<div class="learn-card" data-learn="'+m.id+'"><small>'+esc(m.category)+' · '+esc(m.level)+'</small><h3>'+esc(m.title)+'</h3><p class="muted">'+esc(m.summary)+'</p><div>'+m.topics.map(t=>'<span class="topic">'+esc(t)+'</span>').join('')+'</div></div>').join('')||'<p class="muted">No matching learning module.</p>';
 box.querySelectorAll('[data-learn]').forEach(el=>el.onclick=()=>{const m=aegisKnowledge.find(x=>x.id===el.dataset.learn);if(!m)return;copilot.classList.remove('closed');cpq.value='Teach me '+m.title+' in practical terms and connect it to evidence, risk, remediation and GRC work.';cpq.focus()});
}
document.addEventListener('input',e=>{if(e.target?.id==='knowledgeSearch')renderKnowledge()});
document.addEventListener('change',e=>{if(e.target?.id==='knowledgeLevel')renderKnowledge()});
window.addEventListener('load',()=>{const old=window.loadDocs;window.loadDocs=async function(){await old();document.querySelectorAll('#doclist .docrow').forEach(row=>{const btns=row.lastElementChild;if(!btns||btns.querySelector('.analyze-btn'))return;const download=btns.querySelector('button');if(!download)return;const m=download.getAttribute('onclick')?.match(/getDoc\('([^']+)'\)/);if(!m)return;const b=document.createElement('button');b.className='btn analyze-btn';b.textContent='Review';b.onclick=()=>analyzeDoc(m[1]);btns.insertBefore(b,download)})}});

function installCvssGuide(){
 const risk=document.getElementById('risk');if(!risk||document.getElementById('cvssGuide'))return;
 const card=document.createElement('div');card.id='cvssGuide';card.className='card span12';
 card.innerHTML='<h3>CVSS Severity Guide</h3><p class="muted"><b>CVSS measures vulnerability severity; it is not a company grade.</b> 0.0 None · 0.1–3.9 Low · 4.0–6.9 Medium · 7.0–8.9 High · 9.0–10.0 Critical. There is no universal score a company must achieve. Remediation priority should also consider exploitability, asset criticality and business impact.</p><span id="cvssEvidence" class="pill">Waiting for evidence-backed CVSS data</span>';
 risk.closest('.grid')?.appendChild(card);
 const original=window.renderFindings;window.renderFindings=function(fs){original(fs);const scores=fs.map(x=>Number(x.cvss)).filter(Number.isFinite),el=document.getElementById('cvssEvidence');if(el)el.textContent=scores.length?'Evidence-backed CVSS: highest '+Math.max(...scores).toFixed(1)+' · '+scores.length+'/'+fs.length+' findings scored':'No evidence-backed CVSS score returned by current findings';};
}
window.addEventListener('load',installCvssGuide);


// Enterprise security workspace v6: product hierarchy + capability operations layer.
function installEnterpriseSecurityWorkspace(){
 const nav=[...document.querySelectorAll('.nav button')];
 const overview=nav.find(b=>b.getAttribute('data-aegis-click')?.includes("tab('overview'"));
 const defensive=nav.find(b=>b.getAttribute('data-aegis-click')?.includes("tab('defensive'"));
 if(overview)overview.innerHTML='◈ Dashboard';
 if(defensive)defensive.innerHTML='⬡ Defensive Security';

 const offensive=document.getElementById('offensive');
 if(offensive&&!document.getElementById('offensiveCapabilityMatrix')){
  const block=document.createElement('div');block.id='offensiveCapabilityMatrix';block.className='enterprise-capability-block';
  block.innerHTML='<div class="capability-head"><div><span class="workspace-kicker">ENTERPRISE OFFENSIVE COVERAGE</span><h3>Authorized Security Testing Workbench</h3><p>Native execution, evidence ingestion and licensed connector paths are shown separately so availability is never fabricated.</p></div><span class="truth-badge">AUTHORIZATION GATED</span></div><div class="capability-grid">'+
  [
   ['Attack Surface','Nmap · Nuclei · testssl.sh','NATIVE'],
   ['Web / API DAST','OWASP ZAP · Wapiti · Nuclei','NATIVE'],
   ['Injection Validation','SQLmap · analyst validation','NATIVE'],
   ['Source / SAST','Semgrep · Trivy · Gitleaks','NATIVE'],
   ['Infrastructure VA','Greenbone / OpenVAS','EVIDENCE'],
   ['Manual Pentest','Analyst evidence · review · retest','EVIDENCE'],
   ['Enterprise Connectors','Burp Enterprise · Tenable · Qualys · Rapid7 · Invicti','CONNECTOR']
  ].map(x=>'<article class="capability-card"><small>'+x[2]+'</small><b>'+x[0]+'</b><span>'+x[1]+'</span></article>').join('')+
  '</div><div class="report-workflow"><b>Reporting workflow</b><span>Scope → authorize → test → preserve evidence → normalize findings → analyst review → remediation → retest → password + authenticator protected export</span></div>';
  offensive.querySelector('.module-hero')?.after(block);
 }
 const defensiveSection=document.getElementById('defensive');
 if(defensiveSection&&!document.getElementById('defensiveCapabilityMatrix')){
  const block=document.createElement('div');block.id='defensiveCapabilityMatrix';block.className='enterprise-capability-block';
  block.innerHTML='<div class="capability-head"><div><span class="workspace-kicker">ENTERPRISE DEFENSE COVERAGE</span><h3>Detection, Hardening & Exposure Reduction</h3><p>Defense is operational security. Governance remains independently available under Enterprise GRC.</p></div><span class="truth-badge defensive">EVIDENCE DRIVEN</span></div><div class="capability-grid">'+
  [
   ['Endpoint / Telemetry','Wazuh evidence and breach telemetry','EVIDENCE'],
   ['Cloud Posture','Prowler · AWS · Azure · GCP','NATIVE'],
   ['Host Hardening','Lynis','NATIVE'],
   ['Containers / SBOM','Trivy · Grype · Syft','NATIVE'],
   ['Kubernetes / IaC','Kubescape · Checkov','NATIVE'],
   ['Risk Reduction','Correlation · prioritization · CAPA · retest','NATIVE'],
   ['Enterprise Ecosystem','Sentinel · Defender · CrowdStrike · Splunk · ServiceNow','CONNECTOR']
  ].map(x=>'<article class="capability-card"><small>'+x[2]+'</small><b>'+x[0]+'</b><span>'+x[1]+'</span></article>').join('')+
  '</div>';
  defensiveSection.querySelector('.module-hero')?.after(block);
 }
 const hero=document.querySelector('#overview .executive-hero h2');if(hero)hero.textContent='Enterprise Security Dashboard';
}
window.addEventListener('load',installEnterpriseSecurityWorkspace);
