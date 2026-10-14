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

function aegisOrgId(){return window.activeOrgId||window.currentOrgId||document.querySelector('[data-org-id].active')?.dataset.orgId||''}
window.loadAutomationCenter=async function(){
 const org=aegisOrgId(),assurance=document.getElementById('automationAssurance'),rules=document.getElementById('automationRules'),runs=document.getElementById('automationRuns'),trace=document.getElementById('automationTrace');
 if(!assurance)return;if(!org){assurance.innerHTML='<p class="muted">Select an organization in Enterprise GRC first.</p>';return}
 try{
  const d=await jf('/api/grc/organizations/'+encodeURIComponent(org)+'/automation-center'),a=d.assurance||{},t=d.truthModel||{};
  assurance.innerHTML=[
   ['Evidence queue',a.acceptedSecurityEvidenceAwaitingControlReview??0,'Accepted technical evidence awaiting control review'],
   ['Automation failures',a.recentAutomationFailures??0,'Failures remain visible and never become silent PASS'],
   ['Control tests',Object.values(a.controlTestStates||{}).reduce((x,y)=>x+Number(y||0),0),'Latest deterministic control-test states'],
   ['Final approval',t.finalComplianceApproval||'HUMAN_REVIEW_REQUIRED','Automation cannot issue certification']
  ].map(x=>'<article class="capability-card"><small>AUTOGRC</small><b>'+esc(String(x[0]))+': '+esc(String(x[1]))+'</b><span>'+esc(String(x[2]))+'</span></article>').join('');
  rules.innerHTML=(d.rules||[]).map(x=>'<div class="docrow"><div><b>'+esc(x.name)+'</b><small>'+esc(x.kind)+' · '+(x.enabled?'Enabled':'Disabled')+'</small></div><span class="pill">'+esc(x.next_run_at||'unscheduled')+'</span></div>').join('')||'<p class="muted">No automation rules configured.</p>';
  runs.innerHTML=(d.recentRuns||[]).slice(0,20).map(x=>'<div class="docrow"><div><b>'+esc(x.status)+'</b><small>'+esc(x.started_at||'')+'</small></div><span class="pill">'+Number(x.actions_count||0)+' actions</span></div>').join('')||'<p class="muted">No automation executions recorded.</p>';
  trace.innerHTML=(d.traces||[]).slice(0,30).map(x=>'<div class="docrow"><div><b>'+esc(x.event)+'</b><small>'+esc(x.reason||'Governed automation event')+'</small></div><span class="pill">'+esc(x.created_at||'')+'</span></div>').join('')||'<p class="muted">No automation trace events recorded yet.</p>';
 }catch(e){assurance.textContent=e.message||String(e)}
};

window.loadIncidentWorkspace=async function(){
 const org=aegisOrgId(),summary=document.getElementById('incidentSummary'),iq=document.getElementById('incidentQueue'),sq=document.getElementById('identitySignalQueue');
 if(!org){if(summary)summary.innerHTML='<p class="muted">Select an organization in Enterprise GRC first.</p>';return}
 try{
  const r=await fetch('/api/security/organizations/'+encodeURIComponent(org)+'/incidents');const d=await r.json();if(!r.ok)throw new Error(d.error||'Unable to load incident workspace');
  if(summary)summary.innerHTML='<div class="reviewstats"><div class="reviewstat"><b>'+Number(d.summary?.open||0)+'</b>Open</div><div class="reviewstat"><b>'+Number(d.summary?.critical||0)+'</b>Critical</div><div class="reviewstat"><b>'+Number(d.summary?.identityReviewRequired||0)+'</b>IDR review</div></div>';
  const open=(d.incidents||[]).filter(x=>x.phase!=='CLOSED');if(iq)iq.innerHTML=open.length?open.map(x=>'<div class="audit-row"><b>'+esc(x.incident_key)+' · '+esc(x.title)+'</b><span>'+esc(x.severity)+' · '+esc(x.phase)+' · '+esc(x.source)+'</span></div>').join(''):'<p class="muted">No open incidents.</p>';
  const pending=(d.identitySignals||[]).filter(x=>x.status==='REVIEW_REQUIRED');if(sq)sq.innerHTML=pending.length?pending.map(x=>'<div class="audit-row"><b>'+esc(x.kind)+' · '+esc(x.principal_id)+'</b><span>'+esc(x.source)+' · '+esc(x.observed_at)+'</span><div class="row"><button class="btn alt" data-aegis-click="reviewIdentitySignal(\''+esc(x.id)+'\',\'INVESTIGATED\')">Investigated</button><button class="btn alt" data-aegis-click="reviewIdentitySignal(\''+esc(x.id)+'\',\'BENIGN\')">Benign</button></div></div>').join(''):'<p class="muted">No identity signals awaiting review.</p>';
 }catch(e){if(summary)summary.innerHTML='<p class="muted">'+esc(e.message)+'</p>'}
};
window.reviewIdentitySignal=async function(id,disposition){
 const org=aegisOrgId();if(!org)return;const reason=prompt('Analyst reason for '+disposition+':');if(!reason)return;
 const r=await fetch('/api/security/organizations/'+encodeURIComponent(org)+'/identity-signals/'+encodeURIComponent(id)+'/review',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({disposition,reason})});const d=await r.json();if(!r.ok){alert(d.error||'Identity signal review failed');return}await window.loadIncidentWorkspace();
};
