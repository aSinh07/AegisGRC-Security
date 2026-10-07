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
