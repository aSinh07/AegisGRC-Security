(()=>{'use strict';
const stages=[
 {id:'setup',label:'1 · Setup',help:'Organization, people, scope and document intake',terms:['tenant & scope context','organization members','security audit → grc intake','scope & assets','business context','framework selection']},
 {id:'controls',label:'2 · Controls',help:'Frameworks, controls and Statement of Applicability',terms:['frameworks & controls','statement of applicability','enterprise policy','obligation','risk appetite']},
 {id:'evidence',label:'3 · Evidence',help:'Request, upload, validate and test evidence',terms:['evidence requests','evidence & control test','evidence test','security → grc','control assurance']},
 {id:'risk',label:'4 · Risk & Remediation',help:'Findings, risks, CAPA, treatment and retest',terms:['enterprise risk','risk register','capa','remediation','issue','ai impact']},
 {id:'assurance',label:'5 · Review & Assurance',help:'Independent review, audit and governed reporting',terms:['audit','assurance','management review','report','approval','review']},
 {id:'extended',label:'6 · Extended Governance',help:'Third-party, privacy, AI and architecture governance',terms:['third-party','tprm','privacy','supplier','architecture','resilience']}
];
function text(el){return (el?.textContent||'').toLowerCase()}
function classify(card){const t=text(card);for(const s of stages)if(s.terms.some(k=>t.includes(k)))return s.id;return 'extended'}
function showStage(id){
 const root=document.getElementById('grcops');if(!root)return;
 root.dataset.simpleStage=id;
 root.querySelectorAll('.grc-domain-card').forEach(c=>{c.dataset.simpleStage=classify(c);c.hidden=c.dataset.simpleStage!==id});
 root.querySelectorAll('[data-grc-stage]').forEach(b=>{const on=b.dataset.grcStage===id;b.classList.toggle('active',on);b.setAttribute('aria-pressed',String(on))});
 const s=stages.find(x=>x.id===id),title=document.getElementById('grcSimpleTitle'),help=document.getElementById('grcSimpleHelp');
 if(title)title.textContent=s?.label.replace(/^\d+ · /,'')||'Enterprise GRC';if(help)help.textContent=s?.help||'';
 sessionStorage.setItem('aegis.grc.stage',id);
}
function install(){
 const root=document.getElementById('grcops');if(!root||document.getElementById('grcSimpleNav'))return;
 const hero=root.querySelector('.grc-workspace-hero');if(hero){const h=hero.querySelector('h2'),p=hero.querySelector('p');if(h)h.textContent='Enterprise GRC';if(p)p.textContent='A guided governance workspace. Complete the work from setup through independent assurance; open extended governance only when needed.'}
 const nav=document.createElement('section');nav.id='grcSimpleNav';nav.className='grc-simple-nav';nav.setAttribute('aria-label','Enterprise GRC workflow');
 nav.innerHTML='<div class="grc-simple-heading"><div><span>GUIDED WORKFLOW</span><h3 id="grcSimpleTitle">Setup</h3><p id="grcSimpleHelp">Organization, people, scope and document intake</p></div><div class="grc-simple-rule"><b>Evidence before claims</b><small>Human approval remains required where governance requires independence.</small></div></div><div class="grc-simple-steps">'+stages.map(s=>'<button type="button" data-grc-stage="'+s.id+'">'+s.label+'<small>'+s.help+'</small></button>').join('')+'</div>';
 const anchor=document.getElementById('uxGrcBar')||hero;if(anchor)anchor.after(nav);else root.prepend(nav);
 nav.addEventListener('click',e=>{const b=e.target.closest('[data-grc-stage]');if(b)showStage(b.dataset.grcStage)});
 root.querySelectorAll('.grc-domain-card').forEach(c=>c.dataset.simpleStage=classify(c));
 showStage(sessionStorage.getItem('aegis.grc.stage')||'setup');
 const search=document.getElementById('uxGrcSearch');if(search){search.placeholder='Search current GRC step…';search.oninput=e=>{const q=e.target.value.trim().toLowerCase(),stage=root.dataset.simpleStage;root.querySelectorAll('.grc-domain-card').forEach(c=>{const inStage=c.dataset.simpleStage===stage;c.hidden=!inStage||!!q&&!text(c).includes(q)})}}
 const oldIndex=root.querySelector('.ux-grc-index'),oldWork=root.querySelector('.ux-workbench');if(oldIndex)oldIndex.hidden=true;if(oldWork)oldWork.hidden=true;
}
function runtimeGuard(){
 window.addEventListener('error',e=>{console.error('Aegis UI error',e.error||e.message)});
 window.addEventListener('unhandledrejection',e=>{console.error('Aegis async UI error',e.reason)});
 document.addEventListener('click',e=>{const el=e.target.closest('[data-aegis-click]');if(!el)return;const code=el.dataset.aegisClick||'',m=code.match(/^([A-Za-z_$][\w$]*)\s*\(/);if(m&&typeof window[m[1]]!=='function'){e.preventDefault();console.error('Unavailable UI action:',m[1]);const msg=document.getElementById('grcMsg');if(msg)msg.textContent='This action is temporarily unavailable. Refresh the workspace; if it persists, report action '+m[1]+'.'}},true);
}
runtimeGuard();document.readyState==='loading'?document.addEventListener('DOMContentLoaded',install):install();
window.showSimpleGrcStage=showStage;
})();