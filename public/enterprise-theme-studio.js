(()=>{'use strict';
const K='aegis.palette';
const palettes={cyber:['Cyber',['#67e8f9','#8b5cf6','#22c55e']],royal:['Royal',['#a78bfa','#ec4899','#60a5fa']],ocean:['Ocean',['#38bdf8','#14b8a6','#22c55e']],emerald:['Emerald',['#34d399','#22d3ee','#a3e635']],sunset:['Sunset',['#fb923c','#f43f5e','#facc15']],executive:['Executive',['#d4af37','#c084fc','#60a5fa']]};
function apply(k){if(!palettes[k])k='cyber';document.documentElement.dataset.palette=k;localStorage.setItem(K,k);document.querySelectorAll('.palette-choice').forEach(b=>b.classList.toggle('active',b.dataset.palette===k))}
function install(){
 apply(localStorage.getItem(K)||'cyber');
 if(document.querySelector('.theme-studio'))return true;
 const host=document.querySelector('.top-actions');if(!host)return false;
 const w=document.createElement('div');w.className='theme-studio';
 w.innerHTML='<button type="button" class="theme-studio-btn" aria-haspopup="dialog" aria-expanded="false">Theme Studio</button><div class="theme-studio-panel hidden" role="dialog" aria-label="AegisGRC theme studio"><h4>Enterprise Theme Studio</h4><p>Choose a brand palette. Light / Dark / System remains independent.</p><div class="palette-grid">'+Object.entries(palettes).map(([k,v])=>'<button type="button" class="palette-choice" data-palette="'+k+'"><span class="palette-dots">'+v[1].map(c=>'<i style="background:'+c+'"></i>').join('')+'</span><b>'+v[0]+'</b></button>').join('')+'</div><div class="aegis-accent-line" style="margin-top:12px"></div></div>';
 host.prepend(w);const btn=w.querySelector('.theme-studio-btn'),panel=w.querySelector('.theme-studio-panel');
 btn.addEventListener('click',e=>{e.stopPropagation();const open=panel.classList.toggle('hidden')===false;btn.setAttribute('aria-expanded',String(open))});
 w.querySelector('.palette-grid').addEventListener('click',e=>{const b=e.target.closest('[data-palette]');if(b)apply(b.dataset.palette)});
 document.addEventListener('click',e=>{if(!w.contains(e.target)){panel.classList.add('hidden');btn.setAttribute('aria-expanded','false')}});
 apply(localStorage.getItem(K)||'cyber');return true;
}
function boot(){if(install())return;let tries=0;const id=setInterval(()=>{tries++;if(install()||tries>20)clearInterval(id)},250)}
document.readyState==='loading'?document.addEventListener('DOMContentLoaded',boot):boot();
globalThis.openThemeStudio=()=>{if(!install())return false;document.querySelector('.theme-studio-btn')?.click();return true};
})();