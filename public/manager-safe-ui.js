(()=>{'use strict';
function install(){
 const host=document.querySelector('.top-actions');if(!host||document.getElementById('safeTheme'))return;
 const wrap=document.createElement('div');wrap.id='safeTheme';wrap.className='row';
 const select=document.createElement('select');select.setAttribute('aria-label','Theme');select.innerHTML='<option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option>';
 const saved=localStorage.getItem('aegis.safe.theme')||'system';select.value=saved;
 function apply(v){document.documentElement.dataset.theme=v;localStorage.setItem('aegis.safe.theme',v)}
 select.addEventListener('change',()=>apply(select.value));apply(saved);
 const label=document.createElement('span');label.className='muted';label.textContent='Theme';
 wrap.append(label,select);host.prepend(wrap);
}
document.readyState==='loading'?document.addEventListener('DOMContentLoaded',install):install();
})();