(()=>{'use strict';
const $=id=>document.getElementById(id);
const els={
 profileFields:$('profileFields'),signinFields:$('signinFields'),enrollStart:$('enrollStart'),enroll:$('enroll'),resetBox:$('resetBox'),
 signinTab:$('signinTab'),signupTab:$('signupTab'),loginMsg:$('loginMsg'),pw:$('pw'),email:$('email'),otp:$('otp'),
 resetEmail:$('resetEmail'),resetOtp:$('resetOtp'),resetPw:$('resetPw'),fullName:$('fullName'),designation:$('designation'),
 companyName:$('companyName'),department:$('department'),workProfile:$('workProfile'),qr:$('qr'),secret:$('secret'),enrollOtp:$('enrollOtp')
};
let enrollUserId='';
async function request(url,opt={}){const r=await fetch(url,opt);let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.error||'HTTP '+r.status);return d}
function authMode(mode){const signup=mode==='signup';els.profileFields.classList.toggle('hidden',!signup);els.signinFields.classList.toggle('hidden',signup);els.enrollStart.classList.toggle('hidden',!signup);els.enroll.classList.add('hidden');els.resetBox.classList.add('hidden');els.signinTab.className=signup?'btn alt':'btn';els.signupTab.className=signup?'btn':'btn alt';els.loginMsg.textContent=signup?'Create your profile, then scan the MFA QR with Google Authenticator or Microsoft Authenticator.':'Enter your email, password and current authenticator code.';els.pw.autocomplete=signup?'new-password':'current-password'}
function togglePassword(button){const show=els.pw.type==='password';els.pw.type=show?'text':'password';button.textContent=show?'◌':'◉';button.setAttribute('aria-label',show?'Hide password':'Show password')}
function openReset(){els.resetEmail.value=els.email.value;els.resetBox.classList.remove('hidden');els.loginMsg.textContent='Password reset requires possession of your enrolled authenticator.'}
function closeReset(){els.resetBox.classList.add('hidden')}
async function resetPassword(){els.loginMsg.textContent='Verifying MFA and resetting password…';try{const d=await request('/api/auth/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:els.resetEmail.value,code:els.resetOtp.value,newPassword:els.resetPw.value})});closeReset();els.email.value=els.resetEmail.value;els.pw.value='';els.otp.value='';els.loginMsg.textContent=d.message}catch(e){els.loginMsg.textContent=e.message}}
async function doLogin(){els.loginMsg.textContent='Verifying account and authenticator code…';try{await request('/api/auth/user-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:els.email.value,password:els.pw.value,code:els.otp.value})});location.reload()}catch(e){els.loginMsg.textContent=e.message}}
async function startEnroll(){els.loginMsg.textContent='Creating secure profile…';try{const d=await request('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:els.email.value,password:els.pw.value,fullName:els.fullName.value,designation:els.designation.value,companyName:els.companyName.value,department:els.department.value,workProfile:els.workProfile.value})});enrollUserId=d.userId;els.enroll.classList.remove('hidden');els.qr.replaceChildren(Object.assign(document.createElement('img'),{src:d.qrDataUrl,width:220,height:220,alt:'TOTP QR compatible with Google Authenticator and Microsoft Authenticator'}));els.secret.textContent='Manual setup key: '+d.secret;els.loginMsg.textContent='Scan with Google Authenticator or Microsoft Authenticator, then enter the current 6-digit code.'}catch(e){els.loginMsg.textContent=e.message}}
async function finishEnroll(){els.loginMsg.textContent='Checking authenticator code…';try{await request('/api/auth/register/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userId:enrollUserId,code:els.enrollOtp.value})});location.reload()}catch(e){els.loginMsg.textContent=e.message}}
function bind(selector,fn){const el=document.querySelector(selector);if(!el)throw Error('Missing authentication control: '+selector);el.addEventListener('click',e=>{e.preventDefault();fn(e,el)})}
bind('#signinTab',()=>authMode('signin'));bind('#signupTab',()=>authMode('signup'));
bind('[data-aegis-click="doLogin()"]',()=>doLogin());bind('#enrollStart',()=>startEnroll());
bind('[data-aegis-click="finishEnroll()"]',()=>finishEnroll());bind('[data-aegis-click="openReset()"]',()=>openReset());
bind('[data-aegis-click="closeReset()"]',()=>closeReset());bind('[data-aegis-click="resetPassword()"]',()=>resetPassword());
bind('[data-aegis-click="togglePassword(\'pw\',this)"]',(_e,el)=>togglePassword(el));
document.documentElement.dataset.aegisAuth='ready';
globalThis.AegisAuth={authMode,doLogin,startEnroll,finishEnroll,openReset,closeReset,resetPassword};
})();