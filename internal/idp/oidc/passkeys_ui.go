// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"encoding/json"
	"html/template"
	"strings"
)

// pkCSP is the policy of every passkey page: one inline script, only with this
// response's nonce, no network access (the browser API talks to the
// authenticator, the result travels in an ordinary form post).
func pkCSP(nonce string) string {
	return "default-src 'none'; style-src 'nonce-" + nonce + "'; script-src 'nonce-" + nonce + "'; base-uri 'none'; frame-ancestors 'none'"
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("oidc: passkey options: " + err.Error())
	}
	return string(b)
}

// pkScript is the only JavaScript haven-idp serves. It is static text (no
// server data is interpolated: options arrive in the form's data-opts
// attribute and are parsed as JSON) and runs only with the page's nonce.
// Forms marked data-pk="get" or "create" are driven here; everything else is
// plain HTML. Without WebAuthn support the passkey parts stay hidden and
// .pk-no elements are shown.
//
// A form marked data-conditional="1" (the login page) also starts a
// conditional-mediation request ("passkey autofill") when the browser offers
// it: passive, showing nothing until the user picks a passkey from the
// username field's autofill list, silent on every failure, and aborted before
// the button starts its own request (a page may have only one pending). It
// never touches the password form beyond reading the "keep me signed in" box.
const pkScriptText = `(function(){
function d(s){s=s.split('-').join('+').split('_').join('/');while(s.length%4){s+='=';}var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++){u[i]=b.charCodeAt(i);}return u.buffer;}
function e(buf){var u=new Uint8Array(buf),s='';for(var i=0;i<u.length;i++){s+=String.fromCharCode(u[i]);}return btoa(s).split('+').join('-').split('/').join('_').split('=').join('');}
function set(f,n,v){var x=f.querySelector('input[name='+n+']');if(x){x.value=v;}}
function say(f,t){var m=f.querySelector('.pk-err');if(m){m.textContent=t;m.hidden=false;}}
function desc(l){return (l||[]).map(function(c){return {type:c.type,id:d(c.id),transports:c.transports};});}
var supported=!!(window.PublicKeyCredential&&navigator.credentials&&window.atob);
var forms=document.querySelectorAll('form[data-pk]');
var no=document.querySelectorAll('.pk-no');
for(var i=0;i<no.length;i++){no[i].hidden=supported;}
if(!supported){return;}
Array.prototype.forEach.call(forms,function(f){
var o;try{o=JSON.parse(f.getAttribute('data-opts'));}catch(x){return;}
var btn=f.querySelector('button[type=button]');
f.hidden=false;
var busy=false,auto=null;
function request(){return {challenge:d(o.challenge),rpId:o.rpId,timeout:o.timeout,userVerification:o.userVerification,allowCredentials:desc(o.allowCredentials)};}
function answer(c){var r=c.response,k=document.querySelector('input[type=checkbox][name=remember_me]');
set(f,'remember_me',k&&k.checked?'on':'');
set(f,'pk_cred',e(c.rawId));set(f,'pk_cd',e(r.clientDataJSON));set(f,'pk_ad',e(r.authenticatorData));set(f,'pk_sig',e(r.signature));set(f,'pk_uh',r.userHandle?e(r.userHandle):'');f.submit();}
function autofill(){
var P=window.PublicKeyCredential;
if(f.getAttribute('data-conditional')!=='1'||!window.AbortController||typeof P.isConditionalMediationAvailable!=='function'){return;}
P.isConditionalMediationAvailable().then(function(ok){
if(!ok||busy||auto){return;}
var a=new AbortController();auto=a;
return navigator.credentials.get({publicKey:request(),mediation:'conditional',signal:a.signal}).then(function(c){if(auto===a&&c){busy=true;answer(c);}});
}).catch(function(){});
}
function go(){
if(busy){return;}busy=true;
if(auto){auto.abort();auto=null;}
var p;
if(f.getAttribute('data-pk')==='get'){
p=navigator.credentials.get({publicKey:request()}).then(answer);
}else{
var pc={challenge:d(o.challenge),rp:o.rp,user:{id:d(o.user.id),name:o.user.name,displayName:o.user.displayName},pubKeyCredParams:o.pubKeyCredParams,timeout:o.timeout,attestation:'none',authenticatorSelection:o.authenticatorSelection,excludeCredentials:desc(o.excludeCredentials)};
p=navigator.credentials.create({publicKey:pc}).then(function(c){var r=c.response;
set(f,'pk_cd',e(r.clientDataJSON));set(f,'pk_att',e(r.attestationObject));set(f,'pk_tr',r.getTransports?r.getTransports().join(','):'');f.submit();});
}
p.catch(function(){busy=false;say(f,f.getAttribute('data-fail')||'The passkey request was cancelled or is not available on this device.');autofill();});
}
if(btn){btn.addEventListener('click',go);}
if(f.getAttribute('data-auto')==='1'){try{go();}catch(x){busy=false;}}
autofill();
});
})();`

var pkScript = template.JS(pkScriptText)

// Login page snippet (a template "passkey" attached to pageTmpl). Hidden until
// the script confirms the browser supports WebAuthn.
const pkLoginSnippet = `{{define "passkey"}}{{with .Passkey}}<form id="pkform" method="post" action="{{$.Action}}" data-pk="get" data-conditional="1" data-opts="{{.Opts}}" data-fail="{{$.L.T "The passkey request was cancelled or is not available on this device."}}" hidden>
<input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="pk_mode" value="login"><input type="hidden" name="pk_token" value="{{.Token}}"><input type="hidden" name="remember_me">
<input type="hidden" name="pk_cred"><input type="hidden" name="pk_cd"><input type="hidden" name="pk_ad"><input type="hidden" name="pk_sig"><input type="hidden" name="pk_uh">
<button type="button">{{$.L.T "Sign in with a passkey"}}</button><p class="err pk-err" role="alert" hidden></p></form>
<script nonce="{{$.Nonce}}">{{.Script}}</script>{{end}}{{end}}`

// Second-factor step body (rendered through stepPage; Data is pkStepData).
var pkStepBody = strings.TrimSpace(`
<p class="sub">{{.L.T "Confirm it is you with a passkey or security key."}}</p>
<form method="post" action="{{.Action}}" data-pk="get" data-auto="1" data-opts="{{.Data.Opts}}" data-fail="{{.L.T "The passkey request was cancelled or is not available on this device."}}" hidden>
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="pk_mode" value="2fa"><input type="hidden" name="pk_token" value="{{.Data.Token}}">
<input type="hidden" name="pk_cred"><input type="hidden" name="pk_cd"><input type="hidden" name="pk_ad"><input type="hidden" name="pk_sig"><input type="hidden" name="pk_uh">
<button type="button">{{.L.T "Use passkey"}}</button><p class="err pk-err" role="alert" hidden></p></form>
<p class="err pk-no" role="alert" hidden>{{.L.T "This browser does not support passkeys, so this sign-in cannot continue here."}}</p>
<script nonce="{{.Nonce}}">{{.Data.Script}}</script>`)
