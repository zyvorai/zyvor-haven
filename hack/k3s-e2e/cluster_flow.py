#!/usr/bin/env python3
"""Runs ON the dev host against the deployed IdP through a kubectl port-forward.
Secrets are read from Kubernetes Secrets inside this process and never printed."""
import base64,hashlib,json,os,re,subprocess,sys,time,urllib.parse,urllib.request,http.cookiejar
PORT=sys.argv[1]; NS=sys.argv[2]; REALM="platform"
BASE="http://127.0.0.1:"+PORT; R=BASE+"/realms/"+REALM
ISSUER="https://auth.e2e.haven.test/realms/"+REALM
def sec(name,key):
    out=subprocess.run(["sudo","-n","k3s","kubectl","-n",NS,"get","secret",name,"-o","jsonpath={.data.%s}"%key],capture_output=True,text=True).stdout
    return base64.b64decode(out).decode()
res={"pass":0,"fail":0}
def ok(name,cond,extra=""):
    res["pass" if cond else "fail"]+=1; print(("PASS " if cond else "FAIL ")+name+(("  -> "+str(extra)[:160]) if (extra and not cond) else "")); return cond
class NoRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k): return None
class NoSecure(urllib.request.HTTPCookieProcessor):
    # The IdP marks cookies Secure because its public URL is https; we talk plain http through a
    # port-forward, so drop the attribute (a real browser would be on https).
    def http_response(self,req,resp):
        h=resp.headers  # email.message.Message: rewrite Set-Cookie without the Secure attribute
        h._headers=[(k,re.sub(r';\s*Secure','',v,flags=re.I)) if k.lower()=="set-cookie" else (k,v) for k,v in h._headers]
        return super().http_response(req,resp)
def opener():
    cj=http.cookiejar.CookieJar(); o=urllib.request.build_opener(NoRedir,NoSecure(cj)); o.cj=cj; return o
def req(o,m,url,data=None,hdr=None):
    if isinstance(data,dict): data=urllib.parse.urlencode(data).encode()
    try:
        r=o.open(urllib.request.Request(url,data=data,method=m,headers=hdr or {}),timeout=20); return r.status,r.read().decode(),r.headers
    except urllib.error.HTTPError as e: return e.code,e.read().decode(),e.headers
adm=opener()
asec=sec("platform-idp","admin-client-secret")
s,b,_=req(adm,"POST",R+"/protocol/openid-connect/token",{"grant_type":"client_credentials","client_id":"haven-admin","client_secret":asec})
ok("admin service-account token (client_credentials) from the in-cluster secret",s==200,s)
tok=json.loads(b)["access_token"]
def api(m,p,body=None):
    s,b,_=req(adm,m,BASE+"/admin/v1"+p,json.dumps(body).encode() if body is not None else None,{"Authorization":"Bearer "+tok,"Content-Type":"application/json"}); return s,b
cl=json.loads(api("GET","/realms/%s/clients"%REALM)[1]); names=[c["clientId"] for c in cl]
ok("bootstrap created haven-admin and haven-console clients",("haven-admin" in names) and ("haven-console" in names),names)

# ---- features need HAVEN_IDP_SECRET_KEY: prove it reached the pod
s,_=api("GET","/realms/%s/mfa-policy"%REALM); ok("TOTP/MFA feature ON in the cluster (secret key wired)",s==200,s)
s,b=api("POST","/realms/%s/identity-providers"%REALM,{"alias":"e2e-up","providerId":"oidc","enabled":False,"config":{"issuer":"https://accounts.example.org","clientId":"x","clientSecret":"s3cr3t-do-not-leak"}})
ok("federation: provider with a client secret accepted (needs the secret key)",s in(201,204),(s,b))
s,b=api("GET","/realms/%s/identity-providers/e2e-up"%REALM); ok("federation: secret is masked on read","s3cr3t-do-not-leak" not in b and "*****" in b,b[:120])
api("DELETE","/realms/%s/identity-providers/e2e-up"%REALM)

# ---- full interactive login against the PostgreSQL-backed deployment
user="admin"; pw=sec("platform-idp","admin-password")
cs,cb=api("POST","/realms/%s/clients"%REALM,{"clientId":"e2e-app","enabled":True,"publicClient":True,"standardFlowEnabled":True,"redirectUris":["http://localhost:3000/cb"],"deviceFlowEnabled":False})
# a re-run against the same database finds the client from the previous run: that is fine, the point is that it exists
ok("create a public client through the Admin API (or it already exists from an earlier run)",cs in(200,201,204) or (cs==409 and "already exists" in cb),(cs,cb))
def pkce():
    v=base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode(); return v,base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
def q(ch,extra=None):
    d={"client_id":"e2e-app","redirect_uri":"http://localhost:3000/cb","response_type":"code","scope":"openid","state":"s","nonce":"n","code_challenge":ch,"code_challenge_method":"S256"}; d.update(extra or {}); return urllib.parse.urlencode(d)
v,ch=pkce(); br=opener()
s,body,_=req(br,"GET",R+"/protocol/openid-connect/auth?"+q(ch)); csrf=re.search(r'name="csrf" value="([^"]+)"',body).group(1)
s,body,h=req(br,"POST",R+"/protocol/openid-connect/auth?"+q(ch),{"username":user,"password":pw,"csrf":csrf})
ok("password login redirects with a code",s==302 and "code=" in h.get("Location",""),(s,body[:100]))
code=urllib.parse.parse_qs(urllib.parse.urlparse(h["Location"]).query)["code"][0]
s,b,_=req(opener(),"POST",R+"/protocol/openid-connect/token",{"grant_type":"authorization_code","client_id":"e2e-app","redirect_uri":"http://localhost:3000/cb","code":code,"code_verifier":v})
t=json.loads(b); idc=json.loads(base64.urlsafe_b64decode(t["id_token"].split(".")[1]+"=="))
ok("code exchange returns tokens; iss is the configured public issuer",s==200 and idc["iss"]==ISSUER,idc.get("iss")); sid=idc.get("sid"); ok("id_token carries sid",bool(sid))
s,_,h=req(br,"GET",R+"/protocol/openid-connect/auth?"+q(ch,{"prompt":"none"})); ok("SSO: prompt=none with the session cookie returns a code (session stored in PostgreSQL)",s==302 and "code=" in h.get("Location",""),(s,h.get("Location")))
s,_,_=req(opener(),"GET",R+"/protocol/openid-connect/userinfo",None,{"Authorization":"Bearer "+t["access_token"]}); ok("userinfo with the access token",s==200,s)
sl=json.loads(api("GET","/realms/%s/sessions"%REALM)[1]); ok("Admin API lists the live session",any(x["id"]==sid for x in sl),len(sl))
s,_,h=req(br,"GET",R+"/protocol/openid-connect/logout?"+urllib.parse.urlencode({"id_token_hint":t["id_token"],"post_logout_redirect_uri":"http://localhost:3000/cb","client_id":"e2e-app","state":"bye"}))
ok("RP-initiated logout with id_token_hint redirects",s==302 and "state=bye" in h.get("Location",""),(s,h.get("Location")))
s,_,h=req(br,"GET",R+"/protocol/openid-connect/auth?"+q(ch,{"prompt":"none"})); ok("after logout prompt=none -> login_required",s==302 and "login_required" in h.get("Location",""),h.get("Location"))
s,_,_=req(opener(),"GET",R+"/protocol/openid-connect/userinfo",None,{"Authorization":"Bearer "+t["access_token"]}); ok("access token with the ended sid is rejected",s==401,s)

# ---- discovery / JWKS shared by all replicas
s,b,_=req(adm,"GET",R+"/.well-known/openid-configuration"); d=json.loads(b)
ok("discovery issuer is the configured public URL",d.get("issuer")==ISSUER,d.get("issuer"))
for f in ("device_authorization_endpoint","registration_endpoint","backchannel_logout_supported","revocation_endpoint","introspection_endpoint"):
    ok("discovery advertises "+f,f in d,sorted(d)[:40])
ok("PKCE S256 only",d.get("code_challenge_methods_supported")==["S256"],d.get("code_challenge_methods_supported"))
s,b,_=req(adm,"GET",R+"/protocol/openid-connect/certs"); keys=json.loads(b)["keys"]; ok("JWKS publishes an ES256 key",len(keys)>=1 and keys[0].get("alg")=="ES256" or keys[0].get("crv")=="P-256",keys[0])
print("KIDS="+",".join(sorted(k["kid"] for k in keys)))

# ---- device flow + dynamic registration through the deployed server
api("DELETE","/realms/%s/clients/e2e-cli"%REALM)
cs,cb=api("POST","/realms/%s/clients"%REALM,{"clientId":"e2e-cli","enabled":True,"publicClient":True,"deviceFlowEnabled":True})
s,b,_=req(opener(),"POST",R+"/protocol/openid-connect/auth/device",{"client_id":"e2e-cli"}); dj=json.loads(b) if s==200 else {}
ok("device authorization endpoint issues a user code",s==200 and re.fullmatch(r"[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}",dj.get("user_code","")),(s,b[:100]))
s,b,_=req(opener(),"POST",R+"/protocol/openid-connect/token",{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","client_id":"e2e-cli","device_code":dj.get("device_code","x")}); ok("polling before approval -> authorization_pending",json.loads(b).get("error")=="authorization_pending",b[:100])
s,b=api("POST","/realms/%s/initial-access-tokens"%REALM,{"expirationSeconds":600,"count":1,"note":"e2e"}); iat=json.loads(b).get("token") if s in(200,201) else None
ok("dynamic registration: initial access token issued",bool(iat),(s,b[:100]))
if iat:
    s,b,_=req(opener(),"POST",R+"/clients-registrations/openid-connect",json.dumps({"client_name":"e2e dcr","redirect_uris":["https://dcr.example.org/cb"],"token_endpoint_auth_method":"client_secret_basic","grant_types":["authorization_code"]}).encode(),{"Authorization":"Bearer "+iat,"Content-Type":"application/json"})
    rj=json.loads(b) if s==201 else {}; ok("dynamic registration: client registered (201) with secret + registration token",s==201 and rj.get("client_id","").startswith("hc_") and rj.get("client_secret") and rj.get("registration_access_token"),(s,b[:140]))
    if rj.get("registration_access_token"):
        s,_,_=req(opener(),"DELETE",rj["registration_client_uri"].replace("http://127.0.0.1:"+PORT,BASE) if rj["registration_client_uri"].startswith("http://127") else BASE+"/realms/%s/clients-registrations/openid-connect/%s"%(REALM,rj["client_id"]),None,{"Authorization":"Bearer "+rj["registration_access_token"]}); ok("dynamic registration: management delete",s==204,s)
s,b=api("GET","/realms/%s/guard"%REALM); ok("Guard endpoint answers",s==200,s)
api("DELETE","/realms/%s/clients/e2e-app"%REALM); api("DELETE","/realms/%s/clients/e2e-cli"%REALM)
print("RESULT pass=%d fail=%d"%(res["pass"],res["fail"]))
sys.exit(1 if res["fail"] else 0)
