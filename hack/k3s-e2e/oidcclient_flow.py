#!/usr/bin/env python3
"""OIDCClient lifecycle against the deployed plane. Runs ON the dev host. Never prints secrets."""
import base64,json,subprocess,sys,time,urllib.parse,urllib.request
PORT=sys.argv[1]; NS=sys.argv[2]; REALM="platform"; BASE="http://127.0.0.1:"+PORT; R=BASE+"/realms/"+REALM
K=["sudo","-n","k3s","kubectl","-n",NS]
def kc(*a,inp=None):
    p=subprocess.run(K+list(a),capture_output=True,text=True,input=inp); return p.returncode,p.stdout,p.stderr
def secret(name,key):
    rc,out,_=kc("get","secret",name,"-o","jsonpath={.data.%s}"%key); return base64.b64decode(out).decode() if rc==0 and out else None
res={"pass":0,"fail":0}
def ok(n,c,extra=""):
    res["pass" if c else "fail"]+=1; print(("PASS " if c else "FAIL ")+n+(("  -> "+str(extra)[:200]) if (extra and not c) else "")); return c
def http(m,url,data=None,hdr=None,form=True):
    if isinstance(data,dict): data=urllib.parse.urlencode(data).encode()
    try:
        r=urllib.request.urlopen(urllib.request.Request(url,data=data,method=m,headers=hdr or {}),timeout=20); return r.status,r.read().decode()
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
def cc(cid,sec):
    return http("POST",R+"/protocol/openid-connect/token",{"grant_type":"client_credentials","client_id":cid,"client_secret":sec})
def wait(fn,t=120,every=2):
    end=time.time()+t
    while time.time()<end:
        v=fn()
        if v: return v
        time.sleep(every)
    return None
admin=secret("platform-idp","admin-client-secret")
s,b=cc("haven-admin",admin); atok=json.loads(b)["access_token"]
def api(m,p,body=None):
    return http(m,BASE+"/admin/v1"+p,json.dumps(body).encode() if body is not None else None,{"Authorization":"Bearer "+atok,"Content-Type":"application/json"})
def client_ids(): return [c["clientId"] for c in json.loads(api("GET","/realms/%s/clients"%REALM)[1])]
manifest=f"""
apiVersion: identity.haven.dev/v1alpha1
kind: OIDCClient
metadata: {{name: e2e-job, namespace: {NS}}}
spec:
  planeRef: {{name: platform}}
  displayName: E2E nightly job
  serviceAccount: true
  flows: {{authorizationCode: false}}
---
apiVersion: identity.haven.dev/v1alpha1
kind: OIDCClient
metadata: {{name: e2e-web, namespace: {NS}}}
spec:
  planeRef: {{name: platform}}
  displayName: E2E web app
  redirectUris: ["https://web.e2e.example/auth/callback"]
  secretRef: {{name: e2e-web-secret}}
---
apiVersion: identity.haven.dev/v1alpha1
kind: OIDCClient
metadata: {{name: e2e-spa, namespace: {NS}}}
spec:
  planeRef: {{name: platform}}
  displayName: E2E single page app
  public: true
  redirectUris: ["https://spa.e2e.example/cb","http://localhost:5173/cb"]
"""
rc,out,err=kc("apply","-f","-",inp=manifest); ok("apply three OIDCClients (confidential web, service account, public SPA)",rc==0,err)
def ready(n):
    rc,out,_=kc("get","oidcclient",n,"-o","jsonpath={.status.conditions[?(@.type==\"Ready\")].status}"); return out=="True"
for n in ("e2e-job","e2e-web","e2e-spa"): ok("OIDCClient %s becomes Ready"%n,bool(wait(lambda n=n:ready(n),120)),kc("get","oidcclient",n,"-o","jsonpath={.status.conditions}")[1][:200])
ids=client_ids(); ok("the controller created the clients in the IdP",all(c in ids for c in ("e2e-job","e2e-web","e2e-spa")),ids)
rc,out,_=kc("get","secret","e2e-job-oidc","-o","json"); sj=json.loads(out) if rc==0 else {}
ok("service-account Secret written with client-id, client-secret and issuer",set(sj.get("data",{}))>={"client-id","client-secret","issuer"},list(sj.get("data",{})))
ok("Secret is owned by the OIDCClient (garbage collected with it)",any(o.get("kind")=="OIDCClient" for o in sj.get("metadata",{}).get("ownerReferences",[])),sj.get("metadata",{}).get("ownerReferences"))
ok("issuer in the Secret is the plane's public issuer",secret("e2e-job-oidc","issuer")=="https://auth.e2e.haven.test/realms/platform",secret("e2e-job-oidc","issuer"))
rc,out,_=kc("get","secret","e2e-spa-oidc"); ok("public client writes NO Secret",rc!=0)
csec=secret("e2e-job-oidc","client-secret"); s,b=cc("e2e-job",csec); ok("the Secret's value gets a real client_credentials token from the deployed IdP",s==200 and json.loads(b).get("access_token"),(s,b[:80]))
s,b=http("POST",R+"/protocol/openid-connect/token/introspect",{"token":json.loads(b)["access_token"],"client_id":"haven-admin","client_secret":admin}); ok("introspection says active",json.loads(b).get("active") is True,b[:80])
rc,out,_=kc("get","oidcclient","e2e-job","-o","json"); ok("status holds no secret material",csec not in out,"secret found in status")
# status/events leak scan
rc,ev,_=kc("get","events","-o","json"); ok("no client secret in Kubernetes events",csec not in ev)
# idempotence: an idle period causes no changes
g1=kc("get","oidcclient","e2e-job","-o","jsonpath={.metadata.resourceVersion}")[1]; time.sleep(8); g2=kc("get","oidcclient","e2e-job","-o","jsonpath={.metadata.resourceVersion}")[1]
ok("idle reconcile does not rewrite the resource",g1==g2,(g1,g2))
# rotation
kc("annotate","oidcclient","e2e-job","haven.zyvor.dev/rotate-secret=r1","--overwrite")
new=wait(lambda: (lambda v: v if v and v!=csec else None)(secret("e2e-job-oidc","client-secret")),60)
ok("rotate annotation writes a NEW secret",bool(new))
if new:
    s_old,_=cc("e2e-job",csec); s_new,_=cc("e2e-job",new)
    ok("old secret stops working, new one works",s_old in(400,401) and s_new==200,(s_old,s_new))
# drift: delete the client behind the controller's back
api("DELETE","/realms/%s/clients/e2e-web"%REALM); ok("(setup) client deleted directly in the IdP",True)
back=wait(lambda:"e2e-web" in client_ids(),420,10); ok("drift: the controller recreates the missing client (resync)",bool(back),"not recreated within 7 min")
# deletion
kc("delete","oidcclient","e2e-job","e2e-web","e2e-spa","--wait=true","--timeout=90s")
gone=wait(lambda:all(c not in client_ids() for c in ("e2e-job","e2e-web","e2e-spa")),90); ok("deleting the OIDCClients removes the clients from the IdP (finalizer, policy Delete)",bool(gone),client_ids())
ok("their Secrets are garbage collected",all(kc("get","secret",n)[0]!=0 for n in ("e2e-job-oidc","e2e-web-secret")))
print("RESULT pass=%d fail=%d"%(res["pass"],res["fail"])); sys.exit(1 if res["fail"] else 0)
