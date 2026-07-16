#!/usr/bin/env bash
# H1 build-container recon v2 (read-only, RoE-clean). Writes a SANITIZED summary to
# public/recon.txt (env KEY names only, metadata REACHABILITY only — NO secret values,
# NO tokens) so it is safe to serve from my own site. Researcher: abedalaziz123sayed.
set +e
OUT="public/recon.txt"
mkdir -p public
{
echo "=====H1RECON_START====="
echo "## identity"; id; whoami; uname -a
echo "## container_cgroup"; cat /proc/self/cgroup 2>/dev/null | head
echo "## host"; hostname; (hostname -I 2>/dev/null || true)
echo "## net_ifaces"; (ip -o -4 addr 2>/dev/null || true)
echo "## default_route"; (ip route 2>/dev/null | grep default || true)
echo "## ENV_KEYS_ONLY (no values)"; env | cut -d= -f1 | sort
echo "## NETLIFY_var_key_count"; env | cut -d= -f1 | grep -ci netlify
echo "## home_listing"; echo "HOME=$HOME"; ls -la "$HOME" 2>/dev/null | head -25
echo "## opt_buildhome"; ls -la /opt/buildhome 2>/dev/null | head -25
echo "## sudo"; sudo -n true 2>&1 && echo SUDO_YES || echo SUDO_NO
echo "## docker_sock"; ls -la /var/run/docker.sock 2>/dev/null || echo no-docker-sock
echo "## AWS_IMDS_reachable (dir listing only, not creds)"
curl -s --max-time 4 -o /tmp/imds1 -w "http=%{http_code} exit-ok" http://169.254.169.254/latest/meta-data/ 2>&1; echo; echo "first-line: $(head -1 /tmp/imds1 2>/dev/null)"
echo "## AWS_IMDSv2_tokenendpoint (len only)"
T=$(curl -s --max-time 4 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token 2>/dev/null); echo "imdsv2_token_len=${#T}"
echo "## GCP_metadata_reachable (dir listing only, not token)"
curl -s --max-time 4 -o /tmp/gcp1 -w "http=%{http_code}" -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/ 2>&1; echo; echo "first-line: $(head -1 /tmp/gcp1 2>/dev/null)"
echo "## GCP_sa_email (identity only, not token)"
curl -s --max-time 4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email 2>&1 | head -1
echo "## internal_dns_resolve"
for h in nf-server-api.services-prod.nsvcs.net functions-origin-api.services-prod.nsvcs.net api.netlify.com metadata.google.internal; do echo "-- $h: $(getent hosts "$h" 2>/dev/null | head -1)"; done
echo "=====H1RECON_END====="
} > "$OUT" 2>&1
cat "$OUT"
