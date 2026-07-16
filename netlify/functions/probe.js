// Phase-2 functions-runtime recon — OWN tenant only, read-only, RoE-compliant.
// Public URL => NEVER return secret VALUES. Only key names, cred PRESENCE/prefix/ARN,
// non-secret Lambda metadata, dir listings, and reachability status codes.
const fs = require('fs');
const https = require('https');
const http = require('http');
const KEY = "464649dae257a63eaffa60e7";

function listDir(p) { try { return fs.readdirSync(p).slice(0, 250); } catch (e) { return 'ERR:' + (e.code||e.message); } }

function probe(url, timeoutMs, redact) {
  return new Promise((resolve) => {
    try {
      const lib = url.startsWith('https') ? https : http;
      const req = lib.get(url, { timeout: timeoutMs }, (res) => {
        let body = '';
        res.on('data', (c) => { if (body.length < 2000) body += c; });
        res.on('end', () => {
          let out = { status: res.statusCode };
          if (redact) {
            // parse creds JSON but expose ONLY non-secret fields
            try { const j = JSON.parse(body);
              out.RoleArn = j.RoleArn || null;
              out.Expiration = j.Expiration || null;
              out.AccessKeyId_prefix = j.AccessKeyId ? j.AccessKeyId.slice(0,5) : null;
              out.has_Secret = !!j.SecretAccessKey; out.has_Token = !!j.Token;
              out.Code = j.Code || null;
            } catch(e){ out.snippet = '(unparseable, len='+body.length+')'; }
          } else {
            out.snippet = body.slice(0, 400);
          }
          resolve(out);
        });
      });
      req.on('error', (e) => resolve({ error: e.code || String(e) }));
      req.on('timeout', () => { req.destroy(); resolve({ error: 'TIMEOUT' }); });
    } catch (e) { resolve({ error: String(e) }); }
  });
}

exports.handler = async (event) => {
  if (!event || !event.queryStringParameters || event.queryStringParameters.k !== KEY) {
    return { statusCode: 403, body: 'forbidden' };
  }
  const env = process.env;
  const cred = {
    AWS_ACCESS_KEY_ID_present: !!env.AWS_ACCESS_KEY_ID,
    AWS_ACCESS_KEY_ID_prefix: env.AWS_ACCESS_KEY_ID ? env.AWS_ACCESS_KEY_ID.slice(0,5) : null,
    AWS_SECRET_present: !!env.AWS_SECRET_ACCESS_KEY,
    AWS_SESSION_TOKEN_present: !!env.AWS_SESSION_TOKEN,
    AWS_SESSION_TOKEN_len: env.AWS_SESSION_TOKEN ? env.AWS_SESSION_TOKEN.length : 0,
    AWS_REGION: env.AWS_REGION || env.AWS_DEFAULT_REGION || null,
    AWS_LAMBDA_FUNCTION_NAME: env.AWS_LAMBDA_FUNCTION_NAME || null,
    AWS_LAMBDA_LOG_GROUP_NAME: env.AWS_LAMBDA_LOG_GROUP_NAME || null,
    AWS_LAMBDA_LOG_STREAM_NAME: env.AWS_LAMBDA_LOG_STREAM_NAME || null,
    AWS_EXECUTION_ENV: env.AWS_EXECUTION_ENV || null,
    ECS_RELATIVE_URI: env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || null,
    ECS_FULL_URI: env.AWS_CONTAINER_CREDENTIALS_FULL_URI || null,
    LAMBDA_TASK_ROOT: env.LAMBDA_TASK_ROOT || null,
    _HANDLER: env._HANDLER || null,
  };
  const fsi = {
    var_task: listDir('/var/task'),
    var_task_nm: listDir('/var/task/node_modules'),
    opt: listDir('/opt'),
    tmp: listDir('/tmp'),
    var_runtime: listDir('/var/runtime'),
    root: listDir('/'),
    etc_passwd_head: (function(){try{return fs.readFileSync('/etc/passwd','utf8').split('\n').slice(0,5);}catch(e){return 'ERR:'+e.code;}})(),
  };
  const reach = {};
  reach.imds_v1 = await probe('http://169.254.169.254/latest/meta-data/', 1500, false);
  if (env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) reach.ecs_creds = await probe('http://169.254.170.2' + env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, 1500, true);
  if (env.AWS_CONTAINER_CREDENTIALS_FULL_URI) reach.ecs_creds_full = await probe(env.AWS_CONTAINER_CREDENTIALS_FULL_URI, 1500, true);
  reach.functions_origin = await probe('https://functions-origin-api.services-prod.nsvcs.net/', 2500, false);
  return { statusCode: 200, headers: {'content-type':'application/json'},
    body: JSON.stringify({ ok:true, note:'p2 functions-runtime probe, own tenant, redacted',
      env_key_names: Object.keys(env).sort(), cred, fs: fsi, reach }, null, 2) };
};
