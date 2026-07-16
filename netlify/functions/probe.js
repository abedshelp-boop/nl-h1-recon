// Phase-2 functions-runtime probe v2 — OWN tenant, read-only. Public URL => NO secret values.
// Characterizes IDENTITY only: sts:GetCallerIdentity (who is this Lambda's role?),
// AWS_ACCOUNT_ID, and STRUCTURAL decode of NETLIFY_FUNCTIONS_TOKEN (scope claims, never the token).
const crypto = require('crypto');
const KEY = "464649dae257a63eaffa60e7";
const sha256hex = (s) => crypto.createHash('sha256').update(s,'utf8').digest('hex');
const hmac = (k,s) => crypto.createHmac('sha256',k).update(s,'utf8').digest();

async function stsCallerIdentity(env){
  try{
    const region = env.AWS_REGION || 'us-east-2', service='sts';
    const host = 'sts.' + region + '.amazonaws.com';
    const body = 'Action=GetCallerIdentity&Version=2011-06-15';
    const amzdate = new Date().toISOString().replace(/[:-]/g,'').replace(/\.\d{3}/,'');
    const datestamp = amzdate.slice(0,8);
    const ct = 'application/x-www-form-urlencoded; charset=utf-8';
    const ch = 'content-type:'+ct+'\nhost:'+host+'\nx-amz-date:'+amzdate+'\nx-amz-security-token:'+env.AWS_SESSION_TOKEN+'\n';
    const sh = 'content-type;host;x-amz-date;x-amz-security-token';
    const creq = ['POST','/','',ch,sh,sha256hex(body)].join('\n');
    const scope = datestamp+'/'+region+'/'+service+'/aws4_request';
    const sts = ['AWS4-HMAC-SHA256',amzdate,scope,sha256hex(creq)].join('\n');
    let k = hmac('AWS4'+env.AWS_SECRET_ACCESS_KEY, datestamp);
    k = hmac(k,region); k = hmac(k,service); k = hmac(k,'aws4_request');
    const sig = crypto.createHmac('sha256',k).update(sts,'utf8').digest('hex');
    const auth = 'AWS4-HMAC-SHA256 Credential='+env.AWS_ACCESS_KEY_ID+'/'+scope+', SignedHeaders='+sh+', Signature='+sig;
    const r = await fetch('https://'+host+'/', { method:'POST',
      headers:{ 'Content-Type':ct,'X-Amz-Date':amzdate,'X-Amz-Security-Token':env.AWS_SESSION_TOKEN,'Authorization':auth }, body });
    const t = await r.text();
    const arn = (t.match(/<Arn>(.*?)<\/Arn>/)||[])[1] || null;
    const acct = (t.match(/<Account>(.*?)<\/Account>/)||[])[1] || null;
    const uid = (t.match(/<UserId>(.*?)<\/UserId>/)||[])[1] || null;
    return { http:r.status, Arn:arn, Account:acct, UserId:uid, raw: (arn?null:t.slice(0,300)) };
  }catch(e){ return { error:String(e) }; }
}

function decodeJwt(tok){
  if(!tok) return null;
  const info = { len: tok.length, first4: tok.slice(0,4), last4: tok.slice(-4), looks_jwt: false };
  const parts = tok.split('.');
  if(parts.length===3){
    info.looks_jwt = true;
    try{ info.header = JSON.parse(Buffer.from(parts[0],'base64url').toString()); }catch(e){ info.header='ERR'; }
    try{ const p = JSON.parse(Buffer.from(parts[1],'base64url').toString());
      info.payload_claim_keys = Object.keys(p);
      // expose only scope-revealing, non-credential claims
      const safe = {};
      for(const c of ['iss','aud','exp','iat','nbf','scope','scopes','site_id','account_id','tenant','tenant_id','sub','role','roles','aud','deploy_id','netlify_id']){
        if(p[c]!==undefined) safe[c] = (typeof p[c]==='string' && p[c].length>40) ? p[c].slice(0,40)+'...('+p[c].length+')' : p[c];
      }
      info.safe_claims = safe;
    }catch(e){ info.payload='ERR'; }
  }
  return info;
}

exports.handler = async (event) => {
  if (!event || !event.queryStringParameters || event.queryStringParameters.k !== KEY) return { statusCode:403, body:'forbidden' };
  const env = process.env;
  const out = {
    ok:true, note:'p2 functions-runtime probe v2 (identity), own tenant',
    aws_account_id_env: env.AWS_ACCOUNT_ID || null,
    lambda_function_name: env.AWS_LAMBDA_FUNCTION_NAME || null,
    site_id: env.SITE_ID || null, site_name: env.SITE_NAME || null, url: env.URL || null,
    sts_caller_identity: await stsCallerIdentity(env),
    netlify_functions_token: decodeJwt(env.NETLIFY_FUNCTIONS_TOKEN),
    aws_lambda_metadata_token: env.AWS_LAMBDA_METADATA_TOKEN ? {present:true, len:env.AWS_LAMBDA_METADATA_TOKEN.length} : null,
  };
  return { statusCode:200, headers:{'content-type':'application/json'}, body: JSON.stringify(out, null, 2) };
};
