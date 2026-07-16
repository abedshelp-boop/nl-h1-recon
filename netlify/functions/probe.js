// Phase-2 probe v5 — characterize Netlify-injected runtime artifacts:
// AWS_LAMBDA_METADATA_API (+ _TOKEN) and NETLIFY_FUNCTIONS_TOKEN. Own tenant, read-only.
// Public URL => redact secret-looking values. Goal: does either token/endpoint expose
// anything beyond this tenant, or accept cross-tenant references?
const KEY = "464649dae257a63eaffa60e7";
function redact(s){
  if(typeof s!=='string') return s;
  // mask long hex/base64/jwt-ish blobs
  return s.replace(/[A-Za-z0-9_\-]{40,}/g, m=>'<redacted:'+m.length+'>')
          .replace(/eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g,'<jwt>');
}
async function tryFetch(url, headers, method){
  try{
    const r = await fetch(url,{ method:method||'GET', headers:headers||{}, signal: AbortSignal.timeout(3000) });
    const t = await r.text();
    let keys=null; try{ keys=Object.keys(JSON.parse(t)); }catch(e){}
    return { status:r.status, ct:r.headers.get('content-type'), json_keys:keys, body: redact(t).slice(0,500) };
  }catch(e){ return { error: String(e).slice(0,120) }; }
}
exports.handler = async (event) => {
  if (!event || !event.queryStringParameters || event.queryStringParameters.k !== KEY) return { statusCode:403, body:'forbidden' };
  const env = process.env;
  const out = { ok:true, note:'p2 probe v5 netlify runtime tokens/metadata-api', env_meta:{} };
  out.env_meta.AWS_LAMBDA_METADATA_API = env.AWS_LAMBDA_METADATA_API || null;
  out.env_meta.AWS_LAMBDA_RUNTIME_API = env.AWS_LAMBDA_RUNTIME_API || null;
  out.env_meta.NETLIFY_FUNCTIONS_TOKEN_len = env.NETLIFY_FUNCTIONS_TOKEN ? env.NETLIFY_FUNCTIONS_TOKEN.length : 0;
  out.env_meta.AWS_LAMBDA_METADATA_TOKEN_len = env.AWS_LAMBDA_METADATA_TOKEN ? env.AWS_LAMBDA_METADATA_TOKEN.length : 0;

  const mapi = env.AWS_LAMBDA_METADATA_API;
  const mtok = env.AWS_LAMBDA_METADATA_TOKEN;
  const ftok = env.NETLIFY_FUNCTIONS_TOKEN;
  out.metadata_api = {};
  if(mapi){
    const base = mapi.startsWith('http') ? mapi : 'http://'+mapi;
    // root + common paths, with and without token
    out.metadata_api.root_noauth = await tryFetch(base+'/');
    out.metadata_api.root_auth = await tryFetch(base+'/', { 'Authorization':'Bearer '+mtok, 'X-Nf-Metadata-Token':mtok||'' });
    for(const p of ['/meta','/metadata','/env','/config','/site','/context','/blobs','/2018-06-01/meta','/v1/meta']){
      out.metadata_api['path'+p] = await tryFetch(base+p, { 'Authorization':'Bearer '+mtok, 'X-Nf-Metadata-Token':mtok||'' });
    }
  }
  // NETLIFY_FUNCTIONS_TOKEN against internal + public endpoints
  out.functions_token = {};
  if(ftok){
    out.functions_token.forigin_root = await tryFetch('https://functions-origin-api.services-prod.nsvcs.net/', { 'Authorization':'Bearer '+ftok });
    for(const p of ['/functions','/invoke','/blobs','/v1','/api/v1/sites','/meta','/health']){
      out.functions_token['forigin'+p] = await tryFetch('https://functions-origin-api.services-prod.nsvcs.net'+p, { 'Authorization':'Bearer '+ftok });
    }
    // does it work as a Netlify API token?
    out.functions_token.api_user = await tryFetch('https://api.netlify.com/api/v1/user', { 'Authorization':'Bearer '+ftok });
    out.functions_token.api_sites = await tryFetch('https://api.netlify.com/api/v1/sites?per_page=2', { 'Authorization':'Bearer '+ftok });
  }
  return { statusCode:200, headers:{'content-type':'application/json'}, body: JSON.stringify(out,null,2) };
};
