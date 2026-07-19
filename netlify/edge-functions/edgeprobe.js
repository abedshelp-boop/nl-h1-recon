// Phase-2 Edge Function (Deno) runtime probe. Key-gated; secrets redacted.
// Tests: (1) what env does an edge fn see — Netlify.env vs raw Deno.env (infra leak?);
// (2) context (site/account/deploy) for cross-referencable tokens/ids;
// (3) Cache API tenant isolation (write own key, try reading a foreign-tenant key).
function redact(s) {
  if (typeof s !== 'string') return s;
  return s.replace(/[A-Za-z0-9_\-\.]{20,}/g, (m) => '<r:' + m.length + '>');
}
export default async (request, context) => {
  const url = new URL(request.url);
  if (url.searchParams.get('k') !== 'bl0bx7q2z9k4') return new Response('forbidden', { status: 403 });
  const out = { runtime: 'edge-deno' };

  // (1) env — Netlify wrapper vs raw Deno.env
  try {
    const e = Netlify.env.toObject();
    out.netlify_env = {}; for (const k of Object.keys(e)) out.netlify_env[k] = redact(e[k]);
  } catch (err) { out.netlify_env_err = String(err).slice(0, 120); }
  try {
    out.has_Deno = typeof Deno !== 'undefined';
    if (typeof Deno !== 'undefined') {
      const de = Deno.env.toObject();
      out.deno_env_keys = Object.keys(de).sort();
      out.deno_env = {}; for (const k of Object.keys(de)) out.deno_env[k] = redact(de[k]);
    }
  } catch (err) { out.deno_env_err = String(err).slice(0, 160); }

  // (2) context
  try {
    out.ctx_keys = Object.keys(context || {});
    out.ctx = {
      site: context.site, account: context.account, deploy: context.deploy,
      server: context.server, geo: context.geo, requestId: context.requestId,
    };
  } catch (err) { out.ctx_err = String(err).slice(0, 120); }

  // (3) Cache API isolation
  try {
    out.has_caches = typeof caches !== 'undefined';
    if (typeof caches !== 'undefined') {
      const c = await caches.open('nl-h1-shared-probe');
      const key = 'https://xtenant-cache-probe.invalid/marker';
      // try reading BEFORE writing — if a foreign tenant wrote here, we'd see it
      const pre = await c.match(key);
      out.cache_preRead = pre ? (await pre.text()).slice(0, 80) : null;
      await c.put(new Request(key), new Response('NL1-EDGE-MARKER'));
      const post = await c.match(key);
      out.cache_selfRead = post ? (await post.text()).slice(0, 80) : null;
      out.cache_default = typeof caches.default !== 'undefined';
    }
  } catch (err) { out.cache_err = String(err).slice(0, 160); }

  return new Response(JSON.stringify(out, null, 2), { headers: { 'content-type': 'application/json' } });
};
export const config = { path: '/edge-probe' };
