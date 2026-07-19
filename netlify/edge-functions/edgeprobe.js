// Phase-2 Edge Function (Deno) AI-Gateway key characterization. Key-gated. Keys never returned (only prefix+len+test status).
export default async (request, context) => {
  const url = new URL(request.url);
  if (url.searchParams.get('k') !== 'bl0bx7q2z9k4') return new Response('forbidden', { status: 403 });
  const env = Netlify.env.toObject();
  const out = { keyinfo: {}, baseurls: {}, tests: {} };
  const names = ['ANTHROPIC_API_KEY','OPENAI_API_KEY','GEMINI_API_KEY','NETLIFY_AI_GATEWAY_KEY','NETLIFY_PURGE_API_TOKEN'];
  for (const n of names) { const v = env[n]; out.keyinfo[n] = v ? { prefix: v.slice(0, 16), len: v.length } : null; }
  out.baseurls = {
    ANTHROPIC_BASE_URL: env.ANTHROPIC_BASE_URL, OPENAI_BASE_URL: env.OPENAI_BASE_URL,
    GOOGLE_GEMINI_BASE_URL: env.GOOGLE_GEMINI_BASE_URL, NETLIFY_AI_GATEWAY_URL: env.NETLIFY_AI_GATEWAY_URL,
  };
  const site = { id: context.site?.id, account: context.account?.id };
  out.site = site;

  async function req(u, opt) {
    try { const r = await fetch(u, { ...opt, signal: AbortSignal.timeout(8000) }); const t = await r.text(); return { status: r.status, body: t.slice(0, 220) }; }
    catch (e) { return { err: String(e).slice(0, 140) }; }
  }
  // OpenAI: GET /v1/models = free auth check (200 real-key OK vs 401)
  const ok = env.OPENAI_API_KEY;
  if (ok) {
    out.tests.openai_REAL_upstream = await req('https://api.openai.com/v1/models', { headers: { authorization: 'Bearer ' + ok } });
    if (env.OPENAI_BASE_URL) out.tests.openai_gateway = await req(env.OPENAI_BASE_URL.replace(/\/$/, '') + '/models', { headers: { authorization: 'Bearer ' + ok } });
  }
  // Anthropic: POST /v1/messages with invalid model → 401 bad-auth vs 400/404 auth-OK (NO tokens spent)
  const ak = env.ANTHROPIC_API_KEY;
  if (ak) {
    const body = JSON.stringify({ model: 'invalid-model-xyz', max_tokens: 1, messages: [{ role: 'user', content: 'x' }] });
    const h = { 'x-api-key': ak, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' };
    out.tests.anthropic_REAL_upstream = await req('https://api.anthropic.com/v1/messages', { method: 'POST', headers: h, body });
    if (env.ANTHROPIC_BASE_URL) out.tests.anthropic_gateway = await req(env.ANTHROPIC_BASE_URL.replace(/\/$/, '') + '/v1/messages', { method: 'POST', headers: h, body });
  }
  // Gemini: list models = free auth check
  const gk = env.GEMINI_API_KEY;
  if (gk) out.tests.gemini_REAL_upstream = await req('https://generativelanguage.googleapis.com/v1beta/models?key=' + gk, {});
  return Response.json(out);
};
export const config = { path: '/edge-probe' };
