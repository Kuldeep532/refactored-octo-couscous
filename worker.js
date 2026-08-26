// Dynamic & Secure Cloudflare API Gateway with Rate Limiting
const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5MB limit
const UPSTREAM_TIMEOUT_MS = 30000;
const VALID_AUTH_STYLES = ['bearer', 'x-api-key', 'query'];

// Simple Rate Limit settings (Fallback if KV/RateLimiter binding is used)
const MAX_REQUESTS_PER_MINUTE = 60;

function buildCorsHeaders(origin, env) {
  const allowedOrigins = (env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);
  const isAllowed = allowedOrigins.length === 0 ? true : allowedOrigins.includes(origin);

  return {
    'Access-Control-Allow-Origin': isAllowed ? (origin || '*') : 'null',
    'Access-Control-Allow-Methods': ALLOWED_METHODS.join(', '),
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Target-Provider, Cache-Control',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}

function jsonError(message, status, corsHeaders) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

function resolveProvider(env, providerName) {
  const envKey = `API_${providerName.toUpperCase()}`;
  const raw = env[envKey];
  if (!raw) return null;

  const parts = raw.split('::');
  if (parts.length !== 3) return { error: `Misconfigured variable ${envKey} (expected baseUrl::authStyle::apiKey)` };

  const [baseUrl, authStyle, apiKey] = parts.map(p => p.trim());

  if (!/^https:\/\/[a-zA-Z0-9.-]+$/.test(baseUrl)) {
    return { error: `Misconfigured variable ${envKey}: invalid baseUrl` };
  }
  if (!VALID_AUTH_STYLES.includes(authStyle)) {
    return { error: `Misconfigured variable ${envKey}: invalid authStyle` };
  }
  if (!apiKey) {
    return { error: `Misconfigured variable ${envKey}: apiKey missing` };
  }

  return { baseUrl, authStyle, apiKey };
}

// Custom Rate Limiter using Cloudflare KV/Binding fallback
async function checkRateLimit(identifier, env) {
  if (env.RATE_LIMITER) {
    // Direct Cloudflare Rate Limiting Binding support
    const { success } = await env.RATE_LIMITER.limit({ key: identifier });
    return success;
  }
  
  if (env.GATEWAY_KV) {
    // Cloudflare KV based Rate Limiting
    const key = `ratelimit:${identifier}`;
    const current = Number(await env.GATEWAY_KV.get(key) || 0);
    if (current >= MAX_REQUESTS_PER_MINUTE) {
      return false;
    }
    await env.GATEWAY_KV.put(key, (current + 1).toString(), { expirationTtl: 60 });
    return true;
  }

  return true; // Pass through if no KV/Limiter is attached yet
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = buildCorsHeaders(origin, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (!ALLOWED_METHODS.includes(request.method)) {
      return jsonError('Method Not Allowed', 405, corsHeaders);
    }

    const url = new URL(request.url);
    if (!url.pathname.startsWith('/gateway/v1/')) {
      return jsonError('Endpoint Not Found', 404, corsHeaders);
    }

    try {
      // 1. Client IP & Rate Limiting Check
      const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
      const isAllowedRate = await checkRateLimit(clientIp, env);
      if (!isAllowedRate) {
        return jsonError('Too Many Requests. Please slow down.', 429, corsHeaders);
      }

      // 2. Supabase Auth Validation
      const authHeader = request.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return jsonError('Unauthorized', 401, corsHeaders);
      }

      const userToken = authHeader.split(' ')[1];
      if (!userToken) {
        return jsonError('Unauthorized', 401, corsHeaders);
      }

      const userResponse = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
        headers: {
          'Authorization': `Bearer ${userToken}`,
          'apikey': env.SUPABASE_ANON_KEY
        }
      });

      if (!userResponse.ok) {
        return jsonError('Invalid or Expired Token', 401, corsHeaders);
      }

      const userData = await userResponse.json();
      const userId = userData?.id || clientIp;

      // User-level Rate Limit check (secondary security layer)
      const isAllowedUser = await checkRateLimit(`user:${userId}`, env);
      if (!isAllowedUser) {
        return jsonError('User Rate Limit Exceeded.', 429, corsHeaders);
      }

      // 3. Resolve Provider
      const providerName = (request.headers.get('X-Target-Provider') || '').trim().toLowerCase();
      if (!providerName || !/^[a-z0-9_]+$/.test(providerName)) {
        return jsonError('Invalid or Missing X-Target-Provider Header', 400, corsHeaders);
      }

      const provider = resolveProvider(env, providerName);
      if (!provider) {
        return jsonError('Unknown Provider', 403, corsHeaders);
      }
      if (provider.error) {
        return jsonError(provider.error, 500, corsHeaders);
      }

      // 4. Target URL Construction
      const path = url.pathname.replace(/^\/gateway\/v1\/?/, '');
      const targetUrl = new URL(`${provider.baseUrl}/${path}${url.search}`);

      // 5. Payload Validation
      let bodyText = null;
      if (!['GET', 'HEAD'].includes(request.method)) {
        const contentLength = Number(request.headers.get('Content-Length') || 0);
        if (contentLength > MAX_BODY_BYTES) {
          return jsonError('Payload Too Large', 413, corsHeaders);
        }
        bodyText = await request.text();
        if (bodyText.length > MAX_BODY_BYTES) {
          return jsonError('Payload Too Large', 413, corsHeaders);
        }
      }

      // 6. Upstream Headers Setup & Key Masking
      const reqHeaders = new Headers();
      const forbiddenHeaders = ['host', 'authorization', 'x-target-provider', 'apikey', 'cookie', 'x-api-key', 'cf-connecting-ip', 'cf-ray'];
      
      for (const [key, value] of request.headers.entries()) {
        if (!forbiddenHeaders.includes(key.toLowerCase())) {
          reqHeaders.set(key, value);
        }
      }
      reqHeaders.set('Content-Type', request.headers.get('Content-Type') || 'application/json');

      if (provider.authStyle === 'bearer') {
        reqHeaders.set('Authorization', `Bearer ${provider.apiKey}`);
      } else if (provider.authStyle === 'x-api-key') {
        reqHeaders.set('x-api-key', provider.apiKey);
        if (providerName === 'anthropic') {
          reqHeaders.set('anthropic-version', reqHeaders.get('anthropic-version') || '2023-06-01');
        }
      } else if (provider.authStyle === 'query') {
        targetUrl.searchParams.set('key', provider.apiKey);
      }

      // 7. Request Timeout Control
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

      let response;
      try {
        response = await fetch(targetUrl.toString(), {
          method: request.method,
          headers: reqHeaders,
          body: ['GET', 'HEAD'].includes(request.method) ? null : bodyText,
          signal: controller.signal
        });
      } catch (fetchErr) {
        if (fetchErr.name === 'AbortError') {
          return jsonError('Upstream Timeout', 504, corsHeaders);
        }
        return jsonError('Upstream Unreachable', 502, corsHeaders);
      } finally {
        clearTimeout(timeoutId);
      }

      // 8. Stream Response Friendly Return (Prevents breaking streaming LLM calls)
      const upstreamType = response.headers.get('Content-Type') || 'application/json';
      const safeType = upstreamType.startsWith('text/html') ? 'text/plain; charset=utf-8' : upstreamType;

      return new Response(response.body, {
        status: response.status,
        headers: {
          'Content-Type': safeType,
          ...corsHeaders
        }
      });

    } catch (err) {
      return jsonError('Internal Gateway Error', 500, corsHeaders);
    }
  }
};
