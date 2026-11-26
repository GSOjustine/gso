import { createClient } from '@supabase/supabase-js';

const RATE_BUCKETS = new Map();

export function setApiSecurityHeaders(res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
}

export function enforceSameOrigin(req, res) {
  const origin = req.headers.origin;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  if (!origin || !host) return true;

  try {
    const originHost = new URL(origin).host;
    if (originHost !== host) {
      res.status(403).json({ error: 'Cross-origin request forbidden.' });
      return false;
    }
    return true;
  } catch {
    res.status(403).json({ error: 'Invalid request origin.' });
    return false;
  }
}

export function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

export function checkRateLimit(key, maxRequests = 15, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const timestamps = (RATE_BUCKETS.get(key) || []).filter((ts) => now - ts < windowMs);
  if (timestamps.length >= maxRequests) {
    RATE_BUCKETS.set(key, timestamps);
    return false;
  }
  timestamps.push(now);
  RATE_BUCKETS.set(key, timestamps);
  return true;
}

function cleanEnvValue(val) {
  return (val || '').trim().replace(/^['"]|['"]$/g, '').trim();
}

export function getSupabaseEnv() {
  const supabaseUrl = cleanEnvValue(process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL);
  const supabaseAnonKey = cleanEnvValue(
    process.env.SUPABASE_ANON_KEY ||
    process.env.SUPABASE_PUBLISHABLE_KEY ||
    process.env.VITE_SUPABASE_PUBLISHABLE_KEY
  );
  const supabaseServiceRoleKey = cleanEnvValue(process.env.SUPABASE_SERVICE_ROLE_KEY);

  return { supabaseUrl, supabaseAnonKey, supabaseServiceRoleKey };
}

function getKeyMisconfigReason(serviceRoleKey) {
  if (!serviceRoleKey || serviceRoleKey.includes('paste-your-')) {
    return 'SUPABASE_SERVICE_ROLE_KEY is missing or still set to a placeholder in Vercel.';
  }
  if (serviceRoleKey.startsWith('sb_publishable_')) {
    return 'SUPABASE_SERVICE_ROLE_KEY is set to a publishable key; use the service_role or sb_secret_ key.';
  }
  const parts = serviceRoleKey.split('.');
  if (parts.length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      if (payload?.role && payload.role !== 'service_role') {
        return `SUPABASE_SERVICE_ROLE_KEY has role "${payload.role}" instead of "service_role".`;
      }
    } catch {
      // Ignore malformed base64url; Supabase client will validate
    }
  }
  return null;
}

export async function readJsonBody(req, maxBytes = 16384) {
  if (req.body && typeof req.body === 'object') {
    return req.body;
  }

  return new Promise((resolve, reject) => {
    let raw = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('PAYLOAD_TOO_LARGE'));
        req.destroy();
        return;
      }
      raw += chunk.toString('utf8');
    });
    req.on('end', () => {
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('INVALID_JSON'));
      }
    });
    req.on('error', reject);
  });
}

export function sanitizeText(value, maxLen = 120) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, maxLen);
}

export function isValidEmail(email) {
  return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function validatePasswordStrength(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return 'Password must be between 8 and 128 characters.';
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Password must include uppercase, lowercase, and at least one number.';
  }
  return null;
}

export async function requireAdmin(req, res) {
  const { supabaseUrl, supabaseServiceRoleKey } = getSupabaseEnv();
  if (!supabaseUrl || !supabaseServiceRoleKey) {
    res.status(503).json({ error: 'Server authentication service is not configured.' });
    return null;
  }

  const keyReason = getKeyMisconfigReason(supabaseServiceRoleKey);
  if (keyReason) {
    res.status(503).json({ error: keyReason });
    return null;
  }

  const authHeader = req.headers.authorization || '';
  const match = /^Bearer\s+(.+)$/i.exec(authHeader);
  if (!match) {
    res.status(401).json({ error: 'Authentication required.' });
    return null;
  }

  const token = match[1].trim();
  const supabaseAdmin = createClient(supabaseUrl, supabaseServiceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  try {
    const { data, error } = await supabaseAdmin.auth.getUser(token);
    const user = data?.user;
    if (error || !user) {
      res.status(401).json({ error: 'Invalid or expired session.' });
      return null;
    }

    // Never trust user_metadata for roles — check app_metadata + profiles row
    if (user.app_metadata?.role !== 'admin') {
      res.status(403).json({ error: 'Administrator privileges required.' });
      return null;
    }

    const { data: profile, error: profileErr } = await supabaseAdmin
      .from('profiles')
      .select('id, role, is_active')
      .eq('id', user.id)
      .maybeSingle();

    if (profileErr) {
      const detail = profileErr.code || profileErr.message || 'unknown';
      res.status(503).json({
        error: `Unable to verify admin profile on server (${detail}). Check SUPABASE_SERVICE_ROLE_KEY in Vercel.`
      });
      return null;
    }

    if (!profile || profile.role !== 'admin') {
      res.status(403).json({ error: 'Administrator privileges required.' });
      return null;
    }

    if (!profile.is_active) {
      res.status(403).json({ error: 'Administrator account is not active.' });
      return null;
    }

    return { supabaseAdmin, caller: user };
  } catch {
    res.status(500).json({ error: 'Unable to verify administrator credentials.' });
    return null;
  }
}
