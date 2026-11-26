import { getSupabaseEnv, setApiSecurityHeaders } from './_lib/security.js';

export default function handler(req, res) {
  setApiSecurityHeaders(res);

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  const { supabaseUrl, supabaseAnonKey } = getSupabaseEnv();
  if (!supabaseUrl || !supabaseAnonKey) {
    return res.status(503).json({
      error: 'Supabase environment variables (SUPABASE_URL, SUPABASE_ANON_KEY) are not configured.'
    });
  }

  // Only public project URL and public anon key are returned; NEVER service role key.
  return res.status(200).json({
    supabaseUrl,
    supabaseAnonKey
  });
}
