import {
  checkRateLimit,
  enforceSameOrigin,
  getClientIp,
  isValidEmail,
  readJsonBody,
  requireAdmin,
  sanitizeText,
  setApiSecurityHeaders,
  validatePasswordStrength
} from '../_lib/security.js';

export default async function handler(req, res) {
  setApiSecurityHeaders(res);

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  if (!enforceSameOrigin(req, res)) return;

  const ip = getClientIp(req);
  if (!checkRateLimit(`create-user:${ip}`, 20, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  const auth = await requireAdmin(req, res);
  if (!auth) return;

  const { supabaseAdmin, caller } = auth;
  if (!checkRateLimit(`create-user:admin:${caller.id}`, 20, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Rate limit exceeded for account creation.' });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    const status = err.message === 'PAYLOAD_TOO_LARGE' ? 413 : 400;
    return res.status(status).json({ error: 'Invalid request payload.' });
  }

  // Strict allowlist destructuring (prevents mass assignment)
  const fullName = sanitizeText(body.fullName, 120);
  const email = sanitizeText(body.email, 254).toLowerCase();
  const password = typeof body.password === 'string' ? body.password : '';
  const role = body.role === 'admin' ? 'admin' : 'custodian';

  if (!fullName || !email || !password) {
    return res.status(400).json({ error: 'Full name, email, and password are required.' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  const pwError = validatePasswordStrength(password);
  if (pwError) {
    return res.status(400).json({ error: pwError });
  }

  try {
    const { data: created, error: createErr } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      app_metadata: { role },
      user_metadata: { full_name: fullName }
    });

    if (createErr || !created?.user) {
      const msg = createErr?.message?.toLowerCase().includes('already')
        ? 'An account with that email already exists.'
        : 'Unable to create account.';
      return res.status(400).json({ error: msg });
    }

    const newUser = created.user;

    const { error: profileErr } = await supabaseAdmin.from('profiles').upsert({
      id: newUser.id,
      email,
      full_name: fullName,
      role,
      is_active: true,
      created_by: caller.id
    });

    if (profileErr) {
      await supabaseAdmin.auth.admin.deleteUser(newUser.id);
      return res.status(500).json({ error: 'Failed to provision user profile.' });
    }

    await supabaseAdmin.from('audit_logs').insert({
      actor_id: caller.id,
      action: 'ADMIN_CREATE_USER',
      table_name: 'profiles',
      record_id: newUser.id,
      details: { email, full_name: fullName, role }
    });

    return res.status(201).json({
      user: {
        id: newUser.id,
        email,
        full_name: fullName,
        role,
        is_active: true,
        created_at: newUser.created_at
      }
    });
  } catch {
    return res.status(500).json({ error: 'Unexpected error while creating account.' });
  }
}
