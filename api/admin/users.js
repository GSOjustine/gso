import {
  checkRateLimit,
  enforceSameOrigin,
  getClientIp,
  readJsonBody,
  requireAdmin,
  sanitizeText,
  setApiSecurityHeaders
} from '../_lib/security.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export default async function handler(req, res) {
  setApiSecurityHeaders(res);

  if (req.method !== 'GET' && req.method !== 'PATCH') {
    res.setHeader('Allow', 'GET, PATCH');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  if (req.method === 'PATCH' && !enforceSameOrigin(req, res)) return;

  const ip = getClientIp(req);
  if (!checkRateLimit(`admin-users:${ip}`, 60, 15 * 60 * 1000)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  const auth = await requireAdmin(req, res);
  if (!auth) return;

  const { supabaseAdmin, caller } = auth;

  if (req.method === 'GET') {
    const { data, error } = await supabaseAdmin
      .from('profiles')
      .select('id, email, full_name, role, is_active, created_at')
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(500).json({ error: 'Failed to load user accounts.' });
    }
    return res.status(200).json({ users: data || [] });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    const status = err.message === 'PAYLOAD_TOO_LARGE' ? 413 : 400;
    return res.status(status).json({ error: 'Invalid request payload.' });
  }

  const userId = sanitizeText(body.userId, 64);
  if (!UUID_RE.test(userId)) {
    return res.status(400).json({ error: 'Invalid user identifier.' });
  }
  if (userId === caller.id) {
    return res.status(400).json({ error: 'You cannot deactivate or demote your own active admin account.' });
  }

  const updates = {};
  if (typeof body.isActive === 'boolean') {
    updates.is_active = body.isActive;
  }
  if (body.role === 'admin' || body.role === 'custodian') {
    updates.role = body.role;
  }
  if (!Object.keys(updates).length) {
    return res.status(400).json({ error: 'No valid account updates provided.' });
  }

  try {
    if (updates.role) {
      const { error: authRoleErr } = await supabaseAdmin.auth.admin.updateUserById(userId, {
        app_metadata: { role: updates.role }
      });
      if (authRoleErr) {
        return res.status(500).json({ error: 'Failed to update user authorization role.' });
      }
    }

    if (typeof updates.is_active === 'boolean') {
      const { error: banErr } = await supabaseAdmin.auth.admin.updateUserById(userId, {
        ban_duration: updates.is_active ? 'none' : '876000h'
      });
      if (banErr) {
        return res.status(500).json({ error: 'Failed to update user access status.' });
      }
    }

    const { data: updatedProfile, error: profileErr } = await supabaseAdmin
      .from('profiles')
      .update(updates)
      .eq('id', userId)
      .select('id, email, full_name, role, is_active, created_at')
      .single();

    if (profileErr || !updatedProfile) {
      return res.status(404).json({ error: 'User account not found.' });
    }

    await supabaseAdmin.from('audit_logs').insert({
      actor_id: caller.id,
      action: 'ADMIN_UPDATE_USER',
      table_name: 'profiles',
      record_id: userId,
      details: updates
    });

    return res.status(200).json({ user: updatedProfile });
  } catch {
    return res.status(500).json({ error: 'Unexpected error while updating account.' });
  }
}
