(function (global) {
  let clientPromise = null;

  async function initSupabaseClient() {
    if (!global.supabase || typeof global.supabase.createClient !== 'function') {
      throw new Error('Authentication library failed to load.');
    }

    const res = await fetch('/api/config', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    });

    const payload = await res.json().catch(() => ({}));
    if (!res.ok || !payload.supabaseUrl || !payload.supabaseAnonKey) {
      throw new Error(payload.error || 'System configuration is unavailable.');
    }

    return global.supabase.createClient(payload.supabaseUrl, payload.supabaseAnonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: false
      }
    });
  }

  function getSupabaseClient() {
    if (!clientPromise) {
      clientPromise = initSupabaseClient().catch((err) => {
        clientPromise = null;
        throw err;
      });
    }
    return clientPromise;
  }

  async function getAuthenticatedUserContext() {
    const client = await getSupabaseClient();
    const { data: sessionData } = await client.auth.getSession();
    if (!sessionData?.session) {
      return null;
    }

    const { data: userData, error: userErr } = await client.auth.getUser();
    const user = userData?.user;
    if (userErr || !user) {
      await client.auth.signOut().catch(() => {});
      return null;
    }

    const { data: profile, error: profileErr } = await client
      .from('profiles')
      .select('id, email, full_name, role, is_active')
      .eq('id', user.id)
      .single();

    if (profileErr || !profile || !profile.is_active) {
      await client.auth.signOut().catch(() => {});
      return null;
    }

    const effectiveRole =
      user.app_metadata?.role === 'admin' && profile.role === 'admin' ? 'admin' : 'custodian';

    return {
      client,
      session: sessionData.session,
      user,
      profile,
      role: effectiveRole
    };
  }

  global.gsoSupabase = {
    getSupabaseClient,
    getAuthenticatedUserContext
  };
})(window);
