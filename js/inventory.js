(function () {
  // Legacy standalone helper retained only for non-inline pages; enforces Supabase session.
  (async function verifySession() {
    if (!window.gsoSupabase) {
      window.location.replace('../index.html');
      return;
    }
    try {
      const ctx = await window.gsoSupabase.getAuthenticatedUserContext();
      if (!ctx) {
        window.location.replace('../index.html');
        return;
      }
      const userNameEl = document.getElementById('userName');
      if (userNameEl) userNameEl.textContent = ctx.profile.full_name || 'Custodian';
    } catch {
      window.location.replace('../index.html');
    }
  })();
})();
