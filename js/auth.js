(function () {
  const loginForm = document.getElementById('loginForm');
  const errorEl = document.getElementById('loginError');
  const submitBtn = loginForm ? loginForm.querySelector('button[type="submit"]') : null;

  let failedAttempts = 0;
  let lockoutUntil = 0;

  if (!loginForm) return;

  // If already signed in with an active profile, go directly to inventory
  (async function checkExistingSession() {
    try {
      const ctx = await window.gsoSupabase.getAuthenticatedUserContext();
      if (ctx) {
        window.location.replace('pages/inventory.html');
      }
    } catch {
      // Leave user on login page if config isn't loaded yet
    }
  })();

  loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    errorEl.textContent = '';

    const now = Date.now();
    if (now < lockoutUntil) {
      const secondsLeft = Math.ceil((lockoutUntil - now) / 1000);
      errorEl.textContent = `Too many failed attempts. Please wait ${secondsLeft}s before trying again.`;
      return;
    }

    const email = document.getElementById('loginEmail').value.trim().toLowerCase();
    const password = document.getElementById('loginPassword').value;

    if (!email || !password) {
      errorEl.textContent = 'Please enter both email and password.';
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errorEl.textContent = 'Please enter a valid email address.';
      return;
    }

    if (password.length < 6) {
      errorEl.textContent = 'Password must be at least 6 characters.';
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in…';
    }

    try {
      const client = await window.gsoSupabase.getSupabaseClient();
      const { data, error } = await client.auth.signInWithPassword({ email, password });

      if (error || !data?.user) {
        failedAttempts += 1;
        if (failedAttempts >= 5) {
          lockoutUntil = Date.now() + 30000;
          failedAttempts = 0;
        }
        errorEl.textContent = 'Invalid email or password.';
        return;
      }

      const { data: profile, error: profileErr } = await client
        .from('profiles')
        .select('id, full_name, role, is_active')
        .eq('id', data.user.id)
        .single();

      if (profileErr || !profile || !profile.is_active) {
        await client.auth.signOut().catch(() => {});
        errorEl.textContent = 'Account is inactive or not provisioned. Contact your GSO administrator.';
        return;
      }

      failedAttempts = 0;
      window.location.href = 'pages/inventory.html';
    } catch (err) {
      errorEl.textContent = err?.message || 'Unable to sign in right now. Please try again.';
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-arrow-right-to-bracket"></i> Log in';
      }
    }
  });
})();
