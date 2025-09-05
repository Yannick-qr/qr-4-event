// /static/js/admin-token.js — version simplifiée sans modale

(() => {
  const TOKEN_KEY = 'qr4event_admin_token';
  let token = null;

  function initToken() {
    // 1) token dans l’URL
    const p = new URLSearchParams(location.search);
    const fromUrl = p.get('token');
    if (fromUrl) {
      token = fromUrl.trim();
      try { localStorage.setItem(TOKEN_KEY, token); } catch {}
      return token;
    }

    // 2) token en localStorage
    token = localStorage.getItem(TOKEN_KEY);
    if (token) return token;

    // 3) sinon → retour login
    alert("⚠️ Session expirée. Merci de vous reconnecter.");
    window.location.href = "/static/login.html";
    return null;
  }

  function getToken() {
    if (!token) token = initToken();
    return token;
  }

  async function fetchWithToken(url, options = {}) {
    const t = getToken();
    if (!t) throw new Error("Token administrateur manquant.");

    const method = (options.method || 'GET').toUpperCase();

    if (method === 'GET') {
      const u = new URL(url, location.origin);
      if (!u.searchParams.get('token')) u.searchParams.set('token', t);
      return fetch(u.toString(), options);
    }

    if (options.body instanceof FormData) {
      if (!options.body.has('token')) options.body.append('token', t);
    } else if (options.headers && /application\/json/i.test(options.headers['Content-Type'] || '')) {
      const obj = options.body ? JSON.parse(options.body) : {};
      obj.token = obj.token || t;
      options.body = JSON.stringify(obj);
    } else {
      const fd = new URLSearchParams(options.body || '');
      if (!fd.has('token')) fd.set('token', t);
      options.body = fd;
      options.headers = { ...(options.headers || {}), 'Content-Type': 'application/x-www-form-urlencoded' };
    }

    return fetch(url, options);
  }

  // Expose global
  window.fetchWithToken = fetchWithToken;
  window.getAdminToken = getToken;

  // Init auto
  initToken();
})();
