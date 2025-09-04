// /static/js/admin-token.js — minimal
(() => {
  const TOKEN_KEY = 'qr4event_admin_token';

  const getTokenFromUrl = () => {
    const p = new URLSearchParams(location.search);
    const t = p.get('token');
    return t && t.trim() ? t.trim() : null;
  };
  const saveToken = (t) => { try { localStorage.setItem(TOKEN_KEY, t); } catch {} };
  const getToken  = () => { try { return localStorage.getItem(TOKEN_KEY); } catch { return null; } };

  const showTokenStatus = (t) => {
    const el = document.getElementById('tokenBadge');
    if (!el) return;
    if (t) {
      el.textContent = 'Token chargé';
      el.style.background = '#ecfdf5';
      el.style.color = '#065f46';
      el.style.borderColor = '#a7f3d0';
    } else {
      el.textContent = 'Token: non chargé';
      el.style.background = '#eef6ff';
      el.style.color = '#0369a1';
      el.style.borderColor = '#bae6fd';
    }
  };

  const openTokenModal = () => {
    const m = document.getElementById('tokenModal');
    const i = document.getElementById('tokenInput');
    if (!m || !i) return;
    m.style.display = 'flex';
    i.value = '';
    setTimeout(() => i.focus(), 50);
  };
  const closeTokenModal = () => {
    const m = document.getElementById('tokenModal');
    if (m) m.style.display = 'none';
  };

  async function ensureToken() {
    // 1) param URL > 2) localStorage > 3) modal
    const fromUrl = getTokenFromUrl();
    if (fromUrl) { saveToken(fromUrl); showTokenStatus(fromUrl); return fromUrl; }

    const stored = getToken();
    if (stored) { showTokenStatus(stored); return stored; }

    openTokenModal();
    return new Promise((resolve) => {
      const saveBtn = document.getElementById('tokenSave');
      const cancelBtn = document.getElementById('tokenCancel');
      const input = document.getElementById('tokenInput');
      if (!saveBtn || !cancelBtn || !input) {
        // Pas de modale présente : on résout à null
        showTokenStatus(null);
        return resolve(null);
      }

      function onSave() {
        const v = (input.value || '').trim();
        if (!v) { input.focus(); return; }
        saveToken(v);
        showTokenStatus(v);
        closeTokenModal();
        cleanup();
        resolve(v);
      }
      function onCancel() {
        closeTokenModal();
        cleanup();
        showTokenStatus(null);
        resolve(null);
      }
      function onEnter(e){ if (e.key === 'Enter') onSave(); }
      function cleanup() {
        saveBtn.removeEventListener('click', onSave);
        cancelBtn.removeEventListener('click', onCancel);
        input.removeEventListener('keydown', onEnter);
      }

      saveBtn.addEventListener('click', onSave);
      cancelBtn.addEventListener('click', onCancel);
      input.addEventListener('keydown', onEnter);
    });
  }

  async function fetchWithToken(url, options = {}) {
    const token = await ensureToken();
    if (!token) throw new Error('Token administrateur manquant.');

    const method = (options.method || 'GET').toUpperCase();

    if (method === 'GET') {
      const u = new URL(url, location.origin);
      if (!u.searchParams.get('token')) u.searchParams.set('token', token);
      return fetch(u.toString(), options);
    }

    if (options.body instanceof FormData) {
      if (!options.body.has('token')) options.body.append('token', token);
    } else if (options.headers && /application\/json/i.test(options.headers['Content-Type'] || '')) {
      try {
        const obj = options.body ? JSON.parse(options.body) : {};
        obj.token = obj.token || token;
        options.body = JSON.stringify(obj);
      } catch {
        const fd = new URLSearchParams();
        fd.set('token', token);
        options.body = fd;
        options.headers = { ...(options.headers || {}), 'Content-Type': 'application/x-www-form-urlencoded' };
      }
    } else {
      const fd = new URLSearchParams(typeof options.body === 'string' ? options.body : '');
      if (!fd.has('token')) fd.set('token', token);
      options.body = fd;
      options.headers = { ...(options.headers || {}), 'Content-Type': 'application/x-www-form-urlencoded' };
    }

    return fetch(url, options);
  }

  // Expose global
  window.fetchWithToken = fetchWithToken;
  window.ensureToken = ensureToken;
  window.changeAdminToken = function() {
    try { localStorage.removeItem(TOKEN_KEY); } catch {}
    showTokenStatus(null);
    openTokenModal();
  };

  // Init safe (utile même avec "defer")
  const boot = () => ensureToken();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
