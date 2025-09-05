// static/js/admin-token.js

// 🔑 Récupère le token depuis localStorage
let token = localStorage.getItem("qr4event_admin_token");

// ✅ wrapper fetch qui ajoute automatiquement le token
async function fetchWithToken(url, options = {}) {
  if (!token) {
    token = localStorage.getItem("qr4event_admin_token");
  }

  if (!token) {
    console.error("❌ Aucun token trouvé dans localStorage !");
    alert("⚠️ Session expirée, reconnectez-vous.");
    window.location.href = "/static/login.html";
    return;
  }

  console.log("🔑 Utilisation du token :", token);

  let body = options.body;

  if (body instanceof URLSearchParams) {
    body.append("token", token);
  } else if (body instanceof FormData) {
    body.append("token", token);
  } else if (typeof body === "string") {
    const params = new URLSearchParams(body);
    params.append("token", token);
    body = params;
  } else if (!body) {
    body = new URLSearchParams({ token });
  }

  return fetch(url, {
    ...options,
    body
  });
}
