// 🔑 Récupère le token depuis localStorage
let token = localStorage.getItem("qr4event_admin_token");

// ✅ wrapper fetch qui ajoute automatiquement le token (FormData, URLSearchParams, JSON)
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

  // ✅ Cas JSON (Content-Type: application/json)
  if (options.headers && options.headers["Content-Type"] === "application/json") {
    try {
      const obj = typeof body === "string" ? JSON.parse(body) : body || {};
      obj.token = token; // injecte le token
      body = JSON.stringify(obj);
    } catch (e) {
      console.error("❌ Impossible de parser le body JSON", e);
    }
  }
  // ✅ Cas URLSearchParams
  else if (body instanceof URLSearchParams) {
    body.append("token", token);
  }
  // ✅ Cas FormData
  else if (body instanceof FormData) {
    body.append("token", token);
  }
  // ✅ Cas string brute (par ex: "a=1&b=2")
  else if (typeof body === "string") {
    const params = new URLSearchParams(body);
    params.append("token", token);
    body = params;
  }
  // ✅ Cas aucun body → on injecte directement le token
  else if (!body) {
    body = new URLSearchParams({ token });
  }

  return fetch(url, {
    ...options,
    body
  });
}
