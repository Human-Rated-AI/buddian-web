import {
  createEncryptedChatRequest,
  decryptChatResponse,
  estimateTextTokens,
  verifyAttestationForClient,
} from "./e2ee.js";
import { browserLanguage, I18N, normalizeLanguage } from "./i18n.js";

const apiBase = (() => {
  const host = window.location.hostname;
  if (!host || host === "localhost" || host === "127.0.0.1") {
    return "http://localhost:28100";
  }
  if (host.startsWith("api.")) return window.location.origin;
  return `${window.location.protocol}//api.${host}`;
})();

const state = {
  config: null,
  token: localStorage.getItem("trust_session") || "",
  account: null,
  models: [],
  selectedModel: "",
  language: normalizeLanguage(localStorage.getItem("trust_language") || browserLanguage()),
  firebase: {
    modules: null,
    app: null,
    auth: null,
    analytics: null,
    initPromise: null,
  },
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const el = {
  landing: $("#landing"),
  appShell: $("#app-shell"),
  extensionShell: $("#extension-shell"),
  authButton: $("#auth-button"),
  authNote: $("#auth-note"),
  googleLogin: $("#google-login"),
  appleLogin: $("#apple-login"),
  status: $("#service-status"),
  accountEmail: $("#account-email"),
  userBalance: $("#user-balance"),
  search: $("#search"),
  provider: $("#provider"),
  input: $("#input-modality"),
  output: $("#output-modality"),
  modelList: $("#model-list"),
  modelCount: $("#model-count"),
  quoteModel: $("#quote-model"),
  promptText: $("#prompt-text"),
  promptTokens: $("#prompt-tokens"),
  completionTokens: $("#completion-tokens"),
  quoteButton: $("#quote-button"),
  quoteResult: $("#quote-result"),
  runButton: $("#run-button"),
  proofResult: $("#proof-result"),
  inferenceResult: $("#inference-result"),
  topupAmount: $("#topup-amount"),
  topupButton: $("#topup-button"),
  topupResult: $("#topup-result"),
  contraLink: $("#contra-link"),
  installableList: $("#installable-list"),
  usageList: $("#usage-list"),
};

function t(key) {
  return I18N[state.language]?.[key] || I18N.en[key] || key;
}

function setLanguage(value) {
  state.language = normalizeLanguage(value);
  localStorage.setItem("trust_language", state.language);
  applyTranslations();
}

function applyTranslations(root = document) {
  document.documentElement.lang = state.language;
  if (state.firebase.auth) state.firebase.auth.languageCode = state.language;
  root.querySelectorAll?.("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  root.querySelectorAll?.("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", t(node.dataset.i18nPlaceholder));
  });
  root.querySelectorAll?.("[data-i18n-aria-label]").forEach((node) => {
    node.setAttribute("aria-label", t(node.dataset.i18nAriaLabel));
  });
  $$(".global-language-button").forEach((button) => {
    const active = normalizeLanguage(button.dataset.lang) === state.language;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  });
}

function money(value) {
  const numberValue = Number(value || 0);
  return new Intl.NumberFormat(state.language === "en" ? "en-US" : state.language, {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: numberValue < 1 ? 6 : 2,
  }).format(numberValue);
}

function compactNumber(value) {
  if (value === null || value === undefined) return "n/a";
  return new Intl.NumberFormat(state.language === "en" ? "en-US" : state.language, {
    notation: "compact",
  }).format(Number(value));
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    headers,
    body: options.body && !(options.body instanceof FormData) ? JSON.stringify(options.body) : options.body,
  });
  const text = await response.text();
  let body = {};
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { detail: text };
    }
  }
  if (!response.ok) {
    throw new Error(body.detail?.message || body.detail || response.statusText);
  }
  return body;
}

function firebaseConfigured() {
  const firebase = state.config?.firebase || {};
  return Boolean(firebase.enabled && firebase.apiKey && firebase.authDomain && firebase.projectId && firebase.appId);
}

function firebaseConfig() {
  const firebase = state.config?.firebase || {};
  return {
    apiKey: firebase.apiKey,
    authDomain: firebase.authDomain,
    projectId: firebase.projectId,
    storageBucket: firebase.storageBucket,
    messagingSenderId: firebase.messagingSenderId,
    appId: firebase.appId,
    measurementId: firebase.measurementId,
  };
}

async function initFirebase() {
  if (!firebaseConfigured()) return false;
  if (state.firebase.auth) return true;
  if (state.firebase.initPromise) return state.firebase.initPromise;

  state.firebase.initPromise = (async () => {
    const [appModule, authModule, analyticsModule] = await Promise.all([
      import("https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js"),
      import("https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js"),
      import("https://www.gstatic.com/firebasejs/10.14.1/firebase-analytics.js"),
    ]);
    state.firebase.modules = { appModule, authModule, analyticsModule };
    state.firebase.app = appModule.initializeApp(firebaseConfig());
    state.firebase.auth = authModule.getAuth(state.firebase.app);
    state.firebase.auth.languageCode = state.language;
    const redirectResult = await authModule.getRedirectResult(state.firebase.auth).catch(() => null);
    if (redirectResult?.user) await completeFirebaseAuth(redirectResult.user);
    if (firebaseConfig().measurementId) {
      try {
        const supported = await analyticsModule.isSupported();
        if (supported) state.firebase.analytics = analyticsModule.getAnalytics(state.firebase.app);
      } catch {
        state.firebase.analytics = null;
      }
    }
    return true;
  })().catch((error) => {
    state.firebase.initPromise = null;
    throw error;
  });
  return state.firebase.initPromise;
}

function firebaseProvider(providerName) {
  const authModule = state.firebase.modules?.authModule;
  if (!authModule) throw new Error("Firebase is not ready");
  if (providerName === "google") {
    const provider = new authModule.GoogleAuthProvider();
    provider.addScope("email");
    provider.addScope("profile");
    provider.setCustomParameters({ prompt: "select_account" });
    return provider;
  }
  if (providerName === "apple") {
    const provider = new authModule.OAuthProvider("apple.com");
    provider.addScope("email");
    provider.addScope("name");
    return provider;
  }
  throw new Error("Unsupported provider");
}

async function completeFirebaseAuth(firebaseUser) {
  const idToken = await firebaseUser.getIdToken(true);
  const data = await api("/web/auth/firebase", {
    method: "POST",
    body: { id_token: idToken },
  });
  state.token = data.session_token;
  state.account = data.account;
  localStorage.setItem("trust_session", state.token);
  await afterLogin();
}

async function signIn(providerName) {
  el.authNote.textContent = t("signin_opening");
  const ready = await initFirebase();
  if (!ready) throw new Error(t("signin_unconfigured"));
  const authModule = state.firebase.modules.authModule;
  const provider = firebaseProvider(providerName);
  try {
    const result = await authModule.signInWithPopup(state.firebase.auth, provider);
    await completeFirebaseAuth(result.user);
  } catch (error) {
    if (!["auth/popup-blocked", "auth/cancelled-popup-request"].includes(error?.code)) throw error;
    await authModule.signInWithRedirect(state.firebase.auth, provider);
  }
}

function logout() {
  localStorage.removeItem("trust_session");
  state.token = "";
  state.account = null;
  state.firebase.modules?.authModule?.signOut(state.firebase.auth).catch(() => {});
  renderRoute();
}

function isAdminRoute() {
  return window.location.pathname.replace(/\/+$/, "") === "/admin";
}

function renderRoute() {
  const adminRoute = isAdminRoute();
  const loggedIn = Boolean(state.token && state.account);

  el.authButton.textContent = loggedIn ? t("logout") : t("login");
  el.authButton.onclick = loggedIn ? logout : () => signIn("google").catch(showAuthError);

  el.landing.classList.toggle("hidden", loggedIn);
  el.appShell.classList.toggle("hidden", !loggedIn || adminRoute);
  el.extensionShell.classList.add("hidden");

  if (!loggedIn) {
    el.authNote.textContent = firebaseConfigured() ? t("signin_required") : t("signin_unconfigured");
    el.googleLogin.disabled = !firebaseConfigured();
    el.appleLogin.disabled = !firebaseConfigured();
    return;
  }

  renderAccount();
  if (adminRoute) {
    el.landing.classList.add("hidden");
    el.appShell.classList.add("hidden");
    el.extensionShell.classList.remove("hidden");
    if (window.TrustAdmin?.render) {
      window.TrustAdmin.render({
        root: el.extensionShell,
        api,
        state,
        helpers: { $, escapeHtml, money, t, applyTranslations },
      });
    } else {
      el.extensionShell.innerHTML = `<div class="empty">${escapeHtml(t("admin_unavailable"))}</div>`;
    }
  }
}

function renderAccount() {
  const user = state.account?.user || {};
  el.accountEmail.textContent = user.email || user.display_name || t("account");
  el.userBalance.textContent = money(user.balance?.available_usd || 0);
  const status = state.account?.service_status || t("available");
  if (el.status) el.status.textContent = status === "Available" ? t("available") : status;
  const payments = state.account?.payments_config || state.config?.payments || {};
  if (payments.contra_topup_url) {
    el.contraLink.href = payments.contra_topup_url;
    el.contraLink.classList.remove("hidden");
  } else {
    el.contraLink.classList.add("hidden");
  }
  renderUsage();
}

function renderUsage() {
  const usage = state.account?.usage || [];
  if (!usage.length) {
    el.usageList.innerHTML = `<div class="empty">${escapeHtml(t("no_usage"))}</div>`;
    return;
  }
  el.usageList.innerHTML = usage
    .slice(0, 10)
    .map((item) => {
      const status = item.metadata?.status || item.action;
      return `
        <div class="compact-item">
          <strong>${escapeHtml(item.model_id || item.action)}</strong>
          <span>${money(item.user_charge_usd)} · ${escapeHtml(status)} · ${escapeHtml(item.created_at || "")}</span>
        </div>
      `;
    })
    .join("");
}

function showAuthError(error) {
  el.authNote.textContent = error.message || "Sign-in failed.";
}

async function loadConfig() {
  state.config = await api("/web/config");
  if (firebaseConfigured()) {
    el.authNote.textContent = t("signin_continue");
    initFirebase().catch(showAuthError);
  } else {
    el.authNote.textContent = t("signin_unconfigured");
  }
}

async function refreshAccount() {
  if (!state.token) return false;
  try {
    state.account = await api("/web/me");
    return true;
  } catch {
    localStorage.removeItem("trust_session");
    state.token = "";
    state.account = null;
    return false;
  }
}

async function afterLogin() {
  await Promise.allSettled([refreshAccount(), loadHealth(), loadModels(), loadInstallableModels()]);
  renderRoute();
}

async function loadHealth() {
  const health = await api("/health");
  if (el.status) {
    el.status.textContent = health.serving_enabled ? t("available") : t("unavailable");
  }
}

function modelQuery() {
  const params = new URLSearchParams();
  const provider = el.provider.value;
  if (provider === "standard") params.set("standard", "true");
  else if (provider) params.set("provider_prefix", provider);
  if (el.input.value) params.set("input_modality", el.input.value);
  if (el.output.value) params.set("output_modality", el.output.value);
  if (el.search.value.trim()) params.set("search", el.search.value.trim());
  return params.toString();
}

function renderModels() {
  const models = [...state.models].sort((a, b) => String(a.id).localeCompare(String(b.id)));
  el.modelCount.textContent = `${models.length}`;
  if (!models.length) {
    el.modelList.innerHTML = `<div class="empty">${escapeHtml(t("no_matching_models"))}</div>`;
    return;
  }

  el.modelList.innerHTML = "";
  for (const model of models) {
    const row = document.createElement("article");
    row.className = "model-row";
    row.innerHTML = `
      <div>
        <div class="model-id">${escapeHtml(model.id)}</div>
        <div class="model-desc">${escapeHtml(model.description || model.name || "")}</div>
      </div>
      <div class="chips">
        ${[...model.input_modalities.map((value) => `in:${value}`), ...model.output_modalities.map((value) => `out:${value}`)]
          .map((value) => `<span class="chip">${escapeHtml(value)}</span>`)
          .join("")}
      </div>
      <div class="metric"><strong>${compactNumber(model.context_length)}</strong> ${escapeHtml(t("context"))}</div>
      <div class="price">
        <div><strong>${money(model.user_pricing.prompt_per_1m_tokens)}</strong> ${escapeHtml(t("price_in"))}</div>
        <div><strong>${money(model.user_pricing.completion_per_1m_tokens)}</strong> ${escapeHtml(t("price_out"))}</div>
      </div>
      <button type="button">${escapeHtml(t("select"))}</button>
    `;
    row.querySelector("button").addEventListener("click", () => selectModel(model.id));
    el.modelList.appendChild(row);
  }
}

async function loadModels() {
  if (!state.token) return;
  el.modelList.innerHTML = `<div class="empty">${escapeHtml(t("loading_models"))}</div>`;
  const query = modelQuery();
  const payload = await api(`/models${query ? `?${query}` : ""}`);
  state.models = payload.data || [];
  renderModels();
}

function selectModel(modelId) {
  state.selectedModel = modelId;
  el.quoteModel.value = modelId;
  el.quoteResult.textContent = t("selected");
}

function syncTokenEstimate() {
  const estimated = estimateTextTokens(el.promptText.value);
  if (estimated) el.promptTokens.value = String(estimated);
}

async function quoteRequest() {
  if (!state.selectedModel) {
    el.quoteResult.textContent = t("select_model");
    return null;
  }
  el.quoteButton.disabled = true;
  try {
    const params = new URLSearchParams({
      model_id: state.selectedModel,
      prompt_tokens: String(Number(el.promptTokens.value || 0)),
      completion_tokens: String(Number(el.completionTokens.value || 0)),
    });
    const quote = await api(`/pricing/chat-quote?${params.toString()}`);
    el.quoteResult.textContent = [
      `${t("estimated_charge")}: ${money(quote.estimated_user_charge_usd)}`,
      `${t("input")}: ${money(quote.user_price.prompt_per_1m_tokens)} / 1M`,
      `${t("output")}: ${money(quote.user_price.completion_per_1m_tokens)} / 1M`,
      quote.can_perform ? t("available_now") : quote.block_reason,
    ].join("\n");
    return quote;
  } catch (error) {
    el.quoteResult.textContent = error.message;
    return null;
  } finally {
    el.quoteButton.disabled = false;
  }
}

async function runEncryptedInference() {
  const prompt = el.promptText.value.trim();
  if (!state.selectedModel) {
    el.inferenceResult.textContent = t("run_model_required");
    return;
  }
  if (!prompt) {
    el.inferenceResult.textContent = t("run_prompt_required");
    return;
  }

  syncTokenEstimate();
  el.runButton.disabled = true;
  el.proofResult.textContent = t("fetching_attestation");
  el.inferenceResult.textContent = t("encrypting");

  try {
    const attestation = await api("/e2ee/attestation", {
      method: "POST",
      body: {
        model_id: state.selectedModel,
        signing_algo: "ecdsa",
      },
    });
    const canonicalModel = attestation.canonical_model_id || state.selectedModel;
    const clientCheck = verifyAttestationForClient({
      attestation: attestation.attestation,
      nonce: attestation.attestation_nonce,
      modelPublicKey: attestation.model_public_key,
    });
    if (!clientCheck.ok) {
      throw new Error("Attestation nonce or model encryption key check failed.");
    }

    const encrypted = await createEncryptedChatRequest({
      prompt,
      modelId: canonicalModel,
      modelPublicKey: attestation.model_public_key,
      maxCompletionTokens: Number(el.completionTokens.value || 512),
    });

    el.proofResult.textContent = [
      t("attestation_ok"),
      `nonce: ${attestation.attestation_nonce.slice(0, 16)}...`,
      `model key: ${attestation.model_public_key.slice(0, 18)}...`,
    ].join("\n");
    el.inferenceResult.textContent = t("sending_ciphertext");

    const response = await api("/e2ee/chat/completions", {
      method: "POST",
      body: {
        model_id: state.selectedModel,
        canonical_model_id: canonicalModel,
        estimated_prompt_tokens: Number(el.promptTokens.value || 0),
        estimated_completion_tokens: Number(el.completionTokens.value || 0),
        attestation_nonce: attestation.attestation_nonce,
        client_attestation: clientCheck,
        e2ee_headers: encrypted.headers,
        encrypted_request: encrypted.body,
      },
    });

    el.inferenceResult.textContent = t("decrypting_response");
    const decrypted = await decryptChatResponse({
      response: response.upstream_response,
      clientPrivateKey: encrypted.clientPrivateKey,
      nonce: encrypted.nonce,
      timestamp: encrypted.timestamp,
    });

    const answer = decrypted.map((choice) => choice.content || choice.reasoning_content).filter(Boolean).join("\n\n");
    el.inferenceResult.textContent = answer || "(empty response)";
    el.proofResult.textContent = [
      t("attestation_ok"),
      `${t("e2ee_applied")}: ${String(response.e2ee?.applied || false)}`,
      `${t("response_signature")}: ${response.signature ? t("present") : t("missing")}`,
      `request id: ${response.upstream_response?.id || "n/a"}`,
    ].join("\n");

    await refreshAccount();
    renderAccount();
  } catch (error) {
    el.inferenceResult.textContent = error.message;
  } finally {
    el.runButton.disabled = false;
  }
}

async function quoteTopup() {
  el.topupButton.disabled = true;
  try {
    const params = new URLSearchParams({ amount_usd: String(Number(el.topupAmount.value || 0)) });
    const quote = await api(`/billing/topup-quote?${params.toString()}`);
    el.topupResult.textContent = [
      `${t("credit_shown")}: ${money(quote.user_visible_balance_credit_usd)}`,
      quote.can_accept ? t("acceptable_amount") : quote.block_reason,
    ].join("\n");
  } catch (error) {
    el.topupResult.textContent = error.message;
  } finally {
    el.topupButton.disabled = false;
  }
}

async function loadInstallableModels() {
  if (!state.token) return;
  try {
    const payload = await api("/installable-models");
    el.installableList.innerHTML = (payload.data || [])
      .map(
        (item) => `
        <div class="compact-item">
          <strong>${escapeHtml(item.source)}</strong>
          <span>${escapeHtml(item.kind)} · ${escapeHtml(item.status)}</span>
        </div>
      `,
      )
      .join("");
  } catch (error) {
    el.installableList.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

for (const control of [el.search, el.provider, el.input, el.output]) {
  control.addEventListener("input", () => loadModels().catch(console.error));
}

el.quoteButton.addEventListener("click", quoteRequest);
el.runButton.addEventListener("click", runEncryptedInference);
el.topupButton.addEventListener("click", quoteTopup);
el.promptText.addEventListener("input", syncTokenEstimate);
el.googleLogin.addEventListener("click", () => signIn("google").catch(showAuthError));
el.appleLogin.addEventListener("click", () => signIn("apple").catch(showAuthError));
window.addEventListener("popstate", renderRoute);
document.addEventListener("click", (event) => {
  const languageButton = event.target.closest(".global-language-button");
  if (languageButton) setLanguage(languageButton.dataset.lang || "en");
});

window.TrustApp = {
  api,
  state,
  helpers: { $, $$, escapeHtml, money, t, applyTranslations },
};

(async function main() {
  applyTranslations();
  await loadConfig().catch(showAuthError);
  if (state.token) {
    const valid = await refreshAccount();
    if (valid) await afterLogin();
  }
  renderRoute();
})();
