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
const AUTH_LOG_KEY = "trust_auth_trace";
const ADMIN_BUNDLE_VERSION = "20260611-admin-cache";

const state = {
  config: null,
  token: localStorage.getItem("trust_session") || "",
  account: null,
  models: [],
  selectedModel: "",
  currentCryptoPayment: null,
  language: normalizeLanguage(localStorage.getItem("trust_language") || browserLanguage()),
  firebase: {
    modules: null,
    app: null,
    auth: null,
    analytics: null,
    initPromise: null,
    sessionPromise: null,
  },
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const el = {
  landing: $("#landing"),
  appShell: $("#app-shell"),
  extensionShell: $("#extension-shell"),
  authButton: $("#auth-button"),
  authAvatar: $("#auth-avatar"),
  authName: $("#auth-name"),
  authMenu: $("#auth-menu"),
  logoutButton: $("#logout-button"),
  authNote: $("#auth-note"),
  googleLogin: $("#google-login"),
  appleLogin: $("#apple-login"),
  status: $("#service-status"),
  accountEmail: $("#account-email"),
  userBalance: $("#user-balance"),
  balanceCard: $("#balance-card"),
  balancePaymentPanel: $("#balance-payment-panel"),
  balanceTopupAmount: $("#balance-topup-amount"),
  paymentMinimum: $("#payment-minimum"),
  balancePaypalLinks: $("#balance-paypal-links"),
  balanceZellePayment: $("#balance-zelle-payment"),
  balanceZelleToggle: $("#balance-zelle-toggle"),
  balanceZelleDetails: $("#balance-zelle-details"),
  balanceZelleQr: $("#balance-zelle-qr"),
  balanceZelleRecipient: $("#balance-zelle-recipient"),
  balanceCryptoCreate: $("#balance-crypto-create"),
  balanceCryptoCheckout: $("#balance-crypto-checkout"),
  balanceCryptoCopy: $("#balance-crypto-copy"),
  balanceCryptoCheck: $("#balance-crypto-check"),
  balanceCryptoWallet: $("#balance-crypto-wallet"),
  balanceCryptoResult: $("#balance-crypto-result"),
  balanceTransactionsLink: $("#balance-transactions-link"),
  balanceTransactionList: $("#balance-transaction-list"),
  balancePaymentEmpty: $("#balance-payment-empty"),
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
  installableList: $("#installable-list"),
  usageList: $("#usage-list"),
  transactionsSection: $("#transactions-section"),
  transactionList: $("#transaction-list"),
};

function t(key) {
  return I18N[state.language]?.[key] || I18N.en[key] || key;
}

function setLanguage(value) {
  state.language = normalizeLanguage(value);
  localStorage.setItem("trust_language", state.language);
  applyTranslations();
  renderRoute();
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

function wholeMoney(value) {
  return new Intl.NumberFormat(state.language === "en" ? "en-US" : state.language, {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(Number(value || 0));
}

function compactNumber(value) {
  if (value === null || value === undefined) return "n/a";
  return new Intl.NumberFormat(state.language === "en" ? "en-US" : state.language, {
    notation: "compact",
  }).format(Number(value));
}

function formatDateTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(state.language === "en" ? "en-US" : state.language, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function authTrace(context, details = {}, level = "info") {
  const entry = {
    at: new Date().toISOString(),
    context,
    details,
    href: window.location.href,
  };
  try {
    const existing = JSON.parse(localStorage.getItem(AUTH_LOG_KEY) || "[]");
    const list = Array.isArray(existing) ? existing : [];
    list.push(entry);
    localStorage.setItem(AUTH_LOG_KEY, JSON.stringify(list.slice(-40)));
  } catch {
    // Ignore storage errors; console output below is still useful.
  }
  const method = level === "error" ? "error" : level === "warn" ? "warn" : "info";
  console[method](`[Trust auth] ${context}`, entry);
}

function replayAuthTrace() {
  let entries = [];
  try {
    const raw = JSON.parse(localStorage.getItem(AUTH_LOG_KEY) || "[]");
    entries = Array.isArray(raw) ? raw : [];
  } catch {
    entries = [];
  }
  if (!entries.length) return;
  console.groupCollapsed(`[Trust auth] previous auth trace (${entries.length})`);
  entries.forEach((entry) => console.info(`[Trust auth] ${entry.context}`, entry));
  console.groupEnd();
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
    const error = new Error(body.detail?.message || body.detail || response.statusText);
    error.status = response.status;
    error.path = path;
    error.body = body;
    throw error;
  }
  return body;
}

function logAuthError(context, error, extra = {}) {
  authTrace(context, {
    message: error?.message || String(error),
    code: error?.code,
    name: error?.name,
    status: error?.status,
    path: error?.path,
    body: error?.body,
    stack: error?.stack,
    ...extra,
  }, "error");
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
  authTrace("Firebase init requested", {
    configured: firebaseConfigured(),
    authReady: Boolean(state.firebase.auth),
    initInProgress: Boolean(state.firebase.initPromise),
  });
  if (!firebaseConfigured()) return false;
  if (state.firebase.auth) return true;
  if (state.firebase.initPromise) return state.firebase.initPromise;

  state.firebase.initPromise = (async () => {
    authTrace("Loading Firebase SDK modules");
    const [appModule, authModule, analyticsModule] = await Promise.all([
      import("https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js"),
      import("https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js"),
      import("https://www.gstatic.com/firebasejs/10.14.1/firebase-analytics.js"),
    ]);
    state.firebase.modules = { appModule, authModule, analyticsModule };
    state.firebase.app = appModule.initializeApp(firebaseConfig());
    state.firebase.auth = authModule.getAuth(state.firebase.app);
    state.firebase.auth.languageCode = state.language;
    authModule.onAuthStateChanged(state.firebase.auth, (user) => {
      state.firebase.user = user || null;
      authTrace("Firebase auth state changed", {
        hasUser: Boolean(user),
        firebaseUid: user?.uid || "",
        email: user?.email || "",
        providerData: (user?.providerData || []).map((item) => item.providerId),
      });
      if (user && !state.token && !state.account) {
        completeFirebaseAuthOnce(user, "Backend session exchange failed from Firebase auth state").catch(() => {});
      }
    });
    authTrace("Checking Firebase redirect result", {
      pendingProvider: localStorage.getItem("trust_firebase_auth_provider") || "",
    });
    const redirectResult = await authModule.getRedirectResult(state.firebase.auth).catch((error) => {
      logAuthError("Firebase redirect result failed", error, {
        provider: localStorage.getItem("trust_firebase_auth_provider") || "",
      });
      showAuthError(error);
      return null;
    });
    if (redirectResult?.user) {
      localStorage.removeItem("trust_firebase_auth_provider");
      await completeFirebaseAuthOnce(redirectResult.user, "Backend session exchange failed after redirect", {
        providerId: redirectResult.providerId || "",
      });
    }
    if (!redirectResult?.user && localStorage.getItem("trust_firebase_auth_provider")) {
      authTrace("No Firebase redirect result found after return", {
        pendingProvider: localStorage.getItem("trust_firebase_auth_provider") || "",
        hasCurrentUser: Boolean(state.firebase.auth.currentUser),
        currentUid: state.firebase.auth.currentUser?.uid || "",
        currentEmail: state.firebase.auth.currentUser?.email || "",
      }, "warn");
      if (!state.firebase.auth.currentUser) localStorage.removeItem("trust_firebase_auth_provider");
    }
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
  authTrace("Starting backend session exchange", {
    firebaseUid: firebaseUser?.uid || "",
    email: firebaseUser?.email || "",
    providerData: (firebaseUser?.providerData || []).map((item) => item.providerId),
  });
  let idToken = "";
  try {
    idToken = await firebaseUser.getIdToken(true);
  } catch (error) {
    logAuthError("Firebase ID token fetch failed", error, {
      firebaseUid: firebaseUser?.uid || "",
      email: firebaseUser?.email || "",
    });
    throw error;
  }
  let data;
  try {
    data = await api("/web/auth/firebase", {
      method: "POST",
      body: { id_token: idToken },
    });
  } catch (error) {
    logAuthError("Backend session exchange failed", error, {
      firebaseUid: firebaseUser?.uid || "",
      email: firebaseUser?.email || "",
    });
    throw error;
  }
  state.token = data.session_token;
  state.account = data.account;
  localStorage.setItem("trust_session", state.token);
  localStorage.removeItem("trust_firebase_auth_provider");
  authTrace("Backend session exchange succeeded", {
    accountEmail: state.account?.user?.email || "",
    accountName: state.account?.user?.display_name || "",
  });
  await afterLogin();
}

async function completeFirebaseAuthOnce(firebaseUser, context, extra = {}) {
  if (state.firebase.sessionPromise) return state.firebase.sessionPromise;
  state.firebase.sessionPromise = completeFirebaseAuth(firebaseUser)
    .catch((error) => {
      logAuthError(context, error, {
        firebaseUid: firebaseUser?.uid || "",
        email: firebaseUser?.email || "",
        ...extra,
      });
      showAuthError(error);
      throw error;
    })
    .finally(() => {
      state.firebase.sessionPromise = null;
    });
  return state.firebase.sessionPromise;
}

async function signIn(providerName) {
  closeAuthMenu();
  el.authNote.textContent = t("signin_opening");
  authTrace("Provider selected", { provider: providerName });
  let authModule;
  let provider;
  try {
    const ready = await initFirebase();
    if (!ready) throw new Error(t("signin_unconfigured"));
    authModule = state.firebase.modules.authModule;
    provider = firebaseProvider(providerName);
  } catch (error) {
    logAuthError("Provider sign-in launch failed", error, { provider: providerName });
    throw error;
  }

  localStorage.setItem("trust_firebase_auth_provider", providerName);
  authTrace("Opening Firebase popup", { provider: providerName });
  let result;
  try {
    result = await authModule.signInWithPopup(state.firebase.auth, provider);
  } catch (popupError) {
    logAuthError("Firebase popup sign-in failed", popupError, { provider: providerName });
    const redirectFallbackCodes = new Set([
      "auth/popup-blocked",
      "auth/cancelled-popup-request",
      "auth/operation-not-supported-in-this-environment",
    ]);
    if (!redirectFallbackCodes.has(popupError?.code)) throw popupError;
    authTrace("Falling back to Firebase redirect", {
      provider: providerName,
      popupCode: popupError?.code || "",
    }, "warn");
    await authModule.signInWithRedirect(state.firebase.auth, provider);
    return;
  }

  authTrace("Firebase popup returned user", {
    provider: providerName,
    providerId: result.providerId || "",
    firebaseUid: result.user?.uid || "",
    email: result.user?.email || "",
  });
  await completeFirebaseAuthOnce(result.user, "Backend session exchange failed after popup", {
    provider: providerName,
    providerId: result.providerId || "",
  });
}

function logout() {
  localStorage.removeItem("trust_session");
  localStorage.removeItem("trust_firebase_auth_provider");
  state.token = "";
  state.account = null;
  state.currentCryptoPayment = null;
  el.balancePaymentPanel.classList.add("hidden");
  el.balanceCard.setAttribute("aria-expanded", "false");
  state.firebase.modules?.authModule?.signOut(state.firebase.auth).catch(() => {});
  renderRoute();
}

function accountDisplayName() {
  const user = state.account?.user || {};
  return String(user.display_name || user.email || t("account")).trim();
}

function accountInitials(name) {
  const parts = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "T";
  const first = parts[0]?.[0] || "";
  const second = parts.length > 1 ? parts[1]?.[0] || "" : "";
  return `${first}${second}`.toUpperCase();
}

function closeAuthMenu() {
  el.authMenu.classList.add("hidden");
  el.authButton.setAttribute("aria-expanded", "false");
}

function toggleAuthMenu() {
  if (state.token && state.account) return;
  if (!firebaseConfigured()) {
    el.authNote.textContent = t("signin_unconfigured");
    console.error("[Trust auth] Firebase sign-in requested but Firebase is not configured");
    return;
  }
  const hidden = el.authMenu.classList.toggle("hidden");
  el.authButton.setAttribute("aria-expanded", hidden ? "false" : "true");
}

function renderAuthHeader(loggedIn) {
  el.logoutButton.classList.toggle("hidden", !loggedIn);
  el.authButton.classList.toggle("logged-in", loggedIn);
  if (loggedIn) closeAuthMenu();
  el.authButton.onclick = loggedIn ? null : toggleAuthMenu;
  el.authButton.setAttribute("aria-label", loggedIn ? t("account") : t("login"));

  if (!loggedIn) {
    el.authName.textContent = t("login");
    el.authAvatar.classList.add("hidden");
    el.authAvatar.textContent = "";
    el.authAvatar.style.backgroundImage = "";
    return;
  }

  const user = state.account?.user || {};
  const name = accountDisplayName();
  el.authName.textContent = name;
  el.authAvatar.classList.remove("hidden");
  if (user.photo_url) {
    el.authAvatar.textContent = "";
    el.authAvatar.style.backgroundImage = `url("${String(user.photo_url).replaceAll('"', "%22")}")`;
  } else {
    el.authAvatar.style.backgroundImage = "";
    el.authAvatar.textContent = accountInitials(name);
  }
}

function isAdminRoute() {
  return window.location.pathname.replace(/\/+$/, "") === "/admin";
}

function renderRoute() {
  const adminRoute = isAdminRoute();
  const loggedIn = Boolean(state.token && state.account);

  renderAuthHeader(loggedIn);

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
        helpers: { $, escapeHtml, money, formatDateTime, t, applyTranslations },
      });
    } else {
      el.extensionShell.innerHTML = `<div class="empty">${escapeHtml(t("checking"))}</div>`;
      import(`/admin.js?v=${ADMIN_BUNDLE_VERSION}`)
        .then(() => {
          if (isAdminRoute()) renderRoute();
        })
        .catch(() => {
          el.extensionShell.innerHTML = `<div class="empty">${escapeHtml(t("admin_unavailable"))}</div>`;
        });
    }
  }
}

function renderAccount() {
  const user = state.account?.user || {};
  el.accountEmail.textContent = user.email || user.display_name || t("account");
  el.userBalance.textContent = money(user.balance?.available_usd || 0);
  renderAuthHeader(true);
  const status = state.account?.service_status || t("available");
  if (el.status) el.status.textContent = status === "Available" ? t("available") : status;
  const payments = state.account?.payments_config || state.config?.payments || {};
  renderPaymentLinks(payments);
  renderUsage();
  renderTransactions();
}

function renderPaymentLinks(payments) {
  const cryptoTopup = payments.crypto_topup || state.config?.payments?.crypto_topup || {};
  const cryptoWallet = String(cryptoTopup.wallet_address || payments.crypto_topup_wallet || "").trim();
  const paypalLinks = Array.isArray(payments.paypal_topup_links) ? payments.paypal_topup_links : [];
  const zelle = payments.zelle_payment || {};
  const rawWalletOnly = !cryptoTopup.enabled && cryptoWallet;
  const minimumTopup = payments.minimum_topup_usd || state.config?.payments?.minimum_topup_usd || "10.00";
  const minimumText = t("minimum_payment").replace("{amount}", wholeMoney(minimumTopup));
  if (el.paymentMinimum) el.paymentMinimum.textContent = minimumText;
  if (el.balanceTopupAmount) el.balanceTopupAmount.value = String(Number(minimumTopup || 10));
  if (el.topupAmount) el.topupAmount.value = String(Number(minimumTopup || 10));

  if (paypalLinks.length) {
    el.balancePaypalLinks.innerHTML = paypalLinks.map((link) => `
      <a class="pay-link" href="${escapeHtml(link.url)}" target="_blank" rel="noopener">
        ${escapeHtml(t("pay_paypal_amount").replace("{amount}", money(link.amount_usd)))}
      </a>
    `).join("");
    el.balancePaypalLinks.classList.remove("hidden");
  } else {
    el.balancePaypalLinks.innerHTML = "";
    el.balancePaypalLinks.classList.add("hidden");
  }

  if (zelle.enabled && zelle.qr_url) {
    el.balanceZelleQr.src = zelle.qr_url;
    el.balanceZelleRecipient.textContent = zelle.label || "Zelle";
    el.balanceZellePayment.classList.remove("hidden");
  } else {
    el.balanceZelleQr.removeAttribute("src");
    el.balanceZelleRecipient.textContent = "";
    el.balanceZelleDetails.classList.add("hidden");
    el.balanceZellePayment.classList.add("hidden");
  }

  el.balanceCryptoCreate.classList.toggle("hidden", !cryptoTopup.enabled);
  if (rawWalletOnly && !state.currentCryptoPayment) {
    el.balanceCryptoWallet.textContent = cryptoWallet;
    el.balanceCryptoWallet.classList.remove("hidden");
    el.balanceCryptoCopy.classList.remove("hidden");
  } else if (!state.currentCryptoPayment) {
    el.balanceCryptoWallet.classList.add("hidden");
    el.balanceCryptoCopy.classList.add("hidden");
    el.balanceCryptoCheckout.classList.add("hidden");
    el.balanceCryptoCheckout.removeAttribute("href");
  }
  el.balancePaymentEmpty.classList.toggle(
    "hidden",
    Boolean(paypalLinks.length || zelle.enabled || cryptoTopup.enabled || rawWalletOnly),
  );
}

function toggleBalancePayments(event) {
  event?.preventDefault();
  event?.stopPropagation();
  const opening = el.balancePaymentPanel.classList.contains("hidden");
  el.balancePaymentPanel.classList.toggle("hidden", !opening);
  el.balanceCard.setAttribute("aria-expanded", opening ? "true" : "false");
  console.info("[Trust UI] Balance panel toggled", { open: opening });
  if (opening) {
    el.balancePaymentPanel.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

function toggleZellePayment(event) {
  event?.preventDefault();
  const opening = el.balanceZelleDetails.classList.contains("hidden");
  el.balanceZelleDetails.classList.toggle("hidden", !opening);
  if (opening) {
    el.balanceZelleDetails.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

async function copyCryptoWallet() {
  const details = el.balanceCryptoWallet.textContent.trim();
  if (!details) return;
  await navigator.clipboard.writeText(details);
  el.balanceCryptoResult.textContent = t("copied");
  el.balanceCryptoResult.classList.remove("hidden");
}

function syncTopupAmount(source) {
  const value = source.value || "10";
  if (el.topupAmount) el.topupAmount.value = value;
  if (el.balanceTopupAmount) el.balanceTopupAmount.value = value;
}

function selectedTopupAmount() {
  return String(Number(
    el.balanceTopupAmount?.value
      || el.topupAmount?.value
      || state.account?.payments_config?.minimum_topup_usd
      || state.config?.payments?.minimum_topup_usd
      || 10,
  ));
}

function renderCryptoPaymentIntent(intent, matched = false) {
  state.currentCryptoPayment = intent;
  if (intent.checkout_url) {
    el.balanceCryptoCheckout.href = intent.checkout_url;
    el.balanceCryptoCheckout.classList.remove("hidden");
    el.balanceCryptoWallet.classList.add("hidden");
    el.balanceCryptoCopy.classList.add("hidden");
    el.balanceCryptoCheck.classList.remove("hidden");
    el.balanceCryptoResult.textContent = matched
      ? `${t("crypto_payment_matched")}: ${money(intent.amount_usd)}`
      : t("crypto_checkout_created");
    el.balanceCryptoResult.classList.remove("hidden");
    return;
  }
  const details = [
    `${t("send_exactly")}: ${intent.display_amount}`,
    `${t("wallet")}: ${intent.wallet_address}`,
    `${t("memo")}: ${intent.memo}`,
    `${t("chain")}: ${intent.chain_id}`,
  ].join("\n");
  el.balanceCryptoWallet.textContent = details;
  el.balanceCryptoWallet.classList.remove("hidden");
  el.balanceCryptoCheckout.classList.add("hidden");
  el.balanceCryptoCheckout.removeAttribute("href");
  el.balanceCryptoCopy.classList.remove("hidden");
  el.balanceCryptoCheck.classList.remove("hidden");
  el.balanceCryptoResult.textContent = matched
    ? `${t("crypto_payment_matched")}: ${money(intent.amount_usd)}`
    : t("crypto_payment_created");
  el.balanceCryptoResult.classList.remove("hidden");
}

async function createCryptoTopup() {
  el.balanceCryptoCreate.disabled = true;
  try {
    const intent = await api("/billing/crypto/topup-intent", {
      method: "POST",
      body: { amount_usd: selectedTopupAmount() },
    });
    renderCryptoPaymentIntent(intent);
  } catch (error) {
    el.balanceCryptoResult.textContent = error.message;
    el.balanceCryptoResult.classList.remove("hidden");
  } finally {
    el.balanceCryptoCreate.disabled = false;
  }
}

async function checkCryptoTopup() {
  if (!state.currentCryptoPayment?.payment_id) return;
  el.balanceCryptoCheck.disabled = true;
  try {
    const result = await api("/billing/crypto/topup-check", {
      method: "POST",
      body: { payment_id: state.currentCryptoPayment.payment_id },
    });
    renderCryptoPaymentIntent(result, result.status === "completed");
    if (result.status === "completed") {
      await refreshAccount();
      renderAccount();
    } else {
      el.balanceCryptoResult.textContent = t("crypto_payment_pending");
      el.balanceCryptoResult.classList.remove("hidden");
    }
  } catch (error) {
    el.balanceCryptoResult.textContent = error.message;
    el.balanceCryptoResult.classList.remove("hidden");
  } finally {
    el.balanceCryptoCheck.disabled = false;
  }
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
          <span>${money(item.user_charge_usd)} · ${escapeHtml(status)} · ${escapeHtml(formatDateTime(item.created_at))}</span>
        </div>
      `;
    })
    .join("");
}

function transactionTitle(item) {
  if (item.kind === "usage") return item.model_id || item.source;
  return item.source === "admin_manual" ? t("admin_credit") : item.source;
}

function renderTransactionList(target) {
  if (!target || target.classList.contains("hidden")) return;
  const transactions = state.account?.transactions || [];
  if (!transactions.length) {
    target.innerHTML = `<div class="empty">${escapeHtml(t("no_transactions"))}</div>`;
    return;
  }
  target.innerHTML = transactions.slice(0, 50).map((item) => {
    const prefix = Number(item.amount_usd) >= 0 ? "+" : "";
    const note = item.external_reference || item.metadata?.memo || item.metadata?.request_id || item.status || "";
    return `
      <div class="compact-item">
        <strong>${prefix}${money(item.amount_usd)} · ${escapeHtml(transactionTitle(item))}</strong>
        <span>${escapeHtml(item.status || "")} · ${escapeHtml(formatDateTime(item.created_at))}${note ? ` · ${escapeHtml(note)}` : ""}</span>
      </div>
    `;
  }).join("");
}

function renderTransactions() {
  renderTransactionList(el.balanceTransactionList);
  renderTransactionList(el.transactionList);
}

function showTransactions() {
  el.balanceTransactionList.classList.remove("hidden");
  renderTransactions();
  el.balanceTransactionList.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function showAuthError(error) {
  logAuthError("Visible auth error", error);
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
      `request sha256: ${response.proof?.request_sha256 || "n/a"}`,
      `response sha256: ${response.proof?.response_sha256 || "n/a"}`,
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
el.topupButton?.addEventListener("click", quoteTopup);
el.balanceCard.addEventListener("click", toggleBalancePayments);
el.balanceZelleToggle.addEventListener("click", toggleZellePayment);
el.balanceTopupAmount?.addEventListener("input", () => syncTopupAmount(el.balanceTopupAmount));
el.topupAmount?.addEventListener("input", () => syncTopupAmount(el.topupAmount));
el.balanceCryptoCreate.addEventListener("click", () => createCryptoTopup().catch((error) => {
  el.balanceCryptoResult.textContent = error.message;
  el.balanceCryptoResult.classList.remove("hidden");
}));
el.balanceCryptoCopy.addEventListener("click", () => copyCryptoWallet().catch((error) => {
  el.balanceCryptoResult.textContent = error.message;
  el.balanceCryptoResult.classList.remove("hidden");
}));
el.balanceCryptoCheck.addEventListener("click", () => checkCryptoTopup().catch((error) => {
  el.balanceCryptoResult.textContent = error.message;
  el.balanceCryptoResult.classList.remove("hidden");
}));
el.balanceTransactionsLink.addEventListener("click", showTransactions);
el.promptText.addEventListener("input", syncTokenEstimate);
el.googleLogin.addEventListener("click", () => signIn("google").catch(showAuthError));
el.appleLogin.addEventListener("click", () => signIn("apple").catch(showAuthError));
el.logoutButton.addEventListener("click", logout);
window.addEventListener("popstate", renderRoute);
document.addEventListener("click", (event) => {
  const balanceButton = event.target.closest("#balance-card");
  if (balanceButton) {
    toggleBalancePayments(event);
    return;
  }
  const languageButton = event.target.closest(".global-language-button");
  if (languageButton) setLanguage(languageButton.dataset.lang || "en");
  if (!event.target.closest("#auth-control")) closeAuthMenu();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeAuthMenu();
});

window.TrustApp = {
  api,
  state,
  helpers: { $, $$, escapeHtml, money, formatDateTime, t, applyTranslations },
};

(async function main() {
  replayAuthTrace();
  authTrace("Trust app loaded", {
    hasSessionToken: Boolean(state.token),
    pendingProvider: localStorage.getItem("trust_firebase_auth_provider") || "",
  });
  applyTranslations();
  await loadConfig().catch(showAuthError);
  if (state.token) {
    const valid = await refreshAccount();
    if (valid) await afterLogin();
  }
  renderRoute();
})();
