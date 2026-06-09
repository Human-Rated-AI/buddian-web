import { getPublicKey, getSharedSecret, utils } from "@noble/secp256k1";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const HKDF_INFO = encoder.encode("ecdsa_encryption");

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const clean = cleanHex(hex);
  if (clean.length % 2 !== 0) throw new Error("Invalid hex length");
  const out = new Uint8Array(clean.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

export function cleanHex(value) {
  return String(value || "")
    .trim()
    .replace(/^0x/i, "")
    .toLowerCase();
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function randomPrivateKey() {
  if (typeof utils.randomPrivateKey === "function") return utils.randomPrivateKey();
  if (typeof utils.randomSecretKey === "function") return utils.randomSecretKey();
  return randomBytes(32);
}

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function secpPublicKeyBytes(value) {
  const bytes = typeof value === "string" ? hexToBytes(value) : value;
  if (bytes.length === 64) return concatBytes(new Uint8Array([0x04]), bytes);
  return bytes;
}

function sharedSecretX(privateKey, publicKey) {
  const shared = getSharedSecret(privateKey, secpPublicKeyBytes(publicKey), false);
  if (shared.length === 65) return shared.slice(1, 33);
  if (shared.length === 33) return shared.slice(1, 33);
  if (shared.length === 32) return shared;
  throw new Error(`Unexpected shared secret length: ${shared.length}`);
}

async function deriveAesKey(sharedSecret) {
  const material = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      info: HKDF_INFO,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptForModel(plaintext, modelPublicKeyHex, aad) {
  const modelPublicKey = secpPublicKeyBytes(modelPublicKeyHex);
  const ephemeralPrivateKey = randomPrivateKey();
  const ephemeralPublicKey = getPublicKey(ephemeralPrivateKey, false);
  const shared = sharedSecretX(ephemeralPrivateKey, modelPublicKey);
  const key = await deriveAesKey(shared);
  const nonce = randomBytes(12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: aad ? encoder.encode(aad) : undefined,
      },
      key,
      encoder.encode(plaintext),
    ),
  );
  return bytesToHex(concatBytes(ephemeralPublicKey, nonce, ciphertext));
}

async function decryptFromModel(ciphertextHex, clientPrivateKey, aad) {
  const blob = hexToBytes(ciphertextHex);
  if (blob.length <= 77) throw new Error("Encrypted response is too short");
  const ephemeralPublicKey = blob.slice(0, 65);
  const nonce = blob.slice(65, 77);
  const ciphertext = blob.slice(77);
  const shared = sharedSecretX(clientPrivateKey, ephemeralPublicKey);
  const key = await deriveAesKey(shared);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: aad ? encoder.encode(aad) : undefined,
    },
    key,
    ciphertext,
  );
  return decoder.decode(plaintext);
}

export function clientPublicKeyHex64(clientPrivateKey) {
  return bytesToHex(getPublicKey(clientPrivateKey, false).slice(1));
}

export function isLikelyCiphertextHex(value) {
  const clean = cleanHex(value);
  return clean.length > 154 && clean.length % 2 === 0 && /^[0-9a-f]+$/.test(clean);
}

export function estimateTextTokens(text) {
  const normalized = String(text || "").trim();
  if (!normalized) return 0;
  return Math.max(1, Math.ceil([...normalized].length / 4));
}

export async function createEncryptedChatRequest({
  prompt,
  modelId,
  modelPublicKey,
  maxCompletionTokens,
  temperature = 0.7,
}) {
  const clientPrivateKey = randomPrivateKey();
  const clientPublicKey = clientPublicKeyHex64(clientPrivateKey);
  const nonce = bytesToHex(randomBytes(16));
  const timestamp = String(Math.floor(Date.now() / 1000));
  const requestAad = `v2|req|algo=ecdsa|model=${modelId}|m=0|c=-|n=${nonce}|ts=${timestamp}`;
  const encryptedPrompt = await encryptForModel(prompt, modelPublicKey, requestAad);

  return {
    clientPrivateKey,
    nonce,
    timestamp,
    modelId,
    headers: {
      "X-Signing-Algo": "ecdsa",
      "X-Client-Pub-Key": clientPublicKey,
      "X-Model-Pub-Key": cleanHex(modelPublicKey),
      "X-E2EE-Version": "2",
      "X-E2EE-Nonce": nonce,
      "X-E2EE-Timestamp": timestamp,
    },
    body: {
      model: modelId,
      messages: [{ role: "user", content: encryptedPrompt }],
      stream: false,
      max_tokens: Number(maxCompletionTokens || 512),
      temperature: Number(temperature),
    },
  };
}

export async function decryptChatResponse({ response, clientPrivateKey, nonce, timestamp }) {
  const choices = Array.isArray(response?.choices) ? response.choices : [];
  const decryptedChoices = [];
  for (let index = 0; index < choices.length; index += 1) {
    const choice = choices[index] || {};
    const message = choice.message || {};
    const decrypted = { index, content: "", reasoning_content: "" };
    for (const field of ["content", "reasoning_content"]) {
      if (!message[field]) continue;
      if (!isLikelyCiphertextHex(message[field])) {
        throw new Error(`Response field ${field} is not encrypted ciphertext`);
      }
      const aad = `v2|resp|algo=ecdsa|model=${response.model || ""}|id=${response.id || ""}|choice=${index}|field=${field}|n=${nonce}|ts=${timestamp}`;
      decrypted[field] = await decryptFromModel(message[field], clientPrivateKey, aad);
    }
    decryptedChoices.push(decrypted);
  }
  return decryptedChoices;
}

export function findModelPublicKey(attestation) {
  const keyFields = new Set(["signing_public_key", "e2e_pubkey", "e2ee_public_key", "encryption_public_key"]);
  function walk(value) {
    if (Array.isArray(value)) {
      for (const item of value) {
        const found = walk(item);
        if (found) return found;
      }
      return "";
    }
    if (!value || typeof value !== "object") return "";
    for (const [key, nested] of Object.entries(value)) {
      if (keyFields.has(key) && typeof nested === "string" && nested.trim()) return cleanHex(nested);
    }
    for (const nested of Object.values(value)) {
      const found = walk(nested);
      if (found) return found;
    }
    return "";
  }
  return walk(attestation);
}

export function attestationNonceMatches(attestation, nonce) {
  const expected = cleanHex(nonce);
  function walk(value) {
    if (Array.isArray(value)) return value.some(walk);
    if (!value || typeof value !== "object") return false;
    for (const [key, nested] of Object.entries(value)) {
      if (["request_nonce", "nonce"].includes(key) && cleanHex(nested) === expected) return true;
      if (walk(nested)) return true;
    }
    return false;
  }
  return walk(attestation);
}

export function verifyAttestationForClient({ attestation, nonce, modelPublicKey }) {
  const attestedKey = findModelPublicKey(attestation);
  const expectedKey = cleanHex(modelPublicKey);
  const nonceMatches = attestationNonceMatches(attestation, nonce);
  return {
    ok: Boolean(attestedKey && expectedKey && attestedKey === expectedKey && nonceMatches),
    nonce_matches: nonceMatches,
    model_key_matches: Boolean(attestedKey && expectedKey && attestedKey === expectedKey),
    attested_model_public_key: attestedKey,
  };
}
