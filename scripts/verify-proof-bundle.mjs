#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const HEX_RE = /^[0-9a-f]+$/i;
const FORBIDDEN_PLAINTEXT_KEYS = new Set([
  "plaintext",
  "plaintext_prompt",
  "plaintext_answer",
  "prompt",
  "answer",
  "decrypted",
  "decrypted_response",
]);

function sha256Hex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function cleanHex(value) {
  return String(value || "").trim().replace(/^0x/i, "").toLowerCase();
}

function isEncryptedHex(value) {
  const hex = cleanHex(value);
  return hex.length >= 154 && hex.length % 2 === 0 && HEX_RE.test(hex);
}

function walk(value, path = "$", visitor = () => {}) {
  visitor(value, path);
  if (Array.isArray(value)) {
    value.forEach((item, index) => walk(item, `${path}[${index}]`, visitor));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      walk(nested, `${path}.${key}`, visitor);
    }
  }
}

function nestedHasValue(value, expected) {
  if (!expected) return false;
  if (typeof value === "string" && cleanHex(value) === cleanHex(expected)) return true;
  if (Array.isArray(value)) return value.some((item) => nestedHasValue(item, expected));
  if (value && typeof value === "object") {
    return Object.values(value).some((nested) => nestedHasValue(nested, expected));
  }
  return false;
}

function nestedHasNonce(value, nonce) {
  const expected = cleanHex(nonce);
  if (!expected) return false;
  if (Array.isArray(value)) return value.some((item) => nestedHasNonce(item, nonce));
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      if ((key === "request_nonce" || key === "nonce") && cleanHex(String(nested)) === expected) return true;
      if (nestedHasNonce(nested, nonce)) return true;
    }
  }
  return false;
}

function collectPlaintextKeyFindings(bundle) {
  const findings = [];
  walk(bundle, "$", (value, path) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return;
    for (const key of Object.keys(value)) {
      if (FORBIDDEN_PLAINTEXT_KEYS.has(key.toLowerCase())) {
        findings.push(`${path}.${key}`);
      }
    }
  });
  return findings;
}

function checkEncryptedRequest(bundle, failures) {
  const request = bundle.encrypted_request;
  if (!request || typeof request !== "object") {
    failures.push("missing encrypted_request object");
    return;
  }
  const messages = request.messages;
  if (!Array.isArray(messages) || messages.length === 0) {
    failures.push("encrypted_request.messages is missing or empty");
    return;
  }
  messages.forEach((message, index) => {
    if (!message || typeof message !== "object") {
      failures.push(`encrypted_request.messages[${index}] is not an object`);
      return;
    }
    if (!isEncryptedHex(message.content)) {
      failures.push(`encrypted_request.messages[${index}].content is not encrypted hex`);
    }
  });

  const expectedHash = bundle.proof?.request_sha256;
  if (!expectedHash) {
    failures.push("proof.request_sha256 is missing");
    return;
  }
  const actualHash = sha256Hex(JSON.stringify(request));
  if (actualHash !== expectedHash) {
    failures.push(`encrypted_request hash mismatch: expected ${expectedHash}, got ${actualHash}`);
  }
}

function checkEncryptedResponse(bundle, failures, warnings) {
  const response = bundle.encrypted_response;
  if (!response || typeof response !== "object") {
    failures.push("missing encrypted_response object");
    return;
  }
  const choices = response.choices;
  if (!Array.isArray(choices) || choices.length === 0) {
    warnings.push("encrypted_response.choices is missing or empty");
    return;
  }
  let encryptedFields = 0;
  choices.forEach((choice, index) => {
    const message = choice?.message;
    if (!message || typeof message !== "object") {
      warnings.push(`encrypted_response.choices[${index}].message is missing`);
      return;
    }
    for (const field of ["content", "reasoning_content", "reasoning"]) {
      if (message[field] === undefined || message[field] === null || message[field] === "") continue;
      if (isEncryptedHex(message[field])) {
        encryptedFields += 1;
      } else {
        failures.push(`encrypted_response.choices[${index}].message.${field} is not encrypted hex`);
      }
    }
  });
  if (encryptedFields === 0) {
    failures.push("encrypted_response does not contain encrypted message content");
  }
  if (!bundle.proof?.response_sha256) {
    warnings.push("proof.response_sha256 is missing");
  } else if (bundle.encrypted_response_text) {
    const responseHash = sha256Hex(bundle.encrypted_response_text);
    if (responseHash !== bundle.proof.response_sha256) {
      failures.push(`encrypted_response_text hash mismatch: expected ${bundle.proof.response_sha256}, got ${responseHash}`);
    }
    try {
      JSON.parse(bundle.encrypted_response_text);
    } catch {
      failures.push("encrypted_response_text is not valid JSON");
    }
  } else {
    warnings.push("response_sha256 is server-computed over exact upstream bytes; encrypted_response_text is missing");
  }
}

export function verifyProofBundle(bundle) {
  const failures = [];
  const warnings = [];

  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    return { ok: false, failures: ["bundle is not a JSON object"], warnings };
  }
  if (bundle.schema !== "trust-ai.e2ee-proof-bundle.v1") {
    failures.push(`unexpected schema: ${bundle.schema || "missing"}`);
  }
  if (!bundle.model_id) failures.push("model_id is missing");
  if (!bundle.attestation?.nonce) failures.push("attestation.nonce is missing");
  if (!bundle.attestation?.model_public_key) failures.push("attestation.model_public_key is missing");
  if (!bundle.attestation?.report) {
    warnings.push("attestation.report is missing");
  } else {
    if (!nestedHasNonce(bundle.attestation.report, bundle.attestation.nonce)) {
      failures.push("attestation.report does not contain the expected nonce");
    }
    if (!nestedHasValue(bundle.attestation.report, bundle.attestation.model_public_key)) {
      failures.push("attestation.report does not contain the expected model public key");
    }
  }
  if (!bundle.client_attestation?.ok) failures.push("client_attestation.ok is not true");
  if (!bundle.e2ee_request_headers?.["X-Client-Pub-Key"]) failures.push("X-Client-Pub-Key is missing");
  if (!bundle.e2ee_request_headers?.["X-Model-Pub-Key"]) failures.push("X-Model-Pub-Key is missing");
  if (!bundle.e2ee_response_headers || typeof bundle.e2ee_response_headers !== "object") {
    warnings.push("e2ee_response_headers is missing");
  }
  if (!bundle.signature) warnings.push("response signature is missing");

  checkEncryptedRequest(bundle, failures);
  checkEncryptedResponse(bundle, failures, warnings);

  const plaintextKeyFindings = collectPlaintextKeyFindings(bundle);
  if (plaintextKeyFindings.length) {
    failures.push(`bundle contains plaintext-shaped keys: ${plaintextKeyFindings.join(", ")}`);
  }

  const verification = bundle.proof?.verification || {};
  if (verification.verified !== true) {
    failures.push(`proof.verification.verified is not true (status: ${verification.status || "missing"})`);
  }
  for (const required of [
    "signature_present",
    "signature_text_parse",
    "request_hash_matches",
    "response_hash_matches",
    "signature_recovers_signer",
    "signer_attestation_fetched",
    "attestation_signing_address_matches",
    "attestation_nonce_matches",
  ]) {
    const check = verification.checks?.[required];
    if (!check || check.ok !== true) {
      failures.push(`proof verification check failed or missing: ${required}`);
    }
  }
  for (const optional of [
    "tdx_quote_verified",
    "tdx_report_data_binds_signer",
    "tdx_report_data_binds_nonce",
    "gpu_attestation_verified",
  ]) {
    const check = verification.checks?.[optional];
    if (!check) warnings.push(`proof verification check is missing: ${optional}`);
    else if (check.ok !== true) warnings.push(`proof verification check is not fully passing: ${optional}`);
  }

  return { ok: failures.length === 0, failures, warnings };
}

async function main() {
  const file = process.argv[2];
  if (!file || file === "-h" || file === "--help") {
    console.log("Usage: node scripts/verify-proof-bundle.mjs path/to/trust-ai-proof.json");
    process.exit(file ? 0 : 2);
  }
  const bundle = JSON.parse(await readFile(file, "utf8"));
  const result = verifyProofBundle(bundle);
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.ok ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
