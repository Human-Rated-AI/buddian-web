#!/usr/bin/env node
import { Signature } from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
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

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value) {
  const hex = cleanHex(value);
  if (!hex || hex.length % 2 !== 0 || !HEX_RE.test(hex)) throw new Error("Invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
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

function parseSignatureText(text) {
  const parts = String(text || "").split(":");
  if (parts.length !== 2 && parts.length !== 3) {
    throw new Error("Signature text must be request_hash:response_hash or model:request_hash:response_hash");
  }
  const [signedModel, requestHash, responseHash] = parts.length === 3 ? parts : [null, parts[0], parts[1]];
  for (const [label, value] of [["request_hash", requestHash], ["response_hash", responseHash]]) {
    const clean = cleanHex(value);
    if (clean.length !== 64 || !HEX_RE.test(clean)) throw new Error(`Signature ${label} must be a sha256 hex digest`);
  }
  return {
    signed_model: signedModel,
    request_hash: cleanHex(requestHash),
    response_hash: cleanHex(responseHash),
    part_count: parts.length,
  };
}

function orderedJsonHash(label, body, modelId = null) {
  const preferred = [
    "model",
    "messages",
    "max_tokens",
    "max_completion_tokens",
    "temperature",
    "top_p",
    "stream",
    "tools",
    "tool_choice",
    "response_format",
  ];
  const copy = { ...(body || {}) };
  if (modelId) copy.model = modelId;
  const ordered = {};
  for (const key of preferred) {
    if (Object.prototype.hasOwnProperty.call(copy, key)) {
      ordered[key] = copy[key];
      delete copy[key];
    }
  }
  for (const key of Object.keys(copy).sort()) {
    ordered[key] = copy[key];
  }
  return { label, sha256: sha256Hex(JSON.stringify(ordered)) };
}

function uniqueHashCandidates(candidates) {
  const seen = new Set();
  return candidates.filter((candidate) => {
    if (seen.has(candidate.sha256)) return false;
    seen.add(candidate.sha256);
    return true;
  });
}

function requestHashCandidates(bundle, signedModel) {
  const request = bundle.encrypted_request || {};
  const candidates = [{ label: "exact_gateway_bytes", sha256: sha256Hex(JSON.stringify(request)) }];
  const seenModels = new Set();
  for (const [label, modelId] of [
    ["signed_model_canonical_json", signedModel],
    ["response_model_canonical_json", bundle.encrypted_response?.model],
    ["canonical_model_canonical_json", bundle.canonical_model_id],
    ["request_model_canonical_json", request.model],
  ]) {
    if (!modelId || seenModels.has(modelId)) continue;
    seenModels.add(modelId);
    candidates.push(orderedJsonHash(label, request, modelId));
  }
  return uniqueHashCandidates(candidates);
}

function stripUsageCost(response) {
  const copy = response && typeof response === "object" ? structuredClone(response) : {};
  if (copy.usage && typeof copy.usage === "object") delete copy.usage.cost;
  return copy;
}

function responseHashCandidates(bundle) {
  const response = bundle.encrypted_response || {};
  const candidates = [
    { label: "json_compact_from_parsed_response", sha256: sha256Hex(JSON.stringify(response)) },
  ];
  if (bundle.encrypted_response_text) {
    candidates.unshift({ label: "exact_upstream_bytes", sha256: sha256Hex(bundle.encrypted_response_text) });
  }
  if (response.usage && typeof response.usage === "object" && Object.prototype.hasOwnProperty.call(response.usage, "cost")) {
    candidates.push({
      label: "gateway_usage_cost_stripped_json_compact",
      sha256: sha256Hex(JSON.stringify(stripUsageCost(response))),
    });
  }
  return uniqueHashCandidates(candidates);
}

function matchingHashLabels(expectedHash, candidates) {
  const expected = cleanHex(expectedHash);
  return candidates.filter((candidate) => candidate.sha256 === expected).map((candidate) => candidate.label);
}

function ethereumSignedMessageHash(text) {
  const message = Buffer.from(String(text), "utf8");
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${message.length}`, "utf8");
  return keccak_256(Buffer.concat([prefix, message]));
}

function normalizeRecoveryBit(value) {
  const v = Number(value);
  if (v >= 35) return (v - 35) % 2;
  if (v >= 27) return v - 27;
  return v;
}

function publicKeyToEthereumAddress(publicKey) {
  const uncompressed = publicKey.toRawBytes(false);
  const hash = keccak_256(uncompressed.slice(1));
  return `0x${bytesToHex(hash.slice(-20))}`;
}

function recoverEthereumAddress(text, signatureHex) {
  const signatureBytes = hexToBytes(signatureHex);
  if (signatureBytes.length !== 65) throw new Error("Ethereum signature must be 65 bytes");
  const recovery = normalizeRecoveryBit(signatureBytes[64]);
  if (!Number.isInteger(recovery) || recovery < 0 || recovery > 3) {
    throw new Error(`Invalid signature recovery id: ${signatureBytes[64]}`);
  }
  const signature = Signature.fromCompact(signatureBytes.slice(0, 64)).addRecoveryBit(recovery);
  const publicKey = signature.recoverPublicKey(ethereumSignedMessageHash(text));
  return publicKeyToEthereumAddress(publicKey);
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

function checkSignature(bundle, failures, warnings) {
  const signature = bundle.signature;
  if (!signature || typeof signature !== "object") {
    warnings.push("signature object is missing");
    return;
  }
  const signatureText = String(signature.text || "");
  const signatureHex = String(signature.signature || "");
  const signingAddress = String(signature.signing_address || "");
  let parsed;
  try {
    parsed = parseSignatureText(signatureText);
  } catch (error) {
    failures.push(`signature.text parse failed: ${error.message}`);
    return;
  }

  const requestMatches = matchingHashLabels(parsed.request_hash, requestHashCandidates(bundle, parsed.signed_model));
  if (!requestMatches.length) {
    failures.push(`signature request hash does not match local request candidates: ${parsed.request_hash}`);
  }
  const responseMatches = matchingHashLabels(parsed.response_hash, responseHashCandidates(bundle));
  if (!responseMatches.length) {
    failures.push(`signature response hash does not match local response candidates: ${parsed.response_hash}`);
  }

  if (!signatureHex || !signingAddress) {
    warnings.push("signature.signature or signature.signing_address is missing; cannot recover signer offline");
    return;
  }
  try {
    const recovered = recoverEthereumAddress(signatureText, signatureHex);
    if (cleanHex(recovered) !== cleanHex(signingAddress)) {
      failures.push(`signature signer mismatch: recovered ${recovered}, expected ${signingAddress}`);
    }
  } catch (error) {
    failures.push(`signature signer recovery failed: ${error.message}`);
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
  checkSignature(bundle, failures, warnings);

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
