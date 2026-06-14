#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { verifyProofBundle } from "./verify-proof-bundle.mjs";

function sha256Hex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

const encryptedHex = "ab".repeat(96);
const encryptedRequest = {
  model: "phala/test-model",
  messages: [{ role: "user", content: encryptedHex }],
};
const encryptedResponse = {
  id: "chatcmpl-test",
  choices: [{ message: { content: encryptedHex } }],
};
const encryptedResponseText = JSON.stringify(encryptedResponse);

const bundle = {
  schema: "trust-ai.e2ee-proof-bundle.v1",
  created_at: "2026-06-14T04:30:00.000Z",
  app_origin: "https://trust.hurated.com",
  model_id: "phala/test-model",
  canonical_model_id: "phala/test-model",
  e2ee_version: "1",
  attestation: {
    nonce: "00".repeat(32),
    model_public_key: "02" + "11".repeat(32),
    report: {
      request_nonce: "00".repeat(32),
      model_public_key: "02" + "11".repeat(32),
    },
  },
  client_attestation: { ok: true },
  encrypted_request: encryptedRequest,
  e2ee_request_headers: {
    "X-Client-Pub-Key": "02" + "22".repeat(32),
    "X-Model-Pub-Key": "02" + "11".repeat(32),
  },
  encrypted_response: encryptedResponse,
  encrypted_response_text: encryptedResponseText,
  e2ee_response_headers: { "X-E2EE-Applied": "true" },
  signature: { text: "signed response" },
  proof: {
    request_sha256: sha256Hex(JSON.stringify(encryptedRequest)),
    response_sha256: sha256Hex(encryptedResponseText),
    verification: {
      verified: true,
      status: "verified",
      checks: {
        request_hash: { ok: true },
        response_hash: { ok: true },
        signature_address: { ok: true },
        signer_attestation: { ok: true },
        tdx_quote: { ok: true },
        gpu_attestation: { ok: true },
      },
    },
  },
  billing: { final_user_charge_usd: "0.000001" },
  usage_event_id: 1,
};

assert.equal(verifyProofBundle(bundle).ok, true);

const tamperedRequest = structuredClone(bundle);
tamperedRequest.encrypted_request.messages[0].content = "not encrypted";
assert.equal(verifyProofBundle(tamperedRequest).ok, false);

const plaintextKey = structuredClone(bundle);
plaintextKey.prompt = "do not ship this";
assert.equal(verifyProofBundle(plaintextKey).ok, false);

const tamperedResponseText = structuredClone(bundle);
tamperedResponseText.encrypted_response_text = JSON.stringify({ id: "changed" });
assert.equal(verifyProofBundle(tamperedResponseText).ok, false);

const tamperedAttestation = structuredClone(bundle);
tamperedAttestation.attestation.report.request_nonce = "ff".repeat(32);
assert.equal(verifyProofBundle(tamperedAttestation).ok, false);

console.log("proof bundle verifier tests passed");
