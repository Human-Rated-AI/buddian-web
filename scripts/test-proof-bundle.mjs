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
  schema: "buddian.e2ee-proof-bundle.v1",
  created_at: "2026-06-14T04:30:00.000Z",
  app_origin: "https://buddian.com",
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
  signature: {
    text: `phala/test-model:${sha256Hex(JSON.stringify(encryptedRequest))}:${sha256Hex(encryptedResponseText)}`,
    signature: "e56f97c4b564a4cde3af6e282556793b527141c41294441e2c397b7d9e446f5a043be56aa57c0f53d4b44eac335999d3bbda10ccb9659835c47315c7988072791b",
    signing_address: "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A",
    signing_algo: "ecdsa",
  },
  proof: {
    request_sha256: sha256Hex(JSON.stringify(encryptedRequest)),
    response_sha256: sha256Hex(encryptedResponseText),
    verification: {
      verified: true,
      status: "verified",
      checks: {
        signature_present: { ok: true },
        signature_text_parse: { ok: true },
        request_hash_matches: { ok: true },
        response_hash_matches: { ok: true },
        signature_recovers_signer: { ok: true },
        signer_attestation_fetched: { ok: true },
        attestation_signing_address_matches: { ok: true },
        attestation_nonce_matches: { ok: true },
        tdx_quote_verified: { ok: true },
        tdx_report_data_binds_signer: { ok: true },
        tdx_report_data_binds_nonce: { ok: true },
        gpu_attestation_verified: { ok: true },
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

const tamperedSignature = structuredClone(bundle);
tamperedSignature.signature.signing_address = "0x0000000000000000000000000000000000000000";
assert.equal(verifyProofBundle(tamperedSignature).ok, false);

console.log("proof bundle verifier tests passed");
