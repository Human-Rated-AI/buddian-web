# Trust Web

Open source web client for Trust AI. This repository contains the user-facing client only: Firebase login, model listing, balance display, top-up links, and end-to-end encrypted inference. It does not contain provider API keys, admin tools, server code, deployment secrets, or payment secrets.

## Why There Are No Secrets Here

Firebase web configuration is public by design; it identifies the Firebase project but does not grant admin access. Provider keys, database passwords, payment secrets, and admin permissions live only on the Trust AI backend. The browser receives a short-lived Trust session after Firebase login and sends encrypted inference payloads through the backend, so our provider key is never shipped in this repository or in the downloadable client.

## Build

```bash
npm ci
npm run build
```

The static client is written to `dist/`.

## Reproducible Release And Checksum

Build the release archive:

```bash
npm ci
npm run release
```

This creates:

```text
release/trust-web.tar.gz
release/trust-web.sha256
release/trust-web.release.json
```

Verify the local archive:

```bash
cd release
sha256sum -c trust-web.sha256
```

To compare with the hosted release, download the published `trust-web.tar.gz`, `trust-web.sha256`, and `trust-web.release.json`, then run the same `sha256sum -c trust-web.sha256` command in the download directory. Matching checksums mean the downloadable client archive and release manifest match the published build artifacts for that release.

GitHub releases are published automatically for tags named `trust-web-v*`. The release assets always include the archive, checksum file, and JSON manifest with the source commit and archive SHA-256.

For deterministic builds, the release script sorts archive entries, fixes owner/group metadata, and uses `SOURCE_DATE_EPOCH`. To reproduce a specific release exactly, check out the release tag, use the Node version in `package.json`, run `npm ci`, and then run `npm run release`.

## Verify A Downloaded Proof Bundle

After a successful encrypted request, the client can download a proof bundle. Verify it locally:

```bash
npm ci
npm run verify:proof -- path/to/trust-ai-proof.json
```

The verifier checks that the request hash matches the encrypted request, the response hash matches the exact encrypted upstream response text when present, the saved attestation report contains the expected nonce and model encryption key, request and response content are ciphertext-shaped, the bundle contains no obvious plaintext prompt/answer fields, and the backend proof checks report verified status. It does not contact Trust AI or the provider, so it does not refresh attestation; it validates the saved proof bundle.

## Encrypted Inference Flow

1. The client logs in with Firebase and receives a backend session.
2. The client asks the backend for a fresh model attestation and checks the nonce and encryption public key in the attestation response.
3. The client generates a secp256k1 key, encrypts the prompt locally with AES-GCM using the RedPill E2EE protocol, and sends only ciphertext to the Trust backend. The live deployment defaults to v1 compatibility mode; v2 AAD support remains in the source for providers that accept it.
4. The backend verifies balance, forwards the ciphertext and E2EE headers to the confidential inference provider, and stores metadata only.
5. The client decrypts the encrypted response locally.
6. After a successful encrypted request, the client can download a JSON proof bundle containing encrypted request/response payloads, attestation metadata, response signature data, verifier status, request/response hashes, and billing metadata. The bundle intentionally excludes the plaintext prompt and plaintext answer.

The plaintext prompt and model response are not intentionally stored in this client, local storage, the Trust backend, or the database.
