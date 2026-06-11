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
```

Verify the local archive:

```bash
sha256sum -c release/trust-web.sha256
```

To compare with the hosted release, download the published `trust-web.tar.gz` and `trust-web.sha256`, then run the same `sha256sum -c` command in the download directory. Matching checksums mean the downloadable client archive matches the published build artifact for that release.

For deterministic builds, the release script sorts archive entries, fixes owner/group metadata, and uses `SOURCE_DATE_EPOCH`. To reproduce a specific release exactly, check out the release tag, use the Node version in `package.json`, run `npm ci`, and then run `npm run release`.

## Encrypted Inference Flow

1. The client logs in with Firebase and receives a backend session.
2. The client asks the backend for a fresh model attestation and checks the nonce and encryption public key in the attestation response.
3. The client generates a secp256k1 key, encrypts the prompt locally with AES-GCM using the RedPill E2EE protocol, and sends only ciphertext to the Trust backend. The live deployment defaults to v1 compatibility mode; v2 AAD support remains in the source for providers that accept it.
4. The backend verifies balance, forwards the ciphertext and E2EE headers to the confidential inference provider, and stores metadata only.
5. The client decrypts the encrypted response locally.

The plaintext prompt and model response are not intentionally stored in this client, local storage, the Trust backend, or the database.
