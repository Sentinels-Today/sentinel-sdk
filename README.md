# @sentinels/sdk

**TypeScript SDK for the Sentinels trust stack** — Ed25519 device identity, attestation claims, deterministic trust scoring, hash-chained audit logs, and a thin HTTP client for `sentinel-cloud`.

[![ci](https://github.com/Sentinels-Today/sentinel-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Sentinels-Today/sentinel-sdk/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![node](https://img.shields.io/badge/node-%E2%89%A520-green)

## Install

```sh
npm install @sentinels/sdk
```

Runtime dependencies are limited to [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — both audited, zero-dep, browser/node compatible.

## Quick start

```ts
import {
  DeviceIdentity,
  signClaim,
  verifyClaim,
  computeTrust,
  AuditChain,
  SentinelClient,
} from "@sentinels/sdk";

const device = await DeviceIdentity.generate();
console.log(device.did); // did:sentinel:<64-hex>

const claim = await signClaim(device, {
  kind: "firmware_hash",
  subject: device.did,
  issued_at: new Date().toISOString(),
  nonce: "boot-1",
  payload: { sha256: "abc..." },
});
console.log(await verifyClaim(claim)); // true

const trust = computeTrust({
  firmwareVerified: true,
  verifiedTelemetryEvents: 10,
  anomalyDetected: false,
  keyRotatedWithin7Days: true,
  heartbeatCount: 200,
});
console.log(trust); // { score: 95, level: "verified" }

const chain = new AuditChain();
await chain.append(device.did, "attest", { digest: "..." }, device);
await chain.verify();

const cloud = new SentinelClient({ baseUrl: "https://api.sentinels.today", apiKey: "..." });
await cloud.registerDevice({ did: device.did, public_key_hex: device.publicKeyHex });
```

## Modules

| Module | Exports |
|---|---|
| `identity` | `DeviceIdentity`, `didFromPublicKey`, `parseDid`, `verifyHex`, `DID_PREFIX` |
| `attestation` | `Claim`, `ClaimBody`, `ClaimKind`, `signClaim`, `verifyClaim`, `digestHex`, `canonicalize` |
| `trust` | `TrustInputs`, `TrustScore`, `TrustLevel`, `computeTrust`, `levelForScore`, `DEFAULT_TRUST_INPUTS` |
| `audit` | `AuditChain`, `AuditEntry` |
| `client` | `SentinelClient`, `SentinelClientOptions` |

All algorithms (DID derivation, canonical-JSON claim digest, trust score formula, audit hash chain) are wire-compatible with the Rust [`sentinel-core`](https://github.com/Sentinels-Today/sentinel-core) crates.

## Develop

```sh
npm install
npm run lint
npm run typecheck
npm test
npm run build
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
