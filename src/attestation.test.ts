import { describe, expect, it } from "vitest";

import { canonicalize, digestHex, signClaim, verifyClaim } from "./attestation.js";
import { DeviceIdentity } from "./identity.js";

describe("attestation", () => {
  it("canonicalizes keys in lexical order", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ a: 2, b: 1 })).toBe(canonicalize({ b: 1, a: 2 }));
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  it("digests are stable across key order", async () => {
    const id = await DeviceIdentity.generate();
    const issuedAt = new Date().toISOString();
    const d1 = digestHex({
      kind: "firmware_hash",
      subject: id.did,
      issued_at: issuedAt,
      nonce: "1",
      payload: { a: 1, b: 2 },
    });
    const d2 = digestHex({
      kind: "firmware_hash",
      subject: id.did,
      issued_at: issuedAt,
      nonce: "1",
      payload: { b: 2, a: 1 },
    });
    expect(d1).toBe(d2);
  });

  it("signs and verifies, fails on tamper", async () => {
    const id = await DeviceIdentity.generate();
    const claim = await signClaim(id, {
      kind: "firmware_hash",
      subject: id.did,
      issued_at: new Date().toISOString(),
      nonce: "n",
      payload: { sha256: "abc" },
    });
    expect(await verifyClaim(claim)).toBe(true);

    const tampered = {
      ...claim,
      body: { ...claim.body, payload: { sha256: "xyz" } },
    };
    expect(await verifyClaim(tampered)).toBe(false);
  });
});
