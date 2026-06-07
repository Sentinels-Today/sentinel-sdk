import { describe, expect, it } from "vitest";

import { DID_PREFIX, DeviceIdentity, parseDid, verifyHex } from "./identity.js";

describe("DeviceIdentity", () => {
  it("generates unique DIDs", async () => {
    const a = await DeviceIdentity.generate();
    const b = await DeviceIdentity.generate();
    expect(a.did).not.toBe(b.did);
    expect(a.publicKeyHex).not.toBe(b.publicKeyHex);
    expect(a.did.startsWith(DID_PREFIX)).toBe(true);
    expect(a.did.length).toBe(DID_PREFIX.length + 64);
  });

  it("round-trips through secret bytes", async () => {
    const id = await DeviceIdentity.generate();
    const restored = await DeviceIdentity.fromSecretHex(id.secretHex);
    expect(restored.did).toBe(id.did);
    expect(restored.publicKeyHex).toBe(id.publicKeyHex);
  });

  it("signs and verifies a payload", async () => {
    const id = await DeviceIdentity.generate();
    const payload = new TextEncoder().encode("hello-sentinel");
    const sig = await id.signHex(payload);
    expect(await verifyHex(id.publicKeyHex, payload, sig)).toBe(true);

    const tampered = new TextEncoder().encode("hello-tampered");
    expect(await verifyHex(id.publicKeyHex, tampered, sig)).toBe(false);
  });

  it("parses and rejects DIDs", () => {
    expect(() => parseDid("not-a-did")).toThrow();
    expect(() => parseDid(`${DID_PREFIX}short`)).toThrow();
    expect(() => parseDid(`${DID_PREFIX}${"z".repeat(64)}`)).toThrow();
    const good = `${DID_PREFIX}${"a".repeat(64)}`;
    expect(parseDid(good)).toBe(good);
  });
});
