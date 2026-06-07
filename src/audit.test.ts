import { describe, expect, it } from "vitest";

import { AuditChain } from "./audit.js";
import { DeviceIdentity } from "./identity.js";

describe("AuditChain", () => {
  it("appends and verifies a clean chain", async () => {
    const chain = new AuditChain();
    await chain.append("robot-1", "boot", { ok: true });
    await chain.append("robot-1", "telemetry", { temp: 42 });
    await chain.verify();
    expect(chain.length).toBe(2);
  });

  it("detects tampering", async () => {
    const chain = new AuditChain();
    await chain.append("r", "a", { x: 1 });
    await chain.append("r", "b", { x: 2 });
    (chain.entries[0] as { details: unknown }).details = { x: 99 };
    await expect(chain.verify()).rejects.toThrow(/hash mismatch/);
  });

  it("verifies signed entries and rejects forgeries", async () => {
    const id = await DeviceIdentity.generate();
    const chain = new AuditChain();
    await chain.append("r", "boot", {}, id);
    await chain.append("r", "telemetry", { v: 1 }, id);
    await chain.verify();

    (chain.entries[0] as { signature_hex: string | null }).signature_hex = "00".repeat(64);
    await expect(chain.verify()).rejects.toThrow(/invalid signature/);
  });
});
