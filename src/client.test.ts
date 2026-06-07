import { describe, expect, it } from "vitest";

import { SentinelClient } from "./client.js";

describe("SentinelClient", () => {
  it("posts JSON with bearer token", async () => {
    let captured: { url?: string; init?: RequestInit } = {};
    const fakeFetch: typeof fetch = async (input, init) => {
      captured = { url: input as string, init };
      return new Response(JSON.stringify({ did: "did:sentinel:abc", registered_at: "now" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    };
    const client = new SentinelClient({
      baseUrl: "https://api.example.com/",
      apiKey: "secret",
      fetch: fakeFetch,
    });
    const out = await client.registerDevice({
      did: "did:sentinel:abc",
      public_key_hex: "ff",
    });
    expect(out.did).toBe("did:sentinel:abc");
    expect(captured.url).toBe("https://api.example.com/v1/devices");
    const headers = captured.init?.headers as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer secret");
    expect(headers["content-type"]).toBe("application/json");
    expect(captured.init?.method).toBe("POST");
  });

  it("throws on non-2xx", async () => {
    const fakeFetch: typeof fetch = async () =>
      new Response("nope", { status: 500, statusText: "Internal" });
    const client = new SentinelClient({ baseUrl: "https://api.example.com", fetch: fakeFetch });
    await expect(
      client.registerDevice({ did: "x", public_key_hex: "y" }),
    ).rejects.toThrow(/500/);
  });
});
