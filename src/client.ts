import type { Claim } from "./attestation.js";
import type { TrustScore } from "./trust.js";

export interface SentinelClientOptions {
  baseUrl: string;
  apiKey?: string;
  fetch?: typeof fetch;
}

export interface RegisterDeviceInput {
  did: string;
  public_key_hex: string;
  metadata?: Record<string, unknown>;
}

export interface RegisterDeviceResult {
  did: string;
  registered_at: string;
}

/**
 * Minimal HTTP client for sentinel-cloud. The expected API surface mirrors
 * the routes in the sentinel-cloud reference server.
 */
export class SentinelClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: SentinelClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  private async req<T>(path: string, init?: RequestInit): Promise<T> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...(init?.headers as Record<string, string> | undefined),
    };
    if (this.apiKey) headers["authorization"] = `Bearer ${this.apiKey}`;
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, { ...init, headers });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`sentinel-cloud ${res.status}: ${body || res.statusText}`);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  registerDevice(input: RegisterDeviceInput): Promise<RegisterDeviceResult> {
    return this.req("/v1/devices", { method: "POST", body: JSON.stringify(input) });
  }

  submitClaim(claim: Claim): Promise<{ accepted: true; digest: string }> {
    return this.req("/v1/attestations", { method: "POST", body: JSON.stringify(claim) });
  }

  getTrustScore(did: string): Promise<TrustScore> {
    return this.req(`/v1/devices/${encodeURIComponent(did)}/trust`);
  }
}
