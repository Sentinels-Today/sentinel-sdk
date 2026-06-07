import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

import { DeviceIdentity, verifyHex } from "./identity.js";

export interface AuditEntry {
  id: string;
  robot_id: string;
  action: string;
  details: unknown;
  timestamp: string;
  previous_hash: string | null;
  hash: string;
  signature_hex: string | null;
  public_key_hex: string | null;
}

function uuid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  const r = (n: number) => Math.floor(Math.random() * 16 ** n).toString(16).padStart(n, "0");
  return `${r(8)}-${r(4)}-${r(4)}-${r(4)}-${r(12)}`;
}

function preimage(
  id: string,
  robotId: string,
  action: string,
  details: unknown,
  timestamp: string,
  previousHash: string | null,
): string {
  return `${id}|${robotId}|${action}|${JSON.stringify(details)}|${timestamp}|${previousHash ?? ""}`;
}

function hashHex(s: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(s)));
}

export class AuditChain {
  private readonly _entries: AuditEntry[] = [];

  get entries(): readonly AuditEntry[] {
    return this._entries;
  }

  get length(): number {
    return this._entries.length;
  }

  get tailHash(): string | null {
    return this._entries.length === 0 ? null : (this._entries.at(-1)!.hash);
  }

  async append(
    robotId: string,
    action: string,
    details: unknown,
    signer?: DeviceIdentity,
  ): Promise<AuditEntry> {
    const id = uuid();
    const timestamp = new Date().toISOString();
    const previousHash = this.tailHash;
    const hash = hashHex(preimage(id, robotId, action, details, timestamp, previousHash));

    let signature_hex: string | null = null;
    let public_key_hex: string | null = null;
    if (signer) {
      signature_hex = await signer.signHex(new TextEncoder().encode(hash));
      public_key_hex = signer.publicKeyHex;
    }

    const entry: AuditEntry = {
      id,
      robot_id: robotId,
      action,
      details,
      timestamp,
      previous_hash: previousHash,
      hash,
      signature_hex,
      public_key_hex,
    };
    this._entries.push(entry);
    return entry;
  }

  async verify(): Promise<void> {
    let previous: string | null = null;
    for (let i = 0; i < this._entries.length; i++) {
      const e = this._entries[i]!;
      const expected = hashHex(
        preimage(e.id, e.robot_id, e.action, e.details, e.timestamp, previous),
      );
      if (expected !== e.hash) {
        throw new Error(`hash mismatch at index ${i} (entry ${e.id})`);
      }
      if ((e.previous_hash ?? null) !== previous) {
        throw new Error(`broken previous-hash link at index ${i}`);
      }
      if (e.signature_hex && e.public_key_hex) {
        const ok = await verifyHex(
          e.public_key_hex,
          new TextEncoder().encode(e.hash),
          e.signature_hex,
        );
        if (!ok) throw new Error(`invalid signature on entry ${e.id}`);
      }
      previous = e.hash;
    }
  }
}
