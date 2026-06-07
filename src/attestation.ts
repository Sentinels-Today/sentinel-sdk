import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

import { DeviceIdentity, verifyHex } from "./identity.js";

export type ClaimKind = "firmware_hash" | "measured_boot" | "software_bom" | "custom";

export interface ClaimBody {
  kind: ClaimKind;
  subject: string;
  issued_at: string;
  nonce: string;
  payload: unknown;
}

export interface Claim {
  body: ClaimBody;
  signature_hex: string;
  public_key_hex: string;
}

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`)
    .join(",")}}`;
}

function preimageBytes(body: ClaimBody): Uint8Array {
  return new TextEncoder().encode(canonicalize(body));
}

export function digestHex(body: ClaimBody): string {
  return bytesToHex(sha256(preimageBytes(body)));
}

export async function signClaim(identity: DeviceIdentity, body: ClaimBody): Promise<Claim> {
  const sig = await identity.signHex(preimageBytes(body));
  return { body, signature_hex: sig, public_key_hex: identity.publicKeyHex };
}

export async function verifyClaim(claim: Claim): Promise<boolean> {
  return verifyHex(claim.public_key_hex, preimageBytes(claim.body), claim.signature_hex);
}
