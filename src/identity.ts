import {
  etc as edEtc,
  getPublicKeyAsync,
  signAsync,
  utils as edUtils,
  verifyAsync,
} from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

// noble-ed25519 v2 needs a sync sha512 wired in to enable the sync API surface;
// async helpers also benefit from it. Inject @noble/hashes once at module load.
edEtc.sha512Sync = (...messages: Uint8Array[]) => {
  const h = sha512.create();
  for (const m of messages) h.update(m);
  return h.digest();
};

export const DID_PREFIX = "did:sentinel:";

export class DeviceIdentity {
  private constructor(
    private readonly secret: Uint8Array,
    public readonly publicKey: Uint8Array,
    public readonly did: string,
  ) {}

  static async generate(): Promise<DeviceIdentity> {
    const secret = edUtils.randomPrivateKey();
    const publicKey = await getPublicKeyAsync(secret);
    return new DeviceIdentity(secret, publicKey, didFromPublicKey(publicKey));
  }

  static async fromSecretBytes(secret: Uint8Array): Promise<DeviceIdentity> {
    if (secret.length !== 32) {
      throw new Error(`invalid secret length: expected 32, got ${secret.length}`);
    }
    const publicKey = await getPublicKeyAsync(secret);
    return new DeviceIdentity(secret, publicKey, didFromPublicKey(publicKey));
  }

  static async fromSecretHex(secretHex: string): Promise<DeviceIdentity> {
    return DeviceIdentity.fromSecretBytes(hexToBytes(secretHex));
  }

  get publicKeyHex(): string {
    return bytesToHex(this.publicKey);
  }

  get secretHex(): string {
    return bytesToHex(this.secret);
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    return signAsync(payload, this.secret);
  }

  async signHex(payload: Uint8Array): Promise<string> {
    return bytesToHex(await this.sign(payload));
  }
}

export function didFromPublicKey(publicKey: Uint8Array): string {
  return DID_PREFIX + bytesToHex(sha256(publicKey));
}

export function parseDid(did: string): string {
  if (!did.startsWith(DID_PREFIX)) {
    throw new Error(`invalid DID: missing '${DID_PREFIX}' prefix`);
  }
  const body = did.slice(DID_PREFIX.length);
  if (body.length !== 64) {
    throw new Error(`invalid DID: expected 64-hex body, got ${body.length}`);
  }
  hexToBytes(body); // validates hex
  return did;
}

export async function verifyHex(
  publicKeyHex: string,
  payload: Uint8Array,
  signatureHex: string,
): Promise<boolean> {
  const pk = hexToBytes(publicKeyHex);
  if (pk.length !== 32) {
    throw new Error(`invalid public key length: ${pk.length}`);
  }
  const sig = hexToBytes(signatureHex);
  if (sig.length !== 64) {
    throw new Error(`invalid signature length: ${sig.length}`);
  }
  try {
    return await verifyAsync(sig, payload, pk);
  } catch {
    return false;
  }
}
