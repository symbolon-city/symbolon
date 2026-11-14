// Encrypted wallet file (Node only). The wallet holds the agent's secret key and
// the full text of every agreement, so it is never written in clear.
//
// File format (JSON):
//   { format: "symbolon-wallet", v: 2, key: <how the key is obtained>,
//     cipher: "aes-256-gcm", nonce, data }   (data = ciphertext + 16-byte tag, base64)
// The header is authenticated (AAD): changing any field makes decryption fail.
//
// Where the 32-byte key comes from:
//   - passphrase: scrypt(passphrase, salt)            — any system
//   - keychain:   random key kept in the macOS Keychain
//   - dpapi:      random key protected by Windows DPAPI for the current user,
//                 stored next to the wallet as <wallet>.key

import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb } from "node:crypto";
import { execFile } from "node:child_process";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { WalletState, WalletStorage } from "./wallet.js";

const FORMAT = "symbolon-wallet";

export type KeySpec =
  | { kind: "passphrase"; salt: string; N: number; r: number; p: number }
  | { kind: "keychain"; service: string; account: string }
  | { kind: "dpapi" };

interface WalletFile {
  format: typeof FORMAT;
  v: 2;
  key: KeySpec;
  cipher: "aes-256-gcm";
  nonce: string;
  data: string;
}

/** Runs an external program; injectable for tests. */
export type Runner = (cmd: string, args: string[], input?: string) => Promise<string>;

export const defaultRunner: Runner = (cmd, args, input) =>
  new Promise((resolve, reject) => {
    const child = execFile(cmd, args, { maxBuffer: 1 << 20, windowsHide: true }, (err, stdout, stderr) => {
      if (err) reject(new Error(`${cmd} failed: ${String(stderr || err.message).trim()}`));
      else resolve(String(stdout));
    });
    if (input !== undefined) child.stdin?.end(input);
  });

export interface KeyProvider {
  /** Describes the key for a new wallet file. */
  spec(): Promise<KeySpec>;
  /** Returns the 32-byte key for a wallet file's key spec. Creates it on first use where needed. */
  key(spec: KeySpec, create: boolean): Promise<Buffer>;
}

// ---------- passphrase ----------

const SCRYPT = { N: 1 << 17, r: 8, p: 1 };

function scrypt(pass: string, salt: Buffer, N: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scryptCb(pass.normalize("NFC"), salt, 32, { N, r, p, maxmem: 256 * 1024 * 1024 }, (e, k) => (e ? reject(e) : resolve(k))),
  );
}

export function passphraseProvider(passphrase: string, params = SCRYPT): KeyProvider {
  if (passphrase.length < 12) throw new Error("the wallet password must be at least 12 characters");
  return {
    async spec() {
      return { kind: "passphrase", salt: randomBytes(16).toString("base64"), ...params };
    },
    async key(spec) {
      if (spec.kind !== "passphrase") throw new Error(`this wallet is protected with ${spec.kind}, not a password`);
      return scrypt(passphrase, Buffer.from(spec.salt, "base64"), spec.N, spec.r, spec.p);
    },
  };
}

// ---------- macOS Keychain ----------

export function keychainProvider(account: string, run: Runner = defaultRunner, service = "symbolon-wallet"): KeyProvider {
  return {
    async spec() {
      return { kind: "keychain", service, account };
    },
    async key(spec, create) {
      if (spec.kind !== "keychain") throw new Error(`this wallet is protected with ${spec.kind}, not the Keychain`);
      try {
        const hex = (await run("security", ["find-generic-password", "-s", spec.service, "-a", spec.account, "-w"])).trim();
        if (/^[0-9a-f]{64}$/.test(hex)) return Buffer.from(hex, "hex");
      } catch {
        /* not found */
      }
      if (!create) throw new Error("the wallet key is not in the Keychain");
      const k = randomBytes(32);
      // The key passes once on the command line of `security`, visible to the same user for a moment.
      await run("security", ["add-generic-password", "-s", spec.service, "-a", spec.account, "-w", k.toString("hex"), "-U"]);
      return k;
    },
  };
}

// ---------- Windows DPAPI ----------

const PS_PROTECT =
  "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); " +
  "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser'))";
const PS_UNPROTECT =
  "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); " +
  "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))";

export function dpapiProvider(keyFile: string, run: Runner = defaultRunner): KeyProvider {
  const ps = (script: string, input: string) =>
    run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], input).then((s) => s.trim());
  return {
    async spec() {
      return { kind: "dpapi" };
    },
    async key(spec, create) {
      if (spec.kind !== "dpapi") throw new Error(`this wallet is protected with ${spec.kind}, not Windows protection`);
      try {
        const blob = (await readFile(keyFile, "utf8")).trim();
        return Buffer.from(await ps(PS_UNPROTECT, blob), "base64");
      } catch (e) {
        if (!create || (e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      }
      const k = randomBytes(32);
      const blob = await ps(PS_PROTECT, k.toString("base64"));
      await writeFile(keyFile, blob, { mode: 0o600 });
      return k;
    },
  };
}

// ---------- storage ----------

function aad(f: Pick<WalletFile, "format" | "v" | "key" | "cipher">): Buffer {
  return Buffer.from(JSON.stringify({ format: f.format, v: f.v, key: f.key, cipher: f.cipher }));
}

export class EncryptedWalletStorage implements WalletStorage {
  private cached: { spec: KeySpec; key: Buffer } | null = null;

  constructor(
    private readonly path: string,
    private readonly provider: KeyProvider,
  ) {}

  private async keyFor(spec: KeySpec, create: boolean): Promise<Buffer> {
    if (this.cached && JSON.stringify(this.cached.spec) === JSON.stringify(spec)) return this.cached.key;
    const key = await this.provider.key(spec, create);
    if (key.length !== 32) throw new Error("wallet key must be 32 bytes");
    this.cached = { spec, key };
    return key;
  }

  async load(): Promise<WalletState | null> {
    let raw: string;
    try {
      raw = await readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
    const parsed = JSON.parse(raw) as WalletFile | WalletState;
    if ((parsed as WalletFile).format !== FORMAT) {
      // A wallet saved in clear by an earlier version: encrypt it now.
      const state = parsed as WalletState;
      if (state.v !== 1 || typeof state.agentSecret !== "string") throw new Error("unrecognised wallet file");
      await this.save(state);
      return state;
    }
    const f = parsed as WalletFile;
    if (f.v !== 2 || f.cipher !== "aes-256-gcm") throw new Error("unsupported wallet file version");
    const key = await this.keyFor(f.key, false);
    const data = Buffer.from(f.data, "base64");
    try {
      const d = createDecipheriv("aes-256-gcm", key, Buffer.from(f.nonce, "base64"));
      d.setAAD(aad(f));
      d.setAuthTag(data.subarray(data.length - 16));
      const clear = Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]);
      return JSON.parse(clear.toString("utf8")) as WalletState;
    } catch {
      throw new Error("cannot open the wallet: wrong password or key, or the file was modified");
    }
  }

  async save(state: WalletState): Promise<void> {
    const spec = this.cached?.spec ?? (await this.existingSpec()) ?? (await this.provider.spec());
    const key = await this.keyFor(spec, true);
    const header = { format: FORMAT, v: 2, key: spec, cipher: "aes-256-gcm" } as const;
    const nonce = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", key, nonce);
    c.setAAD(aad(header));
    const data = Buffer.concat([c.update(JSON.stringify(state), "utf8"), c.final(), c.getAuthTag()]);
    const file: WalletFile = { ...header, nonce: nonce.toString("base64"), data: data.toString("base64") };
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = this.path + ".tmp";
    await writeFile(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
    await rename(tmp, this.path);
    await chmod(this.path, 0o600);
  }

  private async existingSpec(): Promise<KeySpec | null> {
    try {
      const f = JSON.parse(await readFile(this.path, "utf8")) as WalletFile;
      return f.format === FORMAT ? f.key : null;
    } catch {
      return null;
    }
  }
}

/** Picks how to protect the wallet from the environment. Never falls back to a clear file. */
export function providerFromEnv(walletPath: string, env = process.env, platform = process.platform, run: Runner = defaultRunner): KeyProvider {
  const mode = env.SYMBOLON_WALLET_KEY ?? (platform === "darwin" ? "keychain" : platform === "win32" ? "dpapi" : "passphrase");
  switch (mode) {
    case "keychain":
      return keychainProvider(walletPath, run);
    case "dpapi":
      return dpapiProvider(walletPath + ".key", run);
    case "passphrase": {
      const pass = env.SYMBOLON_WALLET_PASSWORD;
      if (!pass) throw new Error("set SYMBOLON_WALLET_PASSWORD (at least 12 characters) to protect the wallet");
      return passphraseProvider(pass);
    }
    default:
      throw new Error(`unknown SYMBOLON_WALLET_KEY "${mode}": use keychain, dpapi or passphrase`);
  }
}
