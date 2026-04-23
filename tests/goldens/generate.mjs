// Cross-implementation Known Answer Test (KAT) generator for the Rust
// `signer` workspace.
//
// For every chain we pick a fixed private key + a fixed input (digest,
// message, or transaction preimage) and compute the expected signature /
// address with a mature, independent JavaScript stack (`@noble/curves`,
// `@noble/hashes`, `@scure/base`). The Rust test suite then asserts that
// its own output matches byte-for-byte — making the tests real
// cross-implementation checks rather than self-confirming dumps.
//
// The KATs are **embedded directly** into each chain crate's `tests.rs`
// (as `const _HEX: &str = …;`), so the production code has zero runtime
// dependency on this script. This file is kept as the reproducible
// reference: if the test fixtures ever need to change, re-run the script
// and paste the new hex values into the affected `tests.rs` files.
//
// Run:
//   npm install --prefix tests/goldens
//   node tests/goldens/generate.mjs
//
// Outputs `tests/goldens/vectors.json` (human-readable, diff-friendly)
// and `tests/goldens/vectors.rs` (ready to hand-copy into a test crate).
// Both files are .gitignored — they are artefacts, not source.

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { sha512 } from '@noble/hashes/sha2';
import { sha3_256, keccak_256 } from '@noble/hashes/sha3';
import { ripemd160 } from '@noble/hashes/legacy';
import { blake2b } from '@noble/hashes/blake2';
import { base58, bech32 } from '@scure/base';

// Base58Check = `payload || double_sha256(payload)[..4]` then base58 encode.
function base58check(payload) {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  return base58.encode(concat(payload, checksum));
}

// -------------------- Fixed test material --------------------

const SECP_KEY_HEX =
  '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const ED25519_KEY_HEX =
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const SCHNORR_KEY_HEX =
  '7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a';

// 32-byte deterministic digest used by every `sign_hash` KAT.
const TEST_DIGEST = new Uint8Array(
  Array.from({ length: 32 }, (_, i) => i + 1),
);

// Reusable plain-text message and raw tx bytes.
const TEST_MESSAGE = new TextEncoder().encode('signer kat v3');
const TEST_TX = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03]);

// -------------------- Helpers --------------------

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}
function fromHex(h) {
  return new Uint8Array(Buffer.from(h, 'hex'));
}
function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
// Big-endian u8 CompactSize used by `Bitcoin Signed Message:\n` framing.
function compactSize(n) {
  if (n < 253) return Uint8Array.of(n);
  if (n <= 0xffff) return concat(Uint8Array.of(0xfd), le(n, 2));
  if (n <= 0xffff_ffff) return concat(Uint8Array.of(0xfe), le(n, 4));
  return concat(Uint8Array.of(0xff), le(BigInt(n), 8));
}
function le(v, width) {
  const out = new Uint8Array(width);
  let val = BigInt(v);
  for (let i = 0; i < width; i++) {
    out[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return out;
}
// ULEB128 used by Sui BCS for `Vec<u8>` length prefixes.
function uleb128(n) {
  const out = [];
  let v = n;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v >>= 7;
  }
  out.push(v & 0x7f);
  return Uint8Array.from(out);
}
// RFC 4648 base32 lowercase, no padding — Filecoin's `f1…` encoding.
function base32LowerNoPad(bytes) {
  const alpha = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0n;
  let nbits = 0;
  let out = '';
  for (const b of bytes) {
    bits = (bits << 8n) | BigInt(b);
    nbits += 8;
    while (nbits >= 5) {
      nbits -= 5;
      const idx = Number((bits >> BigInt(nbits)) & 0x1fn);
      out += alpha[idx];
    }
  }
  if (nbits > 0) {
    const idx = Number((bits << BigInt(5 - nbits)) & 0x1fn);
    out += alpha[idx];
  }
  return out;
}

// secp256k1 ECDSA: RFC 6979 deterministic signature over a 32-byte prehash,
// returned as `r(32) || s(32) || v(1)` matching our Rust
// `SignOutput::Ecdsa` wire format.
function ecdsaSignRecoverable(keyHex, digest) {
  const sig = secp256k1.sign(digest, fromHex(keyHex), { lowS: true });
  const compact = sig.toBytes('compact'); // r || s (64 B)
  // `v` is the parity bit of the y-coordinate of the recovered R point.
  const v = sig.recovery & 1;
  return concat(compact, Uint8Array.of(v));
}

// DER-encoded secp256k1 ECDSA signature over a 32-byte prehash.
function ecdsaSignDer(keyHex, digest) {
  return secp256k1.sign(digest, fromHex(keyHex), { lowS: true }).toBytes('der');
}

// Ed25519 over `message`, returning the 64-byte signature.
function ed25519Sign(keyHex, message) {
  return ed25519.sign(message, fromHex(keyHex));
}

// BIP-340 Schnorr signature with zeroed auxiliary randomness — matches
// the deterministic path taken by k256's `sign_raw(msg, &[0u8; 32])`.
function schnorrSign(keyHex, message) {
  return schnorr.sign(message, fromHex(keyHex), new Uint8Array(32));
}

// -------------------- Chain-specific compositions --------------------

const SECP = fromHex(SECP_KEY_HEX);
const SECP_PUBKEY_COMPRESSED = secp256k1.getPublicKey(SECP, true); // 33 B
const SECP_PUBKEY_UNCOMPRESSED = secp256k1.getPublicKey(SECP, false); // 65 B

const ED25519_PUB = ed25519.getPublicKey(fromHex(ED25519_KEY_HEX)); // 32 B
const SCHNORR_XONLY = schnorr.getPublicKey(fromHex(SCHNORR_KEY_HEX)); // 32 B

// -------- Bitcoin (P2PKH legacy + BIP-137 message signing) --------
function btcAddress() {
  const h160 = ripemd160(sha256(SECP_PUBKEY_COMPRESSED));
  // Mainnet P2PKH version byte 0x00.
  return base58check(concat(Uint8Array.of(0x00), h160));
}

function btcMessageDigest(message) {
  const prefix = new TextEncoder().encode('\x18Bitcoin Signed Message:\n');
  const data = concat(prefix, compactSize(message.length), message);
  return sha256(sha256(data));
}

function btcSignMessageBip137(message, addressTypeOffset) {
  const digest = btcMessageDigest(message);
  const sig = secp256k1.sign(digest, SECP, { lowS: true });
  const compact = sig.toBytes('compact');
  const header = addressTypeOffset + (sig.recovery & 1);
  // BIP-137 wire form: `header || r || s` (65 B, header prepended, not
  // appended). Our Rust `SignOutput::Ecdsa` stores `r || s || v` instead,
  // which is the form the tests compare against.
  return concat(compact, Uint8Array.of(header));
}

// -------- Ethereum (EIP-55 address + EIP-191 personal_sign) --------
function evmAddress() {
  // Uncompressed pubkey without the 0x04 prefix.
  const body = SECP_PUBKEY_UNCOMPRESSED.slice(1);
  const hash = keccak_256(body);
  const addr = hash.slice(12); // last 20 bytes
  const addrHex = hex(addr);
  const checksum = hex(keccak_256(new TextEncoder().encode(addrHex.toLowerCase())));
  let out = '0x';
  for (let i = 0; i < addrHex.length; i++) {
    const ch = addrHex[i];
    if (/[0-9]/.test(ch)) {
      out += ch;
    } else {
      out += parseInt(checksum[i], 16) >= 8 ? ch.toUpperCase() : ch;
    }
  }
  return out;
}

function evmSignMessageEip191(message) {
  const prefix = new TextEncoder().encode(
    `\x19Ethereum Signed Message:\n${message.length}`,
  );
  const digest = keccak_256(concat(prefix, message));
  const sig = secp256k1.sign(digest, SECP, { lowS: true });
  const compact = sig.toBytes('compact');
  const v = 27 + (sig.recovery & 1);
  return concat(compact, Uint8Array.of(v));
}

function evmSignTransactionKeccak(tx) {
  const digest = keccak_256(tx);
  const sig = secp256k1.sign(digest, SECP, { lowS: true });
  const compact = sig.toBytes('compact');
  // Raw `v = 0 | 1`, callers add 27 before feeding to RLP.
  return concat(compact, Uint8Array.of(sig.recovery & 1));
}

// -------- Cosmos (bech32 `cosmos1…`) --------
function cosmosAddress() {
  const h160 = ripemd160(sha256(SECP_PUBKEY_COMPRESSED));
  return bech32.encode('cosmos', bech32.toWords(h160));
}

// -------- Tron (Base58Check `T…`, Keccak message prefix) --------
function tronAddress() {
  const body = SECP_PUBKEY_UNCOMPRESSED.slice(1);
  const hash = keccak_256(body);
  const payload = concat(Uint8Array.of(0x41), hash.slice(12));
  return base58check(payload);
}

function tronSignMessage(message) {
  const prefix = new TextEncoder().encode(
    `\x19TRON Signed Message:\n${message.length}`,
  );
  const digest = keccak_256(concat(prefix, message));
  const sig = secp256k1.sign(digest, SECP, { lowS: true });
  return concat(sig.toBytes('compact'), Uint8Array.of(27 + (sig.recovery & 1)));
}

function tronSignTransaction(tx) {
  const digest = sha256(tx);
  const sig = secp256k1.sign(digest, SECP, { lowS: true });
  return concat(sig.toBytes('compact'), Uint8Array.of(sig.recovery & 1));
}

// -------- Filecoin (`f1…` protocol-1 address) --------
function filAddress() {
  const payload = blake2b(SECP_PUBKEY_UNCOMPRESSED, { dkLen: 20 });
  const checksumInput = concat(Uint8Array.of(0x01), payload);
  const checksum = blake2b(checksumInput, { dkLen: 4 });
  const encoded = base32LowerNoPad(concat(payload, checksum));
  return `f1${encoded}`;
}

function filSignOverBlake2b(payload) {
  const digest = blake2b(payload, { dkLen: 32 });
  const sig = secp256k1.sign(digest, SECP, { lowS: true });
  return concat(sig.toBytes('compact'), Uint8Array.of(sig.recovery & 1));
}

// -------- XRPL (classic `r…`, STX prefix + SHA-512/2 + DER) --------
const STX_PREFIX = new Uint8Array([0x53, 0x54, 0x58, 0x00]);

// XRP Ledger uses its own base58 alphabet — same characters as Bitcoin but
// reordered so that account addresses begin with `r`.
const XRP_ALPHABET =
  'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

function xrpBase58Check(payload) {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  const full = concat(payload, checksum);
  // Manual base58 with the XRP alphabet.
  let n = 0n;
  for (const b of full) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    const idx = Number(n % 58n);
    out = XRP_ALPHABET[idx] + out;
    n /= 58n;
  }
  // Preserve leading zero bytes as the alphabet's first character (`r`).
  for (const b of full) {
    if (b !== 0) break;
    out = XRP_ALPHABET[0] + out;
  }
  return out;
}

function xrplAddress() {
  const h160 = ripemd160(sha256(SECP_PUBKEY_COMPRESSED));
  return xrpBase58Check(concat(Uint8Array.of(0x00), h160));
}

function xrplSignTransaction(tx) {
  const full = sha512(concat(STX_PREFIX, tx));
  const digest = full.slice(0, 32);
  return secp256k1.sign(digest, SECP, { lowS: true }).toBytes('der');
}

// -------- Solana (Base58 pubkey address) --------
function svmAddress() {
  return base58.encode(ED25519_PUB);
}

// -------- Sui (address = blake2b_256(0x00 || pk), intent-based signing) --------
const SUI_TX_INTENT = new Uint8Array([0x00, 0x00, 0x00]);
const SUI_MSG_INTENT = new Uint8Array([0x03, 0x00, 0x00]);
const SUI_ED25519_FLAG = 0x00;

function suiAddress() {
  const hash = blake2b(
    concat(Uint8Array.of(SUI_ED25519_FLAG), ED25519_PUB),
    { dkLen: 32 },
  );
  return `0x${hex(hash)}`;
}

function suiSignMessage(message) {
  const bcs = concat(uleb128(message.length), message);
  const digest = blake2b(concat(SUI_MSG_INTENT, bcs), { dkLen: 32 });
  return ed25519.sign(digest, fromHex(ED25519_KEY_HEX));
}

function suiSignTransaction(tx) {
  const digest = blake2b(concat(SUI_TX_INTENT, tx), { dkLen: 32 });
  return ed25519.sign(digest, fromHex(ED25519_KEY_HEX));
}

// -------- Aptos (SHA3-256(pk || 0x00) address) --------
const APTOS_ED25519_SCHEME = 0x00;
const APTOS_RAW_TX_DOMAIN = new TextEncoder().encode('APTOS::RawTransaction');

function aptosAddress() {
  const hash = sha3_256(concat(ED25519_PUB, Uint8Array.of(APTOS_ED25519_SCHEME)));
  return `0x${hex(hash)}`;
}

function aptosSignTransaction(tx) {
  const prefix = sha3_256(APTOS_RAW_TX_DOMAIN);
  const msg = concat(prefix, tx);
  return ed25519.sign(msg, fromHex(ED25519_KEY_HEX));
}

// -------- Nostr (BIP-340 Schnorr, NIP-01 event signing) --------
function nostrNpub() {
  return bech32.encode('npub', bech32.toWords(SCHNORR_XONLY));
}
function nostrNsec() {
  return bech32.encode('nsec', bech32.toWords(fromHex(SCHNORR_KEY_HEX)));
}

function nostrSignTransaction(serializedEvent) {
  const eventId = sha256(serializedEvent);
  return schnorrSign(SCHNORR_KEY_HEX, eventId);
}

// -------------------- Emit Rust golden file --------------------

const goldens = {
  // === Shared ===
  secp_key_hex: SECP_KEY_HEX,
  ed25519_key_hex: ED25519_KEY_HEX,
  schnorr_key_hex: SCHNORR_KEY_HEX,
  secp_pubkey_compressed_hex: hex(SECP_PUBKEY_COMPRESSED),
  ed25519_pubkey_hex: hex(ED25519_PUB),
  schnorr_xonly_hex: hex(SCHNORR_XONLY),

  test_digest_hex: hex(TEST_DIGEST),
  test_message_hex: hex(TEST_MESSAGE),
  test_message_utf8: new TextDecoder().decode(TEST_MESSAGE),
  test_tx_hex: hex(TEST_TX),

  // === Common ECDSA primitives on the shared key ===
  secp_sign_hash_hex: hex(ecdsaSignRecoverable(SECP_KEY_HEX, TEST_DIGEST)),
  secp_sign_hash_der_hex: hex(ecdsaSignDer(SECP_KEY_HEX, TEST_DIGEST)),

  // === EVM ===
  evm_address: evmAddress(),
  evm_sign_message_eip191_hex: hex(evmSignMessageEip191(TEST_MESSAGE)),
  evm_sign_transaction_hex: hex(evmSignTransactionKeccak(TEST_TX)),

  // === Bitcoin ===
  btc_address: btcAddress(),
  btc_message_digest_hex: hex(btcMessageDigest(TEST_MESSAGE)),
  btc_sign_message_p2pkh_uncompressed_hex: hex(btcSignMessageBip137(TEST_MESSAGE, 27)),
  btc_sign_message_p2pkh_compressed_hex: hex(btcSignMessageBip137(TEST_MESSAGE, 31)),
  btc_sign_message_segwit_p2sh_hex: hex(btcSignMessageBip137(TEST_MESSAGE, 35)),
  btc_sign_message_segwit_bech32_hex: hex(btcSignMessageBip137(TEST_MESSAGE, 39)),
  btc_sign_transaction_hex: (() => {
    const digest = sha256(sha256(TEST_TX));
    const sig = secp256k1.sign(digest, SECP, { lowS: true });
    return hex(concat(sig.toBytes('compact'), Uint8Array.of(sig.recovery & 1)));
  })(),

  // === Cosmos ===
  cosmos_address: cosmosAddress(),
  cosmos_sign_transaction_hex: (() => {
    const digest = sha256(TEST_TX);
    const sig = secp256k1.sign(digest, SECP, { lowS: true });
    return hex(concat(sig.toBytes('compact'), Uint8Array.of(sig.recovery & 1)));
  })(),

  // === Tron ===
  tron_address: tronAddress(),
  tron_sign_message_hex: hex(tronSignMessage(TEST_MESSAGE)),
  tron_sign_transaction_hex: hex(tronSignTransaction(TEST_TX)),

  // === Spark (BTC L2 — same primitives as Bitcoin) ===
  spark_address: btcAddress(),
  spark_sign_message_hex: hex(btcSignMessageBip137(TEST_MESSAGE, 31)),
  spark_sign_transaction_hex: (() => {
    const digest = sha256(sha256(TEST_TX));
    const sig = secp256k1.sign(digest, SECP, { lowS: true });
    return hex(concat(sig.toBytes('compact'), Uint8Array.of(sig.recovery & 1)));
  })(),

  // === Filecoin ===
  fil_address: filAddress(),
  fil_sign_message_hex: hex(filSignOverBlake2b(TEST_MESSAGE)),
  fil_sign_transaction_hex: hex(filSignOverBlake2b(TEST_TX)),

  // === XRPL ===
  xrpl_address: xrplAddress(),
  xrpl_sign_transaction_der_hex: hex(xrplSignTransaction(TEST_TX)),

  // === Solana ===
  svm_address: svmAddress(),
  svm_sign_hash_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_DIGEST)),
  svm_sign_message_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_MESSAGE)),
  svm_sign_transaction_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_TX)),

  // === Sui ===
  sui_address: suiAddress(),
  sui_sign_hash_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_DIGEST)),
  sui_sign_message_hex: hex(suiSignMessage(TEST_MESSAGE)),
  sui_sign_transaction_hex: hex(suiSignTransaction(TEST_TX)),
  sui_bcs_message_hex: hex(concat(uleb128(TEST_MESSAGE.length), TEST_MESSAGE)),

  // === TON ===
  // Address is the raw hex pubkey; all sign variants are raw Ed25519.
  ton_address_hex: hex(ED25519_PUB),
  ton_sign_hash_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_DIGEST)),
  ton_sign_message_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_MESSAGE)),
  ton_sign_transaction_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_TX)),

  // === Aptos ===
  aptos_address: aptosAddress(),
  aptos_raw_tx_domain_hash_hex: hex(sha3_256(APTOS_RAW_TX_DOMAIN)),
  aptos_sign_hash_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_DIGEST)),
  aptos_sign_message_hex: hex(ed25519Sign(ED25519_KEY_HEX, TEST_MESSAGE)),
  aptos_sign_transaction_hex: hex(aptosSignTransaction(TEST_TX)),

  // === Nostr ===
  nostr_npub: nostrNpub(),
  nostr_nsec: nostrNsec(),
  nostr_sign_hash_hex: hex(schnorrSign(SCHNORR_KEY_HEX, TEST_DIGEST)),
  nostr_sign_message_hex: hex(schnorrSign(SCHNORR_KEY_HEX, TEST_MESSAGE)),
  nostr_sign_transaction_hex: hex(nostrSignTransaction(TEST_TX)),
};

function rustIdent(key) {
  return key.toUpperCase();
}

function renderRust(g) {
  const lines = [
    '// AUTO-GENERATED by `tests/goldens/generate.mjs`. Do not edit.',
    '//',
    '// Every value in this file is produced by an independent mature JS',
    '// cryptography library (`@noble/curves`, `@noble/hashes`, `@scure/base`).',
    '// The Rust test suite then asserts byte-for-byte equality, giving us',
    '// true cross-implementation Known Answer Tests rather than',
    '// self-confirming output dumps.',
    '//',
    '// Consumers `include!` this file inside an `mod goldens { … }` wrapper',
    '// that is itself marked `#[allow(dead_code)]` — not every chain uses',
    '// every constant.',
    '',
  ];
  for (const [k, v] of Object.entries(g)) {
    lines.push(`pub const ${rustIdent(k)}: &str = ${JSON.stringify(v)};`);
  }
  return `${lines.join('\n')}\n`;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const outPath = join(__dirname, 'vectors.rs');
writeFileSync(outPath, renderRust(goldens));
writeFileSync(join(__dirname, 'vectors.json'), JSON.stringify(goldens, null, 2));

console.log(`wrote ${Object.keys(goldens).length} golden vectors to:`);
console.log(`  ${outPath}`);
console.log(`  ${outPath.replace(/\.rs$/, '.json')}`);
