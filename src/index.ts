import * as bip39 from 'bip39';
import * as nacl from 'tweetnacl';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';

// Simple HMAC-SHA512 HD key derivation
function deriveHDSeed(
  seed: Uint8Array,
  account: number,
  address: number,
): Uint8Array {
  const label = new TextEncoder().encode('inconsiderable');
  const indexBytes = new Uint8Array([account, address]);
  const input = new Uint8Array([...seed, ...indexBytes]);
  const digest = hmac(sha512, label, input);
  return digest.slice(0, 32); // Ed25519 seeds must be 32 bytes
}

function generateHDKeypair(mnemonic: string, account: number, address: number) {
  const masterSeed = bip39.mnemonicToSeedSync(mnemonic); // returns Buffer
  const derivedSeed = deriveHDSeed(
    new Uint8Array(masterSeed),
    account,
    address,
  );
  const keypair = nacl.sign.keyPair.fromSeed(derivedSeed);
  return {
    path: `m/${account}/${address}`,
    publicKey: Buffer.from(keypair.publicKey).toString('base64'),
    privateKey: Buffer.from(keypair.secretKey).toString('base64'),
  };
}

/**
 * Converts a user-supplied passphrase into a 24-word BIP39 mnemonic
 * using SHA-512 and 256 bits of entropy (first 32 bytes).
 */
function generateMnemonic(passphrase: string): string {
  // Namespaced input: useful for versioning or app isolation
  //const input = `${salt}:${passphrase}`;
  const hash = sha512(utf8ToBytes(passphrase)); // Returns Uint8Array of 64 bytes
  const entropy = hash.slice(0, 32); // 32 bytes = 256 bits = 24 words
  return bip39.entropyToMnemonic(Buffer.from(entropy).toString('hex'));
}

// Example usage
const numAccounts = 2;
const numAddressesPerAccount = 1;

const mnemonic = generateMnemonic('Return of the King');

//console.log('Mnemonic:', mnemonic);
for (let acct = 0; acct < numAccounts; acct++) {
  console.log(`\nAccount ${acct}:`);
  for (let addr = 0; addr < numAddressesPerAccount; addr++) {
    const { path, publicKey } = generateHDKeypair(mnemonic, acct, addr);
    console.log(`  Path: ${path}`);
    console.log(`  Public Key: ${publicKey}`);
    //console.log(`  Private Key: ${privateKey}\n`);
  }
}
