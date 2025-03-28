import * as bip39 from 'bip39';
import { sign } from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { encryptData, decryptData } from './encryption';

//Generate a random mnemonic phrase (12 words)
//const mnemonic = bip39.generateMnemonic();
const mnemonic =
  'fence foil trophy morning crunch dune consider blind coffee frost worry build';
console.log('Mnemonic:', mnemonic);

// Derive the seed from the mnemonic
const seed = bip39.mnemonicToSeedSync(mnemonic);

// Get the corresponding public key
const keyPair = sign.keyPair.fromSeed(seed.slice(0, 32));

// Convert the public key to a hexadecimal string
const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
console.log('Public Key (Hex):', publicKeyHex);

//Convert the public key to a base64 string
const publicKeyB64 = naclUtil.encodeBase64(keyPair.publicKey);
console.log('Public Key (B64):', publicKeyB64);

// const encryptedMnemonic = encryptData(
//   new TextEncoder().encode(mnemonic),
//   'koko',
// );

// encryptedMnemonic.then((enc) => {
//   console.log('encrypted mnemonic', enc);

//   decryptData(enc, 'koko').then((dec) =>
//     console.log(
//       'correct decryption',
//       Buffer.from((dec ?? new Uint8Array([])).buffer).toString(),
//     ),
//   );

//   decryptData(enc, 'kol').then((dec) =>
//     console.log(
//       'wrong decryption',
//       Buffer.from((dec ?? new Uint8Array([])).buffer).toString(),
//     ),
//   );
// });
