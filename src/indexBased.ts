import * as bip39 from 'bip39';
import { sha3_256 } from 'js-sha3';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

function generateMnemonic(privateEntropy: string): string {
  // Use a secure hash function (e.g., SHA-256) to hash the private entropy
  const hashedEntropy = sha3_256(privateEntropy);

  //console.log('entropy', hashedEntropy);
  //console.log('length', hashedEntropy.length);

  // Create the mnemonic phrase
  return bip39.entropyToMnemonic(hashedEntropy);
}

//index based deterministic keys
const getMind = async (passphrase: string, count: number) => {
  const mnemonic = generateMnemonic(passphrase);

  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const keypairs = [];

  for (let i = 0; i < count; i++) {
    const derivedSeed = nacl.hash(
      Buffer.concat([seed, Buffer.from(String(i), 'utf-8')]),
    );
    const keyPair = nacl.sign.keyPair.fromSeed(derivedSeed.slice(0, 32));
    keypairs.push({
      publicKey: naclUtil.encodeBase64(keyPair.publicKey),
      privateKey: keyPair.secretKey,
    });
  }

  return keypairs;
};

// Example usage
const privateEntropy = 'Return of the King';
const keys = getMind(privateEntropy, 2);
keys.then((k) => k.map((l) => console.log(l.publicKey)));
