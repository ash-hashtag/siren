import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";

export class SecretKey {
  readonly raw: Uint8Array;
  readonly encryptionKey: CryptoKey;
  readonly hashKey: CryptoKey;

  constructor(raw: Uint8Array, encryptionKey: CryptoKey, hashKey: CryptoKey) {
    this.raw = raw;
    this.encryptionKey = encryptionKey;
    this.hashKey = hashKey;
  }

  static async importRaw(bytes: Uint8Array) {
    const encKey = await crypto.subtle.importKey(
      "raw",
      bytes,
      { name: "AES-CBC" },
      false,
      ["encrypt", "decrypt"],
    );
    const hashKey = await crypto.subtle.importKey(
      "raw",
      bytes,
      { name: "HMAC" },
      false,
      ["sign", "verify"],
    );

    return new SecretKey(bytes, encKey, hashKey);
  }
}

export interface EncryptionAlgorithm {
  encrypt(
    data: Uint8Array<ArrayBufferLike>,
    key: SecretKey,
  ): Promise<EncryptedMessage>;
  decrypt(data: EncryptedMessage, key: SecretKey): Promise<Uint8Array>;
}

export interface KeyPairAlgorithm {}

export interface KeyDerivationFunction {
  derive(key: SecretKey, nonce: Uint8Array): Promise<SecretKey>;
}

export const HKDF: KeyDerivationFunction = {
  derive: function (key: SecretKey, nonce: Uint8Array): Promise<SecretKey> {
    const newKey = hkdf(sha256, key.raw, nonce, undefined, 32);
    return SecretKey.importRaw(newKey);
  },
};

export interface EncryptedMessage {
  iv: Uint8Array;
  cipherText: Uint8Array;
  mac: Uint8Array;
}

export const AES_CBC_HMAC_SHA256: EncryptionAlgorithm = {
  encrypt: async function (
    data: Uint8Array<ArrayBufferLike>,
    key: SecretKey,
  ): Promise<EncryptedMessage> {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const cipherText = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        key.encryptionKey,
        data,
      ),
    );
    const ivAndCipherText = new Uint8Array(iv.length + cipherText.byteLength);
    ivAndCipherText.set(iv, 0);
    ivAndCipherText.set(cipherText, iv.length);
    const mac = new Uint8Array(
      await crypto.subtle.sign("HMAC", key.hashKey, ivAndCipherText),
    );

    return {
      cipherText,
      iv,
      mac,
    };
  },
  decrypt: async function (
    data: EncryptedMessage,
    key: SecretKey,
  ): Promise<Uint8Array> {
    const ivAndCipherText = new Uint8Array(
      data.iv.byteLength + data.cipherText.byteLength,
    );
    ivAndCipherText.set(data.iv, 0);
    ivAndCipherText.set(data.cipherText, data.iv.byteLength);
    const macIsValid = await crypto.subtle.verify(
      "HMAC",
      key.hashKey,
      data.mac,
      ivAndCipherText,
    );
    if (!macIsValid) throw new Error("Invalid MAC!");
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: data.iv },
      key.encryptionKey,
      data.cipherText,
    );

    return new Uint8Array(decrypted);
  },
};

export class DoubleRatchet {
  private senderKey: SecretKey;
  private receiverKey: SecretKey;
  readonly encryptionAlgorithm: EncryptionAlgorithm;
  readonly keyPairAlgorithm: KeyPairAlgorithm;
  readonly keyDeriviationFunction: KeyDerivationFunction;

  constructor(
    senderKey: SecretKey,
    receiverKey: SecretKey,
    encryptionAlgorithm: EncryptionAlgorithm,
    keyPairAlgorithm: KeyPairAlgorithm,
    keyDeriviationFunction: KeyDerivationFunction,
  ) {
    this.senderKey = senderKey;
    this.receiverKey = receiverKey;
    this.encryptionAlgorithm = encryptionAlgorithm;
    this.keyPairAlgorithm = keyPairAlgorithm;
    this.keyDeriviationFunction = keyDeriviationFunction;
  }

  getSenderKey() {
    return this.senderKey;
  }

  getReceiverKey() {
    return this.receiverKey;
  }

  async encrypt(data: Uint8Array) {
    const newSenderKey = await this.keyDeriviationFunction.derive(
      this.senderKey,
      new Uint8Array(),
    );
    const encryptedData = await this.encryptionAlgorithm.encrypt(
      data,
      newSenderKey,
    );
    this.senderKey = newSenderKey;

    return encryptedData;
  }

  async decrypt(data: EncryptedMessage) {
    const newReceiverKey = await this.keyDeriviationFunction.derive(
      this.receiverKey,
      new Uint8Array(),
    );
    const decryptedData = await this.encryptionAlgorithm.decrypt(
      data,
      newReceiverKey,
    );
    this.receiverKey = newReceiverKey;
    return decryptedData;
  }
}
