import { ethers, UnsignedTransaction } from "ethers";
import { getPublicKey, getEthereumAddress, requestKmsSignature, determineCorrectV } from "./util/aws-kms-utils";
import {
  MessageTypes,
  SignTypedDataVersion,
  TypedDataV1,
  TypedMessage,
  typedSignatureHash,
  TypedDataUtils,
} from "@metamask/eth-sig-util";
import { validateVersion } from "./util/signature-utils";
import { bufferToHex } from "ethereumjs-util";
export interface AwsKmsSignerCredentials {
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  region: string;
  keyId: string;
}
export class AwsKmsSigner extends ethers.Signer {
  kmsCredentials: AwsKmsSignerCredentials;

  ethereumAddress: string;

  constructor(kmsCredentials: AwsKmsSignerCredentials, provider?: ethers.providers.Provider) {
    super();
    ethers.utils.defineReadOnly(this, "provider", provider || null);
    ethers.utils.defineReadOnly(this, "kmsCredentials", kmsCredentials);
  }

  async getAddress(): Promise<string> {
    if (this.ethereumAddress === undefined) {
      const key = await getPublicKey(this.kmsCredentials);
      this.ethereumAddress = getEthereumAddress(key.PublicKey as Buffer);
    }
    return Promise.resolve(this.ethereumAddress);
  }

  async _signDigest(digestString: string): Promise<string> {
    const digestBuffer = Buffer.from(ethers.utils.arrayify(digestString));
    const sig = await requestKmsSignature(digestBuffer, this.kmsCredentials);
    const ethAddr = await this.getAddress();
    const { v } = determineCorrectV(digestBuffer, sig.r, sig.s, ethAddr);
    return ethers.utils.joinSignature({
      v,
      r: `0x${sig.r.toString("hex")}`,
      s: `0x${sig.s.toString("hex")}`,
    });
  }

  async signMessage(message: string | ethers.utils.Bytes): Promise<string> {
    return this._signDigest(ethers.utils.hashMessage(message));
  }
  /**
   * Original implementation takes into account the private key, but here we use the private
   * key from the GCP KMS, so we don't need to provide the PK as signature option.
   * Source code: https://github.com/MetaMask/eth-sig-util/blob/main/src/sign-typed-data.ts#L510
   * .
   * Sign typed data according to EIP-712. The signing differs based upon the `version`.
   *
   * V1 is based upon [an early version of EIP-712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca)
   * that lacked some later security improvements, and should generally be neglected in favor of
   * later versions.
   *
   * V3 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), except that arrays and
   * recursive data structures are not supported.
   *
   * V4 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), and includes full support of
   * arrays and recursive data structures.
   *
   * @param options - The signing options.
   * @param options.data - The typed data to sign.
   * @param options.version - The signing version to use.
   * @returns The '0x'-prefixed hex encoded signature.
   */
   async signTypedData<V extends SignTypedDataVersion, T extends MessageTypes>({
    data,
    version,
  }: {
    data: V extends "V1" ? TypedDataV1 : TypedMessage<T>;
    version: V;
  }): Promise<string> {
    validateVersion(version);

    if (data === null || data === undefined) {
      throw new Error("Missing data parameter");
    }

    let messageSignature: Promise<string>;
    if (version === SignTypedDataVersion.V1) {
      messageSignature = this._signDigest(typedSignatureHash(data as TypedDataV1));
    } else {
      const eip712Hash: Buffer = TypedDataUtils.eip712Hash(
        data as TypedMessage<T>,
        version as SignTypedDataVersion.V3 | SignTypedDataVersion.V4
      );
      messageSignature = this._signDigest(bufferToHex(eip712Hash));
    }
    return messageSignature;
  }

  async signTransaction(transaction: ethers.utils.Deferrable<ethers.providers.TransactionRequest>): Promise<string> {
    const unsignedTx = await ethers.utils.resolveProperties(transaction);
    const serializedTx = ethers.utils.serializeTransaction(<UnsignedTransaction>unsignedTx);
    const transactionSignature = await this._signDigest(ethers.utils.keccak256(serializedTx));
    return ethers.utils.serializeTransaction(<UnsignedTransaction>unsignedTx, transactionSignature);
  }

  connect(provider: ethers.providers.Provider): AwsKmsSigner {
    return new AwsKmsSigner(this.kmsCredentials, provider);
  }
}
