/// <reference types="node" />
import { KMS } from "aws-sdk";
import BN from "bn.js";
import { AwsKmsSignerCredentials } from "../index";
export declare function sign(digest: Buffer, kmsCredentials: AwsKmsSignerCredentials): Promise<import("aws-sdk/lib/request").PromiseResult<KMS.SignResponse, import("aws-sdk").AWSError>>;
export declare function getPublicKey(kmsCredentials: AwsKmsSignerCredentials): Promise<import("aws-sdk/lib/request").PromiseResult<KMS.GetPublicKeyResponse, import("aws-sdk").AWSError>>;
export declare function getEthereumAddress(publicKey: Buffer): string;
export declare function findEthereumSig(signature: Buffer): {
    r: BN;
    s: BN;
};
export declare function requestKmsSignature(plaintext: Buffer, kmsCredentials: AwsKmsSignerCredentials): Promise<{
    r: BN;
    s: BN;
}>;
export declare function determineCorrectV(msg: Buffer, r: BN, s: BN, expectedEthAddr: string): {
    pubKey: string;
    v: number;
};
