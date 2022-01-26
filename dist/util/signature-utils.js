"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.validateVersion = validateVersion;
exports.recoverTypedSignature = recoverTypedSignature;

var _ethSigUtil = require("@metamask/eth-sig-util");

var _utils = require("@metamask/eth-sig-util/dist/utils");

var _ethereumjsUtil = require("ethereumjs-util");

/**
 * Validate that the given value is a valid version string.
 *
 * @param version - The version value to validate.
 * @param allowedVersions - A list of allowed versions. If omitted, all versions are assumed to be
 * allowed.
 */
function validateVersion(version, allowedVersions) {
  if (!Object.keys(_ethSigUtil.SignTypedDataVersion).includes(version)) {
    throw new Error(`Invalid version: '${version}'`);
  } else if (allowedVersions && !allowedVersions.includes(version)) {
    throw new Error(`SignTypedDataVersion not allowed: '${version}'. Allowed versions are: ${allowedVersions.join(", ")}`);
  }
}
/**
 * Recover the address of the account that created the given EIP-712
 * signature. The version provided must match the version used to
 * create the signature.
 *
 * @param options - The signature recovery options.
 * @param options.data - The typed data that was signed.
 * @param options.signature - The '0x-prefixed hex encoded message signature.
 * @param options.version - The signing version to use.
 * @returns The '0x'-prefixed hex address of the signer.
 */


function recoverTypedSignature({
  data,
  signature,
  version
}) {
  validateVersion(version);

  if (data === null || data === undefined) {
    throw new Error("Missing data parameter");
  } else if (signature === null || signature === undefined) {
    throw new Error("Missing signature parameter");
  }

  let messageHash;

  if (version === _ethSigUtil.SignTypedDataVersion.V1) {
    messageHash = Buffer.from((0, _ethSigUtil.typedSignatureHash)(data));
  } else {
    messageHash = _ethSigUtil.TypedDataUtils.eip712Hash(data, version);
  }

  const publicKey = (0, _utils.recoverPublicKey)(messageHash, signature);
  const sender = (0, _ethereumjsUtil.publicToAddress)(publicKey);
  return (0, _ethereumjsUtil.bufferToHex)(sender);
}