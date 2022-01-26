"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.AwsKmsSigner = void 0;

var _ethers = require("ethers");

var _awsKmsUtils = require("./util/aws-kms-utils");

var _ethSigUtil = require("@metamask/eth-sig-util");

var _signatureUtils = require("./util/signature-utils");

var _ethereumjsUtil = require("ethereumjs-util");

function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { Promise.resolve(value).then(_next, _throw); } }

function _asyncToGenerator(fn) { return function () { var self = this, args = arguments; return new Promise(function (resolve, reject) { var gen = fn.apply(self, args); function _next(value) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value); } function _throw(err) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err); } _next(undefined); }); }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class AwsKmsSigner extends _ethers.ethers.Signer {
  constructor(kmsCredentials, provider) {
    super();

    _defineProperty(this, "kmsCredentials", void 0);

    _defineProperty(this, "ethereumAddress", void 0);

    _ethers.ethers.utils.defineReadOnly(this, "provider", provider || null);

    _ethers.ethers.utils.defineReadOnly(this, "kmsCredentials", kmsCredentials);
  }

  getAddress() {
    var _this = this;

    return _asyncToGenerator(function* () {
      if (_this.ethereumAddress === undefined) {
        const key = yield (0, _awsKmsUtils.getPublicKey)(_this.kmsCredentials);
        _this.ethereumAddress = (0, _awsKmsUtils.getEthereumAddress)(key.PublicKey);
      }

      return Promise.resolve(_this.ethereumAddress);
    })();
  }

  _signDigest(digestString) {
    var _this2 = this;

    return _asyncToGenerator(function* () {
      const digestBuffer = Buffer.from(_ethers.ethers.utils.arrayify(digestString));
      const sig = yield (0, _awsKmsUtils.requestKmsSignature)(digestBuffer, _this2.kmsCredentials);
      const ethAddr = yield _this2.getAddress();

      const _determineCorrectV = (0, _awsKmsUtils.determineCorrectV)(digestBuffer, sig.r, sig.s, ethAddr),
            v = _determineCorrectV.v;

      return _ethers.ethers.utils.joinSignature({
        v,
        r: `0x${sig.r.toString("hex")}`,
        s: `0x${sig.s.toString("hex")}`
      });
    })();
  }

  signMessage(message) {
    var _this3 = this;

    return _asyncToGenerator(function* () {
      return _this3._signDigest(_ethers.ethers.utils.hashMessage(message));
    })();
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


  signTypedData({
    data,
    version
  }) {
    var _this4 = this;

    return _asyncToGenerator(function* () {
      (0, _signatureUtils.validateVersion)(version);

      if (data === null || data === undefined) {
        throw new Error("Missing data parameter");
      }

      let messageSignature;

      if (version === _ethSigUtil.SignTypedDataVersion.V1) {
        messageSignature = _this4._signDigest((0, _ethSigUtil.typedSignatureHash)(data));
      } else {
        const eip712Hash = _ethSigUtil.TypedDataUtils.eip712Hash(data, version);

        messageSignature = _this4._signDigest((0, _ethereumjsUtil.bufferToHex)(eip712Hash));
      }

      return messageSignature;
    })();
  }

  signTransaction(transaction) {
    var _this5 = this;

    return _asyncToGenerator(function* () {
      const unsignedTx = yield _ethers.ethers.utils.resolveProperties(transaction);

      const serializedTx = _ethers.ethers.utils.serializeTransaction(unsignedTx);

      const transactionSignature = yield _this5._signDigest(_ethers.ethers.utils.keccak256(serializedTx));
      return _ethers.ethers.utils.serializeTransaction(unsignedTx, transactionSignature);
    })();
  }

  connect(provider) {
    return new AwsKmsSigner(this.kmsCredentials, provider);
  }

}

exports.AwsKmsSigner = AwsKmsSigner;