"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.sign = sign;
exports.getPublicKey = getPublicKey;
exports.getEthereumAddress = getEthereumAddress;
exports.findEthereumSig = findEthereumSig;
exports.requestKmsSignature = requestKmsSignature;
exports.determineCorrectV = determineCorrectV;

var _ethers = require("ethers");

var _awsSdk = require("aws-sdk");

var asn1 = _interopRequireWildcard(require("asn1.js"));

var _bn = _interopRequireDefault(require("bn.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function _getRequireWildcardCache(nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { Promise.resolve(value).then(_next, _throw); } }

function _asyncToGenerator(fn) { return function () { var self = this, args = arguments; return new Promise(function (resolve, reject) { var gen = fn.apply(self, args); function _next(value) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value); } function _throw(err) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err); } _next(undefined); }); }; }

/* this asn1.js library has some funky things going on */

/* eslint-disable func-names */
const EcdsaSigAsnParse = asn1.define("EcdsaSig", function () {
  // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
  this.seq().obj(this.key("r").int(), this.key("s").int());
});
const EcdsaPubKey = asn1.define("EcdsaPubKey", function () {
  // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
  this.seq().obj(this.key("algo").seq().obj(this.key("a").objid(), this.key("b").objid()), this.key("pubKey").bitstr());
});
/* eslint-enable func-names */

function sign(_x, _x2) {
  return _sign.apply(this, arguments);
}

function _sign() {
  _sign = _asyncToGenerator(function* (digest, kmsCredentials) {
    const kms = new _awsSdk.KMS(kmsCredentials);
    const params = {
      // key id or 'Alias/<alias>'
      KeyId: kmsCredentials.keyId,
      Message: digest,
      // 'ECDSA_SHA_256' is the one compatible with ECC_SECG_P256K1.
      SigningAlgorithm: "ECDSA_SHA_256",
      MessageType: "DIGEST"
    };
    const res = yield kms.sign(params).promise();
    return res;
  });
  return _sign.apply(this, arguments);
}

function getPublicKey(_x3) {
  return _getPublicKey.apply(this, arguments);
}

function _getPublicKey() {
  _getPublicKey = _asyncToGenerator(function* (kmsCredentials) {
    const kms = new _awsSdk.KMS(kmsCredentials);
    return kms.getPublicKey({
      KeyId: kmsCredentials.keyId
    }).promise();
  });
  return _getPublicKey.apply(this, arguments);
}

function getEthereumAddress(publicKey) {
  // The public key is ASN1 encoded in a format according to
  // https://tools.ietf.org/html/rfc5480#section-2
  // I used https://lapo.it/asn1js to figure out how to parse this
  // and defined the schema in the EcdsaPubKey object
  const res = EcdsaPubKey.decode(publicKey, "der");
  let pubKeyBuffer = res.pubKey.data; // The public key starts with a 0x04 prefix that needs to be removed
  // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html

  pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length);

  const address = _ethers.ethers.utils.keccak256(pubKeyBuffer); // keccak256 hash of publicKey


  const EthAddr = `0x${address.slice(-40)}`; // take last 20 bytes as ethereum adress

  return EthAddr;
}

function findEthereumSig(signature) {
  const decoded = EcdsaSigAsnParse.decode(signature, "der");
  const r = decoded.r,
        s = decoded.s;
  const secp256k1N = new _bn.default("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16); // max value on the curve

  const secp256k1halfN = secp256k1N.div(new _bn.default(2)); // half of the curve
  // Because of EIP-2 not all elliptic curve signatures are accepted
  // the value of s needs to be SMALLER than half of the curve
  // i.e. we need to flip s if it's greater than half of the curve
  // if s is less than half of the curve, we're on the "good" side of the curve, we can just return

  return {
    r,
    s: s.gt(secp256k1halfN) ? secp256k1N.sub(s) : s
  };
}

function requestKmsSignature(_x4, _x5) {
  return _requestKmsSignature.apply(this, arguments);
}

function _requestKmsSignature() {
  _requestKmsSignature = _asyncToGenerator(function* (plaintext, kmsCredentials) {
    const signature = yield sign(plaintext, kmsCredentials);

    if (signature.$response.error || signature.Signature === undefined) {
      throw new Error(`AWS KMS call failed with: ${signature.$response.error}`);
    }

    return findEthereumSig(signature.Signature);
  });
  return _requestKmsSignature.apply(this, arguments);
}

function recoverPubKeyFromSig(msg, r, s, v) {
  return _ethers.ethers.utils.recoverAddress(`0x${msg.toString("hex")}`, {
    r: `0x${r.toString("hex")}`,
    s: `0x${s.toString("hex")}`,
    v
  });
}

function determineCorrectV(msg, r, s, expectedEthAddr) {
  // This is the wrapper function to find the right v value
  // There are two matching signatues on the elliptic curve
  // we need to find the one that matches to our public key
  // it can be v = 27 or v = 28
  let v = 27;
  let pubKey = recoverPubKeyFromSig(msg, r, s, v);

  if (pubKey.toLowerCase() !== expectedEthAddr.toLowerCase()) {
    // if the pub key for v = 27 does not match
    // it has to be v = 28
    v = 28;
    pubKey = recoverPubKeyFromSig(msg, r, s, v);
  }

  return {
    pubKey,
    v
  };
}