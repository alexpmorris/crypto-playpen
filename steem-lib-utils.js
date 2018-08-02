'use strict';
var ecurve = require('ecurve');
var ECDSA = require('./ecdsa');
var PublicKey = require('./publicKey');
var Signature = require('./signature');
var ECSignature = require('./ecsignature');
var Config = require('./chainConfig');
const base58 = require('bs58');
const assert = require('assert');
const hash = require('./hash');

// =====================================================

function verifySignature (hash, pub, sig) {
  if (typeof hash == 'object') {
    var opts = hash;
    hash = opts.hash;
    pub = opts.pubkey;
    sig = opts.signature;
  }

  var c = ecurve.getCurveByName('secp256k1');
  var h = new Buffer(hash, 'hex');
  var p = PublicKey.fromHex(pub).Q;
  var s = ECSignature.fromDER(new Buffer(sig, 'hex'));

  return ECDSA.verify(c, h, s, p);  
}

function verifySteemSignature (tr_buf, pubkey, signature) {
  if (typeof tr_buf == 'object') {
    var opts = tr_buf;
    tr_buf = opts.tr_buf;
    pubkey = opts.pubkey;
    signature = opts.signature;
  }
  
  if (typeof tr_buf == 'string') tr_buf = new Buffer(tr_buf, 'hex');
  if (typeof pubkey == 'string') pubkey = PublicKey.fromString(pubkey)
  if (typeof signature == 'string') signature = Signature.fromHex(signature);

  var chain_id = Config.networks.Steem.chain_id;
  tr_buf = Buffer.concat([new Buffer(chain_id, 'hex'), tr_buf]);

  return signature.verifyBuffer(tr_buf, pubkey);  
}
// ==========================================

function signGrapheneMessage(msg, privateWif) {
  const sigObj = Signature.sign(msg, privateWif);
  return btoa('\x28'+String.fromCharCode.apply(null, sigObj.r.toBuffer())+
                    String.fromCharCode.apply(null, sigObj.s.toBuffer()));
}

function verifyGrapheneMessage(msg, sigBase64, publicKey) {
  try {
    const pubKeyObj = PublicKey.fromString(publicKey);
    const sigBuf = new Buffer('\x21'+atob(sigBase64).substring(1),"ascii");
    const sigObj = Signature.fromBuffer(sigBuf);
    return sigObj.verifyBuffer(msg,pubKeyObj);
  } catch (e) { return false; }
}

// ============================= EOS signing =============================

/**
  @arg {Buffer} keyBuffer data
  @arg {string} keyType = sha256x2, K1, etc
  @return {string} checksum encoded base58 string
*/
function checkEncode(keyBuffer, keyType = null) {
  assert(Buffer.isBuffer(keyBuffer), 'expecting keyBuffer<Buffer>')
  if(keyType === 'sha256x2') { // legacy
    const checksum = hash.sha256(hash.sha256(keyBuffer)).slice(0, 4)
    return base58.encode(Buffer.concat([keyBuffer, checksum]))
  } else {
    const check = [keyBuffer]
    if(keyType) {
        check.push(Buffer.from(keyType))
    }
    const checksum = hash.ripemd160(Buffer.concat(check)).slice(0, 4)
    return base58.encode(Buffer.concat([keyBuffer, checksum]))
  }
}

/**
  @arg {Buffer} keyString data
  @arg {string} keyType = sha256x2, K1, etc
  @return {string} checksum encoded base58 string
*/
function checkDecode(keyString, keyType = null) {
    assert(keyString != null, 'private key expected')
    const buffer = new Buffer(base58.decode(keyString))
    const checksum = buffer.slice(-4)
    const key = buffer.slice(0, -4)

    let newCheck
    if(keyType === 'sha256x2') { // legacy
        newCheck = hash.sha256(hash.sha256(key)).slice(0, 4) // WIF (legacy)
    } else {
      const check = [key]
      if(keyType) {
          check.push(Buffer.from(keyType))
      }
      newCheck = hash.ripemd160(Buffer.concat(check)).slice(0, 4) //PVT
    }

    if (checksum.toString() !== newCheck.toString()) {
        throw new Error('Invalid checksum, ' +
            `${checksum.toString('hex')} != ${newCheck.toString('hex')}`
        )
    }

    return key
}

function signEosMessage(msg, privateWif) {
  const sigObj = Signature.sign(msg, privateWif);
  const sigBuf = sigObj.toBuffer();
  return 'SIG_K1_' + checkEncode(sigBuf, 'K1');
}

function verifyEosMessage(msg, signature, publicKey) {
  try {
    const pubKeyObj = PublicKey.fromString(publicKey);
    assert(typeof signature, 'string', 'signature');
    const match = signature.match(/^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/);
    assert(match != null && match.length === 3, 'Expecting signature like: SIG_K1_bas58signature..');
    const [, sigType, sigString] = match;
    const sigObj = Signature.fromBuffer(checkDecode(sigString, sigType));
    return sigObj.verifyBuffer(msg, pubKeyObj);
  } catch (e) { return false; }
}

module.exports = {
  verifySignature: verifySignature,
  verifySteemSignature: verifySteemSignature,
  signGrapheneMessage: signGrapheneMessage,
  verifyGrapheneMessage: verifyGrapheneMessage,
  signEosMessage: signEosMessage,
  verifyEosMessage: verifyEosMessage
};
