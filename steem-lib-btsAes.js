// https://code.google.com/p/crypto-js
/*import AES from "crypto-js/aes";
import encHex from "crypto-js/enc-hex";
import encBase64 from "crypto-js/enc-base64";
import assert from "assert";
import {Long} from "bytebuffer";
import { sha256, sha512 } from './hash';*/

var CryptoJS = require('crypto-js');
var AES = CryptoJS.AES;
var encHex = CryptoJS.enc.Hex;
var encBase64 = CryptoJS.enc.Base64;
var assert = require('assert');
var Long = require('bytebuffer');
var hash = require('./hash');
var PrivateKey = require('./privateKey')
var config = require('./chainConfig');
var secureRandom = require('secure-random');

var unique_nonce_entropy = null;

/** Provides symetric encrypt and decrypt via AES. */
class btsAes {

    /** @private */
    constructor(iv, key) { this.iv = iv, this.key = key; }

    /** This is an excellent way to ensure that all references to Aes can not operate anymore (example: a wallet becomes locked).  An application should ensure there is only one Aes object instance for a given secret `seed`. */
    clear() { return this.iv = this.key = undefined; }

    /** @arg {string} seed - secret seed may be used to encrypt or decrypt. */
    static fromSeed(seed) {
        if (seed === undefined) { throw new Error("seed is required"); }
        var _hash = hash.sha512(seed);
        _hash = _hash.toString('hex');
        // DEBUG console.log('... fromSeed _hash',_hash)
        return btsAes.fromSha512(_hash);
    };

    /** @arg {string} hash - A 128 byte hex string, typically one would call {@link fromSeed} instead. */
    static fromSha512(hash) {
        assert.equal(hash.length, 128, `A Sha512 in HEX should be 128 characters long, instead got ${hash.length}`);
        var iv = encHex.parse(hash.substring(64, 96));
        var key = encHex.parse(hash.substring(0, 64));
        return new btsAes(iv, key);
    };

    static fromBuffer(buf) {
        assert(Buffer.isBuffer(buf), "Expecting Buffer")
        assert.equal(buf.length, 64, `A Sha512 Buffer should be 64 characters long, instead got ${buf.length}`);
        return btsAes.fromSha512( buf.toString("hex") )
    };

    static unique_nonce_uint64() {
        var entropy = unique_nonce_entropy = ((() => {
    
                if (unique_nonce_entropy === null) {
                    //console.log('... secureRandom.randomUint8Array(1)[0]',secureRandom.randomUint8Array(1)[0])
                    return parseInt(secureRandom.randomUint8Array(1)[0]);
                } else {
                    return ++unique_nonce_entropy % 256;
                }
        })()
        );
        var long = Long.Long.fromNumber(Date.now());
        //console.log('unique_nonce_uint64 date\t',ByteBuffer.allocate(8).writeUint64(long).toHex(0))
        //console.log('unique_nonce_uint64 entropy\t',ByteBuffer.allocate(8).writeUint64(Long.fromNumber(entropy)).toHex(0))
        long = long.shiftLeft(8).or(Long.Long.fromNumber(entropy));
        //console.log('unique_nonce_uint64 shift8\t',ByteBuffer.allocate(8).writeUint64(long).toHex(0))
        return long.toString();
    };

    static encryptBTSmemo(private_key, memoToPubKey, memo, usePrefix) {
        const prv_chain = Steem.config.address_prefix;
        if (!usePrefix) usePrefix = prv_chain;
        var memo_object = null;
        try {
            Steem.config.address_prefix = usePrefix;
            private_key = btsAes.toPrivateObj(private_key);
            const memoFromPubKey = private_key.toPublicKey().toString();
            const nonce = btsAes.unique_nonce_uint64();
            const message = btsAes.encrypt_with_checksum(private_key, memoToPubKey, nonce, memo).toString('hex');
            memo_object = { from: memoFromPubKey, 
                            to: memoToPubKey, 
                            nonce: nonce, 
                            message: message 
                          };
        } catch (e) { console.log(e); }
        Steem.config.address_prefix = prv_chain;
        return memo_object;
    }

    static decryptBTSmemo(private_key, memo, usePrefix) {
        const prv_chain = Steem.config.address_prefix;
        if (!usePrefix) usePrefix = prv_chain;
        var msg = "";
        try {
            if (typeof memo != "object") memo = JSON.parse(memo);
            msg = memo.message;
            private_key = btsAes.toPrivateObj(private_key);
            if (!private_key) throw new TypeError('private_key is required');
            Steem.config.address_prefix = usePrefix;
            const pubkey = private_key.toPublicKey().toString();
            const otherpub = pubkey === memo.from.toString() ? memo.to.toString() : memo.from.toString();
            msg = btsAes.decrypt_with_checksum(private_key, otherpub, memo.nonce, memo.message).toString();
        } catch (e) { console.log(e); }
        Steem.config.address_prefix = prv_chain;
        return msg;
      }
      
    /**
        @throws {Error} - "Invalid Key, ..."
        @arg {PrivateKey} private_key - required and used for decryption
        @arg {PublicKey} public_key - required and used to calcualte the shared secret
        @arg {string} [nonce = ""] optional but should always be provided and be unique when re-using the same private/public keys more than once.  This nonce is not a secret.
        @arg {string|Buffer} message - Encrypted message containing a checksum
        @return {Buffer}
    */
    static decrypt_with_checksum(private_key, public_key, nonce, message, legacy = false) {

        // Warning: Do not put `nonce = ""` in the arguments, in es6 this will not convert "null" into an emtpy string
        if( nonce == null ) // null or undefined
            nonce = ""

        if (!Buffer.isBuffer(message)) {
            message = new Buffer(message, 'hex');
        }

        private_key = btsAes.toPrivateObj(private_key)
        if (!private_key) throw new TypeError('private_key is required')
    
        var S = private_key.get_shared_secret(public_key, legacy);
        // D E B U G
        // console.log('decrypt_with_checksum', {
        //     priv_to_pub: private_key.toPublicKey().toString(),
        //     pub: public_key.toPublicKeyString(),
        //     nonce: nonce,
        //     message: message.length,
        //     S: S.toString('hex')
        // })

        var aes = btsAes.fromSeed(Buffer.concat([
            // A null or empty string nonce will not effect the hash
            new Buffer(""+nonce),
            new Buffer(S.toString('hex'))
        ]))

        var planebuffer = aes.decrypt(message);
        if (!(planebuffer.length >= 4)) {
            throw new Error("Invalid key, could not decrypt message(1)");
        }

        // DEBUG console.log('... planebuffer',planebuffer)
        var checksum = planebuffer.slice(0, 4);
        var plaintext = planebuffer.slice(4);

        // console.log('... checksum',checksum.toString('hex'))
        // console.log('... plaintext',plaintext.toString())

        var new_checksum = hash.sha256(plaintext);
        new_checksum = new_checksum.slice(0, 4);
        new_checksum = new_checksum.toString('hex');

        if (!(checksum.toString('hex') === new_checksum)) {
            throw new Error("Invalid key, could not decrypt message(2)");
        }

        return plaintext;
    };

    /** Identical to {@link decrypt_with_checksum} but used to encrypt.  Should not throw an error.
        @return {Buffer} message - Encrypted message which includes a checksum
    */
    static encrypt_with_checksum(private_key, public_key, nonce, message) {

        // Warning: Do not put `nonce = ""` in the arguments, in es6 this will not convert "null" into an emtpy string

        if( nonce == null) // null or undefined
            nonce = ""

        if (!Buffer.isBuffer(message)) {
            message = new Buffer(message, 'binary');
        }

        private_key = btsAes.toPrivateObj(private_key)
        if (!private_key) throw new TypeError('private_key is required')
            
        var S = private_key.get_shared_secret(public_key);

        // D E B U G
        // console.log('encrypt_with_checksum', {
        //     priv_to_pub: private_key.toPublicKey().toString()
        //     pub: public_key.toPublicKeyString()
        //     nonce: nonce
        //     message: message.length
        //     S: S.toString('hex')
        // })

        var aes = btsAes.fromSeed(Buffer.concat([
            // A null or empty string nonce will not effect the hash
            new Buffer(""+nonce),
            new Buffer(S.toString('hex'))
        ]));
        // DEBUG console.log('... S',S.toString('hex'))
        var checksum = hash.sha256(message).slice(0,4);
        var payload = Buffer.concat([checksum, message]);
        // DEBUG console.log('... payload',payload.toString())
        return aes.encrypt(payload);
    };

    /** @private */
    _decrypt_word_array(cipher) {
        // https://code.google.com/p/crypto-js/#Custom_Key_and_IV
        // see wallet_records.cpp master_key::decrypt_key
        return AES.decrypt({ ciphertext: cipher, salt: null}, this.key, {iv: this.iv});
    }

    /** @private */
    _encrypt_word_array(plaintext) {
        //https://code.google.com/p/crypto-js/issues/detail?id=85
        var cipher = AES.encrypt(plaintext, this.key, {iv: this.iv});
        return encBase64.parse(cipher.toString());
    }

    /** This method does not use a checksum, the returned data must be validated some other way.
        @arg {string} ciphertext
        @return {Buffer} binary
    */
    decrypt(ciphertext) {
        if (typeof ciphertext === "string") {
            ciphertext = new Buffer(ciphertext, 'binary');
        }
        if (!Buffer.isBuffer(ciphertext)) {
            throw new Error("buffer required");
        }
        assert(ciphertext, "Missing cipher text");
        // hex is the only common format
        var hex = this.decryptHex(ciphertext.toString('hex'));
        return new Buffer(hex, 'hex');
    }

    /** This method does not use a checksum, the returned data must be validated some other way.
        @arg {string} plaintext
        @return {Buffer} binary
    */
    encrypt(plaintext) {
        if (typeof plaintext === "string") {
            plaintext = new Buffer(plaintext, 'binary');
        }
        if (!Buffer.isBuffer(plaintext)) {
            throw new Error("buffer required");
        }
        //assert plaintext, "Missing plain text"
        // hex is the only common format
        var hex = this.encryptHex(plaintext.toString('hex'));
        return new Buffer(hex, 'hex');
    }

    /** This method does not use a checksum, the returned data must be validated some other way.
        @arg {string|Buffer} plaintext
        @return {string} hex
    */
    encryptToHex(plaintext) {
        if (typeof plaintext === "string") {
            plaintext = new Buffer(plaintext, 'binary');
        }
        if (!Buffer.isBuffer(plaintext)) {
            throw new Error("buffer required");
        }
        //assert plaintext, "Missing plain text"
        // hex is the only common format
        return this.encryptHex(plaintext.toString('hex'));
    }

    /** This method does not use a checksum, the returned data must be validated some other way.
        @arg {string} cipher - hex
        @return {string} binary (could easily be readable text)
    */
    decryptHex(cipher) {
        assert(cipher, "Missing cipher text");
        // Convert data into word arrays (used by Crypto)
        var cipher_array = encHex.parse(cipher);
        var plainwords = this._decrypt_word_array(cipher_array);
        return encHex.stringify(plainwords);
    }

    /** This method does not use a checksum, the returned data must be validated some other way.
        @arg {string} cipher - hex
        @return {Buffer} encoded as specified by the parameter
    */
    decryptHexToBuffer(cipher) {
        assert(cipher, "Missing cipher text");
        // Convert data into word arrays (used by Crypto)
        var cipher_array = encHex.parse(cipher);
        var plainwords = this._decrypt_word_array(cipher_array);
        var plainhex = encHex.stringify(plainwords);
        return new Buffer(plainhex, 'hex');
    }

    /** This method does not use a checksum, the returned data must be validated some other way.
        @arg {string} cipher - hex
        @arg {string} [encoding = 'binary'] - a valid Buffer encoding
        @return {String} encoded as specified by the parameter
    */
    decryptHexToText(cipher, encoding = 'binary') {
        return this.decryptHexToBuffer(cipher).toString(encoding);
    }

    /** This method does not use a checksum, the returned data must be validated some other way.
        @arg {string} plainhex - hex format
        @return {String} hex
    */
    encryptHex(plainhex) {
        var plain_array = encHex.parse(plainhex);
        var cipher_array = this._encrypt_word_array(plain_array);
        return encHex.stringify(cipher_array);
    }

    static toPrivateObj(o) { return o ? o.d ? o : PrivateKey.fromWif(o) : o }

}

module.exports = btsAes;
