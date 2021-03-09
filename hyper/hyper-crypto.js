// https://github.com/mafintosh/hypercore-crypto/blob/master/index.js
// https://research.kudelskisecurity.com/2017/03/06/why-replace-sha-1-with-blake2
// ed25519 WIF secret key format: base58Check(0x90 + 32byteKey + 4byteBlake2b)
// ed25519 public key format: HYP + base58Check(0x91 + 32byteKey + 4byteBlake2b)
// latest version: 20210304 by APM

hyper_utils = {
    sodium: null,
    buffer: null,
    base58: null,
    bigint: null,
    init: function(sodium, buffer, base58, bigint) {
        this.sodium = sodium;
        this.buffer = buffer;
        this.base58 = base58;
        this.bigint = bigint;
        this.check_init();
    },
    check_init: function() {
        if (this.sodium == null || this.buffer == null || this.base58 == null || this.bigint == null) throw new Error("not initialized!");
    },
    fromKeyString(key, keyType) {
        if (!key || (typeof key == 'object')) throw new Error(keyType+'Key as String not provided!');
        if (keyType !== 'public') {
            key = this.base58.decode(key);
            const version = key.readUInt8(0);
            if (version != 0x90) throw new Error('Expected version ' + 0x90 + ', instead got ' + version);
            const raw_key = key.slice(0, -4);
            const key_hash = key.slice(-4);
            let hash = this.sodium.crypto_generichash_instance(raw_key);
            const final_hash = this.buffer.from(hash.final().slice(0,4));
            if (key_hash.toString('hex') !== final_hash.toString('hex'))
                throw new Error('Invalid privateKey (hash miss-match)');
            return raw_key.slice(1);
        } else {
            key = this.base58.decode(key.substring(3));
            const version = key.readUInt8(0);
            if (version != 0x91) throw new Error('Expected version ' + 0x91 + ', instead got ' + version);
            const raw_key = key.slice(0, -4);
            const key_hash = key.slice(-4);
            let hash = this.sodium.crypto_generichash_instance(raw_key);
            const final_hash = this.buffer.from(hash.final().slice(0,4));
            if (key_hash.toString('hex') !== final_hash.toString('hex'))
                throw new Error('Invalid publicKey (hash miss-match)');
            return raw_key.slice(1);
        }
    },
    toKeyString(key, keyType, address_prefix) {
        if (!this.buffer.isBuffer(key)) throw new Error(keyType+'Key as Buffer not provided!');
        key = key.slice(0,32);
        if (keyType !== 'public') {
            key = this.buffer.concat([new this.buffer.from([0x90]), key]);
            let hash = this.sodium.crypto_generichash_instance(key);
            const final_hash = this.buffer.from(hash.final());
            key = this.buffer.concat([key, final_hash.slice(0,4)]);
            return this.base58.encode(key);
        } else {
            if (!address_prefix) address_prefix = 'HYP'; else address_prefix = address_prefix.toUpperCase();
            key = this.buffer.concat([new this.buffer.from([0x91]), key]);
            let hash = this.sodium.crypto_generichash_instance(key);
            const final_hash = this.buffer.from(hash.final());
            key = this.buffer.concat([key, final_hash.slice(0,4)]);
            return address_prefix+this.base58.encode(key);
        }
    },
    getKeyBytes: function(key, keyType) {
        if (!key) throw new Error(keyType+'Key not provided!');
        if (typeof key == 'string') {
            key = this.fromKeyString(key, keyType);
        }
        if (this.buffer.isBuffer(key)) key = key.slice(0,32);
        if (key.length !== 32) throw new Error(keyType+'Key must be exactly 32 bytes!');
        return key;
    },
    get64BitSecretKey: function(key) {
        this.check_init();
        if (this.buffer.isBuffer(key) && key.length == 64) return key;
        const publicKey = this.buffer.allocUnsafe(this.sodium.crypto_sign_PUBLICKEYBYTES);
        var secretKey = this.buffer.allocUnsafe(this.sodium.crypto_sign_SECRETKEYBYTES);
        secretKey = this.buffer.concat([this.getKeyBytes(key, 'secret'), publicKey]);
        this.sodium.crypto_sign_seed_keypair(publicKey, secretKey, true); 
        return secretKey;
    },
    keyPair: function(seed, address_prefix, discovery_base) {
        this.check_init();
        var publicKey = this.buffer.allocUnsafe(this.sodium.crypto_sign_PUBLICKEYBYTES);
        var secretKey = this.buffer.allocUnsafe(this.sodium.crypto_sign_SECRETKEYBYTES);
        if (seed) {
            secretKey = this.get64BitSecretKey(seed);
            publicKey = secretKey.slice(32,64);
        } else this.sodium.crypto_sign_keypair(publicKey, secretKey);
        const discoveryPublicKey = this.buffer.allocUnsafe(this.sodium.crypto_sign_PUBLICKEYBYTES);
        if (!discovery_base) discovery_base = 'hypercore';
        this.sodium.crypto_generichash(discoveryPublicKey, this.buffer.from(discovery_base), publicKey);
        if (address_prefix) return { 
            publicKey: this.toKeyString(publicKey, 'public', address_prefix),
            discoveryPublicKey: this.toKeyString(discoveryPublicKey, 'public', address_prefix),
            secretKey: this.toKeyString(secretKey, 'private'),
        };
        return { publicKey, discoveryPublicKey, secretKey: secretKey.slice(0,32) };
    },
    sign: function(message, secretKey, base58) {
        this.check_init();
        if (!message) throw new Error('message required');
        const publicKey = this.buffer.allocUnsafe(this.sodium.crypto_sign_PUBLICKEYBYTES);
        secretKey = this.buffer.concat([this.getKeyBytes(secretKey, 'secret'), publicKey]);
        this.sodium.crypto_sign_seed_keypair(publicKey, secretKey, true);
        const signature = this.buffer.allocUnsafe(this.sodium.crypto_sign_BYTES);
        this.sodium.crypto_sign_detached(signature, this.buffer.from(message), secretKey);
        if (base58) return 'SIG_ED_'+this.base58.encode(signature);
        return signature;
    },
    verify: function(message, signature, publicKey) {
        this.check_init();
        if (!message) throw new Error('message required');
        publicKey = this.getKeyBytes(publicKey, 'public');
        if (typeof signature == 'string') {
            if (!signature.startsWith('SIG_ED_')) throw new Error('unknown signature type!');
            signature = this.base58.decode(signature.substring(7));
        }
        if (signature.length != this.sodium.crypto_sign_BYTES) throw new Error('signature must be exactly '+this.sodium.crypto_sign_BYTES+' bytes!');
        return this.sodium.crypto_sign_verify_detached(signature, this.buffer.from(message), publicKey);
    },
    memo_encrypt: function(secretKey, toPublicKey, message, address_prefix) {
        this.check_init();
        if (!message) throw new Error('memo message required');
        secretKey = this.get64BitSecretKey(this.getKeyBytes(secretKey, 'secret'));
        toPublicKey = this.getKeyBytes(toPublicKey, 'public');
        const fromPublicKey = secretKey.slice(32,64);
        const fromMemoSecretKey = this.buffer.allocUnsafe(this.sodium.crypto_box_SECRETKEYBYTES);
        this.sodium.crypto_sign_ed25519_sk_to_curve25519(fromMemoSecretKey, secretKey);
        const fromMemoPublicKey = this.buffer.allocUnsafe(this.sodium.crypto_box_PUBLICKEYBYTES);
        this.sodium.crypto_sign_ed25519_pk_to_curve25519(fromMemoPublicKey, fromPublicKey);
        const toMemoPublicKey = this.buffer.allocUnsafe(this.sodium.crypto_box_PUBLICKEYBYTES);
        this.sodium.crypto_sign_ed25519_pk_to_curve25519(toMemoPublicKey, toPublicKey)
        const scalarmult_q = this.buffer.allocUnsafe(this.sodium.crypto_scalarmult_BYTES);
        if (this.sodium.crypto_scalarmult(scalarmult_q, fromMemoSecretKey, toMemoPublicKey) != 0) {
            throw new Error('scalarmult_error');
        }
        let hash = this.sodium.crypto_generichash_instance(scalarmult_q);
        hash.update(fromPublicKey);
        hash.update(toPublicKey);
        const shared_secret = hash.final();
        const nonce = this.randomBytes(this.sodium.crypto_box_NONCEBYTES);
        message = this.buffer.from(message, 'utf-8');
        const encrypted = this.buffer.allocUnsafe(this.sodium.crypto_secretbox_MACBYTES+message.byteLength);
        this.sodium.crypto_secretbox_easy(encrypted, message, nonce, shared_secret);
        if (!address_prefix) address_prefix = 'HYP';
        return { from: this.toKeyString(secretKey.slice(32,64), 'public'),
                 to: this.toKeyString(toPublicKey, 'public'),
                 nonce: this.bigint.fromBuffer(nonce).toString(),
                 message: encrypted.toString('hex')
                };
    },
    memo_decrypt: function(secretKey, message) {
        this.check_init();
        if (!message) throw new Error('memo message required');
        secretKey = this.get64BitSecretKey(this.getKeyBytes(secretKey, 'secret'));
        const skMemoSecretKey = this.buffer.allocUnsafe(this.sodium.crypto_box_SECRETKEYBYTES);
        this.sodium.crypto_sign_ed25519_sk_to_curve25519(skMemoSecretKey, secretKey);
        const skMemoPublicKey = this.buffer.allocUnsafe(this.sodium.crypto_box_PUBLICKEYBYTES);
        this.sodium.crypto_sign_ed25519_pk_to_curve25519(skMemoPublicKey, secretKey.slice(32,64));
        if (typeof message == 'string') message = JSON.parse(message);
        const fromPublicKey = this.getKeyBytes(message.from, 'public');
        const toPublicKey = this.getKeyBytes(message.to, 'public');
        const fromMemoPublicKey = this.buffer.allocUnsafe(this.sodium.crypto_box_PUBLICKEYBYTES);
        this.sodium.crypto_sign_ed25519_pk_to_curve25519(fromMemoPublicKey, fromPublicKey);
        const toMemoPublicKey = this.buffer.allocUnsafe(this.sodium.crypto_box_PUBLICKEYBYTES);
        this.sodium.crypto_sign_ed25519_pk_to_curve25519(toMemoPublicKey, toPublicKey)
        if (skMemoPublicKey.compare(fromMemoPublicKey) == 0) var otherMemoPublicKey = toMemoPublicKey; else
            if (skMemoPublicKey.compare(toMemoPublicKey) == 0) var otherMemoPublicKey = fromMemoPublicKey; else
                throw new Error('publicKey does not match sender or receiver');
        const scalarmult_q = this.buffer.allocUnsafe(this.sodium.crypto_scalarmult_BYTES);
        if (this.sodium.crypto_scalarmult(scalarmult_q, skMemoSecretKey, otherMemoPublicKey) != 0) {
            throw new Error('scalarmult_error');
        }
        let hash = this.sodium.crypto_generichash_instance(scalarmult_q);
        hash.update(fromPublicKey);
        hash.update(toPublicKey);
        const shared_secret = hash.final();
        const nonce = this.bigint(message.nonce).toBuffer();
        let encrypted = this.buffer.from(message.message, 'hex');
        const decrypted = this.buffer.allocUnsafe(encrypted.byteLength-this.sodium.crypto_secretbox_MACBYTES);
        if (!this.sodium.crypto_secretbox_open_easy(decrypted, encrypted, nonce, shared_secret)) {
            throw new Error('decryption failed')
        }
        return decrypted.toString('utf-8');
    },
    randomBytes: function(n) {
        this.check_init();
        const buf = this.buffer.allocUnsafe(n);
        this.sodium.randombytes_buf(buf);
        return buf;
    },
}

document.addEventListener("DOMContentLoaded", async function() {
    sdk = await hyperSDK({
        // With this, all drive will disappear after the process exits
        // This is here so that running the example doesn't clog up your history
        persist: false,
        // storage can be set to an instance of `random-access-*`
        // const RAI = require('random-access-idb')
        // otherwise it defaults to `random-access-web` in the browser
        // and `random-access-file` in node
        storage: null  //storage: RAI
    });
    hyper_utils.init(sdk.sodium,Steem.buffer,Steem.base58,Steem.BigInteger);
});

var feed_alt_crypto = {
    sign (data, sk, cb) {
      return cb(null, hyper_utils.sign(data, sk))
    },
    verify (sig, data, pk, cb) {
      return cb(null, hyper_utils.verify(sig, data, pk))
    }
  }
