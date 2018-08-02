// GrapheneUtils.java, by @alexpmorris, 2018-02-22
//
// easily verify messages passed between javascript <-> java using a graphene keypair
//
// depending on the use case, a token and/or timestamp should also be included in
// each message in order to verify the message isn't being reused (ie. for login purposes, etc)
//
// this simply expands slightly upon the work of many other great projects, including:
//
// https://github.com/bitcoinj/bitcoinj
// https://github.com/marvin-we/steem-java-api-wrapper
// https://github.com/marvin-we/crypto-core
// https://github.com/Agorise/graphenej
//
// https://github.com/steemit/steem-js
//
// new key formats for eos: https://github.com/EOSIO/eos/issues/2146
//      Public keys will be represented as EOS_<key_type_id>_<base_58_encoding_of_public_key_data>
//      Private keys will be represented as PRI_<key_type_id>_<base_58_encoding_of_private_key_data>
//      Signatures will be represented as SIG_<key_type_id>_<base_58_encoding_of_signature_data>


import com.google.common.primitives.*;
import eu.bittrade.crypto.core.*;
import eu.bittrade.crypto.core.base58.*;
import eu.bittrade.libs.steemj.base.models.*;
import org.spongycastle.crypto.digests.*;
import org.spongycastle.util.encoders.Base64;

import java.math.*;
import java.nio.charset.*;
import java.util.*;

/* in javascript using my custom-rolled version of the steem-js library (available on my github crypto-playpen):
   (note: this should also work with other graphene-based javascript libraries)

https://stackoverflow.com/questions/12710001/how-to-convert-uint8-array-to-base64-encoded-string

verify signature from javascript to java:

    var privateWif = "5JRaypasxMx1L97ZUX7YuC5Psb5EAbF821kkAGtBj7xCJFQcbLg";
    var sigObj = steem.ecc.Signature.sign("test", privateWif);
    var sigBase64 = btoa('\40'+String.fromCharCode.apply(null, sigObj.r.toBuffer())+String.fromCharCode.apply(null, sigObj.s.toBuffer()));

verify signature from java to javascript:

    var sigBase64 = "G+MS/x9rpgfhxR7Z3s9VopBW8y7iJZPaN+4D8yp7MNqqBI/Pux85Prl0UacVRTkcBeFvfat/Pdc7PVoXKq4eqnY=";
    var publicKey = "STM6aGPtxMUGnTPfKLSxdwCHbximSJxzrRjeQmwRW9BRCdrFotKLs";
    var pubKeyObj = steem.ecc.PublicKey.fromString(publicKey)
    var sigBuf = new steem.ecc.buffer('\33'+atob(sigBase64).substring(1),"ascii");
    var sigObj = steem.ecc.Signature.fromBuffer(sigBuf);
    var isValid = sigObj.verifyBuffer("test",pubKeyObj);
    if (isValid) console.log("valid signature!");

javascript functions based on the above:

    function signGrapheneMessage(msg, privateWif) {
      const sigObj = steem.ecc.Signature.sign(msg, privateWif);
      return btoa('\40'+String.fromCharCode.apply(null, sigObj.r.toBuffer())+String.fromCharCode.apply(null, sigObj.s.toBuffer()));
    }

    function verifyGrapheneMessage(msg, sigBase64, publicKey) {
      try {
        const pubKeyObj = steem.ecc.PublicKey.fromString(publicKey)
        const sigBuf = new steem.ecc.buffer('\33'+atob(sigBase64).substring(1),"ascii");
        const sigObj = steem.ecc.Signature.fromBuffer(sigBuf);
        return sigObj.verifyBuffer(msg,pubKeyObj);
      } catch (e) { return false; }
    }

*/

public class GrapheneUtils {

    private static final int CHECKSUM_BYTES = 4;

    public static byte[] calculateChecksum(byte[] publicKey) {
        RIPEMD160Digest ripemd160Digest = new RIPEMD160Digest();
        ripemd160Digest.update(publicKey, 0, publicKey.length);
        byte[] actualChecksum = new byte[ripemd160Digest.getDigestSize()];
        ripemd160Digest.doFinal(actualChecksum, 0);
        return actualChecksum;
    }

    // use this method to retrieve the address representation of the public key
    // associated with a particular private key
    // prefix = STM, BTS, EOS, GLS, etc...
    // privKey is the ECKey object holding the associated private key
    public static String getAddressFromPublicKey(String prefix, eu.bittrade.crypto.core.ECKey privKey) {
        try {
            // Recreate the address from the public key.
            byte [] pubBytes;
            if (privKey.isCompressed()) pubBytes = privKey.getPubKey(); else
                pubBytes = org.bitcoinj.core.ECKey.fromPublicOnly(org.bitcoinj.core.ECKey.compressPoint(privKey.getPubKeyPoint())).getPubKey();
            return prefix + org.bitcoinj.core.Base58.encode(Bytes.concat(pubBytes,
                    Arrays.copyOfRange(calculateChecksum(pubBytes), 0, CHECKSUM_BYTES)));
        } catch (Exception e) {
            return "";
        }
    }

    // returns a graphene Wif from the byte representation of a private key
    public static String getGrapheneWifFromPrivateKey(eu.bittrade.crypto.core.ECKey pKey) {
        return pKey.getPrivateKeyEncoded(128).toBase58();
    }

    // returns an ECKey object holding a byte representation of a private key from a graphene Wif
    public static eu.bittrade.crypto.core.ECKey GrapheneWifToPrivateKey(String Wif) {
        eu.bittrade.crypto.core.ECKey pKey = DumpedPrivateKey.fromBase58(null, Wif, new Sha256ChecksumProvider()).getKey();
        //System.out.println(pKey.getPrivateKeyEncoded(128).toBase58());
        //System.out.println(getAddressFromPublicKey("STM", pKey));
        return pKey;
    }

    public static String SignMessage(String message, eu.bittrade.crypto.core.ECKey privKey) {
        Sha256Hash messageAsHash = Sha256Hash.of(message.getBytes());
        ECKey.ECDSASignature sigObj = privKey.sign(messageAsHash);

        byte[] sigData = new byte[65];
        // first byte is header, defined as "int headerByte = recId + 27 + (isCompressed() ? 4 : 0);"
        sigData[0] = (byte)27;
        System.arraycopy(CryptoUtils.bigIntegerToBytes(sigObj.r, 32), 0, sigData, 1, 32);
        System.arraycopy(CryptoUtils.bigIntegerToBytes(sigObj.s, 32), 0, sigData, 33, 32);
        return new String(Base64.encode(sigData), Charset.forName("UTF-8"));
    }

    public static boolean VerifyMessage(String message, String sigBase64, PublicKey pubKey) {
        try {

            byte[] encodedSig;
            encodedSig = Base64.decode(sigBase64);
            byte header = encodedSig[0];
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(encodedSig, 1, 33));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(encodedSig, 33, 65));
            ECKey.ECDSASignature sigObj = new ECKey.ECDSASignature(r,s);

            Sha256Hash messageAsHash = Sha256Hash.of(message.getBytes());

            return ECKey.verify(messageAsHash.getBytes(), sigObj.encodeToDER(), pubKey.toByteArray());

        } catch (Exception e) { return false; }
    }

    public static String SignEosMessage(String message, eu.bittrade.crypto.core.ECKey privKey) {
        Sha256Hash messageAsHash = Sha256Hash.of(message.getBytes());
        ECKey.ECDSASignature sigObj = privKey.sign(messageAsHash);

        byte[] sigData = new byte[69];
        // first byte is header, defined as "int headerByte = recId + 27 + (isCompressed() ? 4 : 0);"
        sigData[0] = (byte)31;
        System.arraycopy(CryptoUtils.bigIntegerToBytes(sigObj.r, 32), 0, sigData, 1, 32);
        System.arraycopy(CryptoUtils.bigIntegerToBytes(sigObj.s, 32), 0, sigData, 33, 32);

        //append ripemd160 checksum
        byte[] checksum = calculateChecksum(Bytes.concat(Arrays.copyOfRange(sigData, 0, 65),"K1".getBytes()));
        System.arraycopy(checksum, 0, sigData, 65, 4);

        return new String("SIG_K1_"+Base58.encode(sigData));
    }

    public static boolean VerifyEosMessage(String message, String sigBase58, PublicKey pubKey) {
        try {

            byte[] encodedSig;
            String[] sig_arr = sigBase58.split("_");
            encodedSig = Base58.decode(sig_arr[2]);

            byte header = encodedSig[0];
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(encodedSig, 1, 33));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(encodedSig, 33, 65));
            byte[] checksum = Arrays.copyOfRange(encodedSig, 65, 69);

            //ripemd160 checksum
            byte[] new_checksum = calculateChecksum(Bytes.concat(Arrays.copyOfRange(encodedSig, 0, 65),"K1".getBytes()));
            if (!Arrays.equals(Arrays.copyOfRange(new_checksum,0, 4),checksum)) return false;

            ECKey.ECDSASignature sigObj = new ECKey.ECDSASignature(r, s);

            Sha256Hash messageAsHash = Sha256Hash.of(message.getBytes());

            return ECKey.verify(messageAsHash.getBytes(), sigObj.encodeToDER(), pubKey.toByteArray());

        } catch (Exception e) { return false; }
    }
   
    // sample usage

    /*
    public static void VerifyDemo() {
        ECKey privKey = GrapheneWifToPrivateKey("5JRaypasxMx1L97ZUX7YuC5Psb5EAbF821kkAGtBj7xCJFQcbLg");
        String base64Sig = SignMessage("test",privKey);
        System.out.println("base64Sig = " + base64Sig);

        String pubKeyAddress = getAddressFromPublicKey("STM", privKey);
        System.out.println("PublicAddress = " + pubKeyAddress);

        PublicKey pubKeyObj = new PublicKey(pubKeyAddress);
        System.out.println("isValid = "+VerifyMessage("test", base64Sig, pubKeyObj));
    }
    */

}
