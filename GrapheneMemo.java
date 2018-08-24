import com.google.common.primitives.*;
import com.jsoniter.*;
import com.jsoniter.any.*;
import eu.bittrade.crypto.core.*;
import eu.bittrade.libs.steemj.base.models.PublicKey;
import org.spongycastle.util.encoders.Base64;

import java.math.*;
import java.security.*;
import java.util.*;

/**
 * Class used to represent a memo data structure
 * {@url https://bitshares.org/doxygen/structgraphene_1_1chain_1_1memo__data.html}
 */
public class GrapheneMemo {
    public final static String TAG = "Memo";
    public static final String KEY_FROM = "from";
    public static final String KEY_TO = "to";
    public static final String KEY_NONCE = "nonce";
    public static final String KEY_MESSAGE = "message";

    private PublicKey from;
    private PublicKey to;
    private BigInteger nonce;
    private byte[] message;
    private String plaintextMessage;

    public String getPlaintextMessage() {
        if(plaintextMessage == null)
            return "";
        else
            return plaintextMessage;
    }

    public void setPlaintextMessage(String plaintextMessage) {
        this.plaintextMessage = plaintextMessage;
    }

    /**
     * Empty Constructor
     */
    public GrapheneMemo() {
        this.from = null;
        this.to = null;
        this.message = null;
    }

    /**
     * Constructor used for private memos.
     * @param from: Address of sender
     * @param to: Address of recipient.
     * @param nonce: Nonce used in the encryption.
     * @param message: Message in ciphertext.
     */
    public GrapheneMemo(PublicKey from, PublicKey to, BigInteger nonce, byte[] message){
        this.from = from;
        this.to = to;
        this.nonce = nonce;
        this.message = message;
    }

    /**
     * Constructor intended to be used with public memos
     * @param message: Message in plaintext.
     */
    public GrapheneMemo(String message){
        this.message = message.getBytes();
    }

    public PublicKey getSource(){
        return this.from;
    }

    public PublicKey getDestination(){
        return this.to;
    }

    public BigInteger getNonce(){
        return this.nonce;
    }

    public byte[] getByteMessage(){
        return this.message;
    }

    public String getStringMessage(){
        if(this.message != null)
            return new String(this.message);
        else
            return "";
    }

    /**
     * Method used to decrypt memo data.
     * @param privateKey: Private key of the sender.
     * @param publicKey: Public key of the recipient.
     * @param nonce: The nonce.
     * @param message: Plaintext message.
     * @return: The encrypted version of the message.
     */
    public static byte[] encryptMessage(ECKey privateKey, PublicKey publicKey, BigInteger nonce, String message){
        byte[] encrypted = null;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

            // Getting nonce bytes
            String stringNonce = nonce.toString();
            byte[] nonceBytes = Arrays.copyOfRange(ChainUtils.hexlify(stringNonce), 0, stringNonce.length());

            // Getting shared secret
            byte[] secret = publicKey.getPublicKey().getPubKeyPoint().multiply(privateKey.getPrivKey()).normalize().getXCoord().getEncoded();

            // SHA-512 of shared secret
            byte[] ss = sha512.digest(secret);

            byte[] seed = Bytes.concat(nonceBytes, ChainUtils.hexlify(ChainUtils.bytesToHex(ss)));

            // Calculating checksum
            byte[] sha256Msg = sha256.digest(message.getBytes());
            byte[] checksum = Arrays.copyOfRange(sha256Msg, 0, 4);

            // Concatenating checksum + message bytes
            byte[] msgFinal = Bytes.concat(checksum, message.getBytes());

            // Applying encryption
            encrypted = ChainUtils.encryptAES(msgFinal, seed);
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("NoSuchAlgotithmException. Msg:"+ ex.getMessage());
        }
        return encrypted;
    }

    /**
     * Method used to decrypt memo data.
     * @param privateKey: The private key of the recipient.
     * @param publicKey: The public key of the sender.
     * @param nonce: The nonce.
     * @param message: The encrypted message.
     * @return: The plaintext version of the enrcrypted message.
     * @throws Exception
     */
    public static String decryptMessage(ECKey privateKey, PublicKey publicKey, BigInteger nonce, byte[] message) throws Exception {
        String plaintext = "";
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

            // Getting nonce bytes
            String stringNonce = nonce.toString();
            byte[] nonceBytes = Arrays.copyOfRange(ChainUtils.hexlify(stringNonce), 0, stringNonce.length());

            // Getting shared secret
            byte[] secret = publicKey.getPublicKey().getPubKeyPoint().multiply(privateKey.getPrivKey()).normalize().getXCoord().getEncoded();

            // SHA-512 of shared secret
            byte[] ss = sha512.digest(secret);

            byte[] seed = Bytes.concat(nonceBytes, ChainUtils.hexlify(ChainUtils.bytesToHex(ss)));

            // Calculating checksum
            byte[] sha256Msg = sha256.digest(message);


            // Applying decryption
            byte[] temp = ChainUtils.decryptAES(message, seed);
            byte[] checksum = Arrays.copyOfRange(temp, 0, 4);
            byte[] decrypted = Arrays.copyOfRange(temp, 4, temp.length);
            plaintext = new String(decrypted);
            byte[] checksumConfirmation = Arrays.copyOfRange(sha256.digest(decrypted), 0, 4);
            boolean checksumVerification = Arrays.equals(checksum, checksumConfirmation);
            if(!checksumVerification){
                throw new Exception("Invalid checksum found while performing decryption");
            }
        } catch (Exception e) {
            System.out.println("NoSuchAlgotithmException. Msg:"+ e.getMessage());
        }
        return plaintext;
    }

    // much more difficult to encode/decode STEEM memos from java
    // since they seem to be serializing the actual javascript objects

    public static String encryptBTSmemo(String privKey, String toPubKey, String message, boolean asBase64) {
        try {
            ECKey privateKey = GrapheneUtils.GrapheneWifToPrivateKey(privKey);
            String fromPubKey = GrapheneUtils.getAddressFromPublicKey(toPubKey.substring(0,3), privateKey);
            PublicKey pubKey = new PublicKey(toPubKey);
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[8];
            random.nextBytes(bytes);
            BigInteger nonce = new BigInteger(bytes).abs();
            message = ChainUtils.bytesToHex(encryptMessage(privateKey, pubKey, nonce, message));
            String result = "{\""+KEY_FROM+"\":\""+fromPubKey+"\","+
                             "\""+KEY_TO+"\":\""+toPubKey+"\","+
                             "\""+KEY_NONCE+"\":\""+nonce+"\","+
                             "\""+KEY_MESSAGE+"\":\""+message+"\"}";
            if (asBase64) result = new String(Base64.encode(result.getBytes()));
            return result;
        } catch (Exception e) { }
        return message;
    }

    public static String decryptBTSmemo(String privKey, String memo) {
        try {
            if (!memo.startsWith("{") || !memo.endsWith("}")) memo = new String(Base64.decode(memo));
            Any json_memo = JsonIterator.deserialize(memo);
            if (json_memo.get(KEY_NONCE).valueType().equals(ValueType.INVALID))
                return json_memo.get(KEY_MESSAGE).toString();
            BigInteger nonce = new BigInteger(json_memo.get(KEY_NONCE).toString());
            String fromKey = json_memo.get(KEY_FROM).toString();
            String toKey = json_memo.get(KEY_TO).toString();
            ECKey privateKey = GrapheneUtils.GrapheneWifToPrivateKey(privKey);
            String publicKey = GrapheneUtils.getAddressFromPublicKey(fromKey.substring(0,3), privateKey);
            PublicKey pubKey = null;
            if (publicKey.equals(fromKey)) pubKey = new PublicKey(toKey); else
                pubKey = new PublicKey(fromKey);
            String message = json_memo.get(KEY_MESSAGE).toString();
            return decryptMessage(privateKey, pubKey, nonce, ChainUtils.hexToBytes(message));
        } catch (Exception e) { }
        return memo;
    }

}
