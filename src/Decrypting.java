import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Decrypting {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";

    public static String Decrypt(byte[] encrypted, String mode) throws Exception{
        IvParameterSpec ivSpec = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        Cipher cipher;

        //System.out.println("input : " + new String(input));
        switch (mode){
            case "ECB":
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                break;
            case "CBC":
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "OFB":
                cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "CFB":
                cipher= Cipher.getInstance("AES/CFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "CTR":
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            default:
                System.out.println("No such mode, default mode: ECB!");
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                break;
        }

        return byteArrayToString(cipher.doFinal(encrypted));
    }

    private static String byteArrayToString(byte[] encrypted) {
        String decryptedMessage = new String(encrypted);
        return decryptedMessage;
    }
}
