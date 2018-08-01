package encrypt;

import org.apache.commons.codec.binary.Base64;

import java.security.*;


public class KeyGeneration {
    private PrivateKey priv;
    private PublicKey pub;

    public KeyGeneration() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");


            SecureRandom random = SecureRandom.getInstanceStrong();
            keyGen.initialize(3072, random);
            KeyPair pair = keyGen.generateKeyPair();
            priv = pair.getPrivate();
            pub = pair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

    }

    public PrivateKey GetPrivateKey() {
        return priv;
    }

    public PublicKey GetPublicKey() {
        return pub;
    }

    public String GetPrivateKey64() {
        byte[] pv = priv.getEncoded();
        return new Base64().encodeAsString(pv);
    }

    public String GetPublicKey64() {
        byte[] pubkey = pub.getEncoded();
        return new Base64().encodeAsString(pubkey);
    }

}
