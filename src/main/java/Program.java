import encrypt.KeyGeneration;
import encrypt.SignData;

import java.io.*;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.Properties;

public class Program {
    public static void main(String[] args) throws IOException {

//        ListSecurityProviders();
//
//        if (true) { return; }


        Properties properties = new Properties();
        FileInputStream pFile = new FileInputStream("test.properties.asc");
        properties.load(pFile);

        String name = properties.getProperty("name");
        String debug = properties.getProperty("debug");



        bcKeyGen();
        if (true) return;

        ReadPrivateKey("private_key_64.txt");


        KeyGeneration keyGeneration = new KeyGeneration();
        String privateKey64 = keyGeneration.GetPrivateKey64();
        String publicKey64 = keyGeneration.GetPublicKey64();

        PrivateKey pvKey = keyGeneration.GetPrivateKey();
        PublicKey pubKey = keyGeneration.GetPublicKey();

        /* save the public key in a file */
        byte[] pubKeyEncoded = pubKey.getEncoded();
        byte[] pvKeyEncoded = pvKey.getEncoded();


        SignData signData = new SignData(pvKey);
        signData.Sign("signme.txt");

        FileOutputStream keyfos = null;
        PrintWriter out = null;
        try {
            keyfos = new FileOutputStream("public_key");
            keyfos.write(pubKeyEncoded);
            keyfos.close();

            keyfos = new FileOutputStream("private_key");
            keyfos.write(pvKeyEncoded);
            keyfos.close();

            out = new PrintWriter("private_key_64.txt");
            out.println(privateKey64);
            out.close();

            out = new PrintWriter("public_key_64.txt");
            out.println(publicKey64);
            out.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }


    private static void bcKeyGen() {

    }

    private static void ReadPrivateKey(String fileName) {
//        String keyPath = "mykey.pem";
//        BufferedReader br = new BufferedReader(new FileReader(keyPath));
//        Security.addProvider(new BouncyCastleProvider());
//        PemObjectParser pp = new PEMParser(br);
//        PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
//        KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
//        pp.close();
//        samlResponse.sign(Signature.getInstance("SHA1withRSA").toString(), kp.getPrivate(), certs);
//
//
//
//        PrivateKey pvKey;
//        try {
//            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
//            KeyPair pair;
//
//		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
    }
    
    private static void ListSecurityProviders() {
        for (Provider provider: Security.getProviders()) {
            System.out.println(provider.getName());
            for (Provider.Service s: provider.getServices()){
                if (s.getType().equals("Cipher"))
                    System.out.println("\t"+s.getType()+" "+ s.getAlgorithm());
            }
        }
    }


}
