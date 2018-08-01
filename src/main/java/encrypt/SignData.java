package encrypt;

import java.io.*;
import java.security.*;

public class SignData {
    private Signature dsa;

    public SignData(PrivateKey privateKey) {
        try {
            dsa = Signature.getInstance("MD5withRSA", "SunRsaSign");
            dsa.initSign(privateKey);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public void Sign(String fileName) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(fileName);
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                dsa.update(buffer, 0, len);
            };
            bufin.close();

            byte[] realSig = dsa.sign();

            /* save the signature in a file */
            FileOutputStream sigfos = new FileOutputStream("sig");
            sigfos.write(realSig);
            sigfos.close();



        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
