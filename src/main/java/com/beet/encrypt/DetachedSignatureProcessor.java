package com.beet.encrypt;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.security.Security;

public class DetachedSignatureProcessor {

    public DetachedSignatureProcessor() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public boolean verifySignature(
            String fileName,
            String inputFileName,
            String keyFileName)
            throws IOException, PGPException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));

        boolean result = verifySignature(fileName, in, keyIn);

        keyIn.close();
        in.close();
        return result;
    }

    /*
     * verify the signature in in against the file fileName.
     */
    private static boolean verifySignature(
            String fileName,
            InputStream in,
            InputStream keyIn)
            throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
        PGPSignatureList p3;

        Object o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) o;

            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

            p3 = (PGPSignatureList) pgpFact.nextObject();
        } else {
            p3 = (PGPSignatureList) o;
        }

        PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
                new JcaKeyFingerprintCalculator());


        InputStream dIn = new BufferedInputStream(new FileInputStream(fileName));

        PGPSignature sig = p3.get(0);
        PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        int ch;
        while ((ch = dIn.read()) >= 0) {
            sig.update((byte) ch);
        }

        dIn.close();

        if (sig.verify()) {
            return true;
        } else {
            return false;
        }
    }

    public void createSignature(
            String inputFileName,
            String keyFileName,
            String outputFileName,
            char[] pass, String digestMode,
            boolean armor)
            throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));

        createSignature(inputFileName, keyIn, out, pass, digestMode, armor);

        out.close();
        keyIn.close();
    }

    private static void createSignature(
            String fileName,
            InputStream keyIn,
            OutputStream out,
            char[] pass, String digestMode,
            boolean armor)
            throws IOException, PGPException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        PGPSecretKey pgpSec = PGPUtils.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));

        int digestCode = PGPUtil.SHA1;
        //SHA1,SHA256,SHA384,SHA512,MD5,RIPEMD160
        switch (digestMode.toUpperCase()) {
            case "SHA1":
                digestCode = PGPUtil.SHA1;
                break;
            case "SHA256":
                digestCode = PGPUtil.SHA256;
                break;
            case "SHA384":
                digestCode = PGPUtil.SHA384;
                break;
            case "SHA512":
                digestCode = PGPUtil.SHA512;
                break;
            case "MD5":
                digestCode = PGPUtil.MD5;
                break;
            case "RIPEMD160":
                digestCode = PGPUtil.RIPEMD160;
                break;
        }

        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(),
                digestCode).setProvider("BC"));
        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
        BCPGOutputStream bOut = new BCPGOutputStream(out);
        InputStream fIn = new BufferedInputStream(new FileInputStream(fileName));

        int ch;
        while ((ch = fIn.read()) >= 0) {
            sGen.update((byte) ch);
        }

        fIn.close();

        sGen.generate().encode(bOut);

        if (armor) {
            out.close();
        }
    }
}
