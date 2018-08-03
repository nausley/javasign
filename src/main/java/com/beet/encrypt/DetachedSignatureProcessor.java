package com.beet.encrypt;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.security.GeneralSecurityException;

public class DetachedSignatureProcessor {
//    private static final String cmdName = "bcSignDetached";

    public void verifySignature(
            String fileName,
            String inputFileName,
            String keyFileName)
            throws GeneralSecurityException, IOException, PGPException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));

        verifySignature(fileName, in, keyIn);

        keyIn.close();
        in.close();
    }

    /*
     * verify the signature in in against the file fileName.
     */
    private static void verifySignature(
            String fileName,
            InputStream in,
            InputStream keyIn)
            throws GeneralSecurityException, IOException, PGPException {
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

        PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());


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
            System.out.println("signature verified.");
        } else {
            System.out.println("signature verification failed.");
        }
    }

    public void createSignature(
            String inputFileName,
            String keyFileName,
            String outputFileName,
            char[] pass,
            boolean armor)
            throws GeneralSecurityException, IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));

        createSignature(inputFileName, keyIn, out, pass, armor);

        out.close();
        keyIn.close();
    }

    private static void createSignature(
            String fileName,
            InputStream keyIn,
            OutputStream out,
            char[] pass,
            boolean armor)
            throws GeneralSecurityException, IOException, PGPException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        PGPSecretKey pgpSec = PGPUtils.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

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

    /**
     * A simple utility class that creates seperate signatures for files and verifies them.
     *
     * To sign a file: DetachedSignatureProcessor -s [-a] fileName secretKey passPhrase.
     * If -a is specified the output file will be "ascii-armored".
     *
     * To decrypt: DetachedSignatureProcessor -v  fileName signatureFile publicKeyFile.
     *
     * Note: this example will silently overwrite files.
     * It also expects that a single pass phrase
     * will have been used.
     */
//    public static void main(String[] args)
//            throws GeneralSecurityException, IOException, PGPException {
//        Security.addProvider(new BouncyCastleProvider());
//
//        MainArgs mainArgs = new MainArgs();
//        CommandSign sign = new CommandSign();
//        CommandVerify verify = new CommandVerify();
//        JCommander jc = JCommander.newBuilder()
//                .addObject(mainArgs)
//                .addCommand("sign", sign)
//                .addCommand("verify", verify)
//                .args(args)
//                .programName(cmdName)
//                .build();
//
//        if (mainArgs.help | jc.getParsedCommand() == null) {
//            jc.usage();
//            System.exit(100);
//        }
//
//        InputStream keyIn = null;
//        switch (jc.getParsedCommand()) {
//            case "sign":
//                System.out.println("Signing Command");
//                //-s [-a] fileName secretKey passPhrase
//                if (sign.ASCOutput) {
//                    createSignature(sign.FileName, sign.SecretFile, sign.FileName + ".asc", sign.PassPhrase.toCharArray(), true);
//                } else {
//                    createSignature(sign.FileName, sign.SecretFile, sign.FileName + ".bpg", sign.PassPhrase.toCharArray(), false);
//                }
//                break;
//
//            case "verify":
//                System.out.println("Signature Validation Command");
//                //-v  fileName signatureFile publicKeyFile
//                verifySignature(verify.FileName, verify.SignatureFile, verify.PublicKey);
//                break;
//
//        }
//    }
}
