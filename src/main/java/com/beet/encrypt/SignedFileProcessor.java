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
import java.util.Iterator;

public class SignedFileProcessor {
//    private static final String cmdName = "bcSignFile2";
//
//    private static void PrintHelp(Options options) {
//        HelpFormatter formatter = new HelpFormatter();
//        formatter.printHelp(cmdName, options, true);
//    }

    public SignedFileProcessor() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /*
     * verify the passed in file as being correctly signed.
     */
    private static void verifyFile(
            InputStream in,
            InputStream keyIn)
            throws Exception {

        in = PGPUtil.getDecoderStream(in);
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
        PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();
        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();
        PGPOnePassSignature ops = p1.get(0);
        PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

        InputStream dIn = p2.getInputStream();
        int ch;
        PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
        FileOutputStream out = new FileOutputStream(p2.getFileName());

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        while ((ch = dIn.read()) >= 0) {
            ops.update((byte) ch);
            out.write(ch);
        }

        out.close();

        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

        if (ops.verify(p3.get(0))) {
            System.out.println("signature verified.");
        } else {
            System.out.println("signature verification failed.");
        }
    }

    /**
     * Generate an encapsulated signed file.
     *
     * @param fileName
     * @param keyIn
     * @param out
     * @param pass
     * @param armor
     * @throws IOException
     * @throws PGPException
     */
    private static void signFile(
            String fileName,
            InputStream keyIn,
            OutputStream out,
            char[] pass,
            boolean armor)
            throws IOException, PGPException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        PGPSecretKey pgpSec = PGPUtils.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);

        BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));

        sGen.generateOnePassVersion(false).encode(bOut);

        File file = new File(fileName);
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
        FileInputStream fIn = new FileInputStream(file);
        int ch;

        while ((ch = fIn.read()) >= 0) {
            lOut.write(ch);
            sGen.update((byte) ch);
        }

        lGen.close();

        sGen.generate().encode(bOut);

        cGen.close();

        if (armor) {
            out.close();
        }
    }
//
//    public static void main(String[] args) throws Exception {
//        Security.addProvider(new BouncyCastleProvider());
//
////        MainArgs mainArgs = new MainArgs();
////        CommandSign sign = new CommandSign();
////        CommandVerify verify = new CommandVerify();
////        JCommander jc = JCommander.newBuilder()
////                .addObject(mainArgs)
////                .addCommand("sign",sign)
////                .addCommand("verify", verify)
////                .args(args)
////                .programName(cmdName)
////                .build();
////
////        if (mainArgs.help | jc.getParsedCommand() == null) {
////            jc.usage();
////            System.exit(100);
////        }
////
////        FileInputStream keyIn = null;
////        switch (jc.getParsedCommand()) {
////            case "sign":
////                System.out.println("Signing Command");
////                keyIn = new FileInputStream(sign.KeyFile);
////                if (sign.ASCOutput) {
////                    FileOutputStream out = new FileOutputStream(sign.FileToSign + ".asc");
////                    signFile(sign.FileToSign, keyIn, out, sign.PassPhrase.toCharArray(), true);
////                } else {
////                    FileOutputStream out = new FileOutputStream(sign.FileToSign + ".bpg");
////                    signFile(sign.FileToSign, keyIn, out, sign.PassPhrase.toCharArray(), false);
////                }
////                break;
////
////            case "verify":
////                System.out.println("Signature Validation Command");
////                FileInputStream in = new FileInputStream(verify.FileIn);
////                keyIn = new FileInputStream(verify.KeyFile);
////
////                verifyFile(in, keyIn);
////                break;
////
////        }
//
//
//
//
//    }
}
