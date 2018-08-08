package com.beet.encrypt;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Strings;

import java.io.*;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

public class ClearSignedProcessor {
//    private static final String cmdName = "bcSignClear";

    public ClearSignedProcessor() {
        Security.addProvider(new BouncyCastleProvider());
    }


    private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
            throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
            throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }
        while ((ch = fIn.read()) >= 0);

        if (ch < 0) {
            lookAhead = -1;
        }

        return lookAhead;
    }

    private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn)
            throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }

    /*
     * verify a clear text signed file
     */
    public static void verifyFile(
            InputStream in,
            InputStream keyIn,
            String resultName)
            throws Exception {
        ArmoredInputStream aIn = new ArmoredInputStream(in);
        OutputStream out = new BufferedOutputStream(new FileOutputStream(resultName));

        //
        // write out signed section using the local line separator.
        // note: trailing white space needs to be removed from the end of
        // each line RFC 4880 Section 7.1
        //
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, aIn);
        byte[] lineSep = getLineSeparator();

        if (lookAhead != -1 && aIn.isClearText()) {
            byte[] line = lineOut.toByteArray();
            out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
            out.write(lineSep);

            while (lookAhead != -1 && aIn.isClearText()) {
                lookAhead = readInputLine(lineOut, lookAhead, aIn);

                line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                out.write(lineSep);
            }
        } else {
            // a single line file
            if (lookAhead != -1) {
                byte[] line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                out.write(lineSep);
            }
        }

        out.close();

        PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(keyIn, new JcaKeyFingerprintCalculator());

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(aIn);
        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
        PGPSignature sig = p3.get(0);

        PGPPublicKey publicKey = pgpRings.getPublicKey(sig.getKeyID());
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

        //
        // read the input, making sure we ignore the last newline.
        //

        InputStream sigIn = new BufferedInputStream(new FileInputStream(resultName));

        lookAhead = readInputLine(lineOut, sigIn);

        processLine(sig, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, sigIn);

                sig.update((byte) '\r');
                sig.update((byte) '\n');

                processLine(sig, lineOut.toByteArray());
            }
            while (lookAhead != -1);
        }

        sigIn.close();

        if (sig.verify()) {
            System.out.println("signature verified.");
        } else {
            System.out.println("signature verification failed.");
        }
    }

    private static byte[] getLineSeparator() {
        String nl = Strings.lineSeparator();
        byte[] nlBytes = new byte[nl.length()];

        for (int i = 0; i != nlBytes.length; i++) {
            nlBytes[i] = (byte) nl.charAt(i);
        }

        return nlBytes;
    }


    /*
     * create a clear text signed file.
     */
    public static void signFile(
            String fileName,
            InputStream keyIn,
            OutputStream out,
            char[] pass,
            String digestName)
            throws IOException, PGPException, SignatureException {
        int digest;

        if (digestName.equals("SHA256")) {
            digest = PGPUtil.SHA256;
        } else if (digestName.equals("SHA384")) {
            digest = PGPUtil.SHA384;
        } else if (digestName.equals("SHA512")) {
            digest = PGPUtil.SHA512;
        } else if (digestName.equals("MD5")) {
            digest = PGPUtil.MD5;
        } else if (digestName.equals("RIPEMD160")) {
            digest = PGPUtil.RIPEMD160;
        } else {
            digest = PGPUtil.SHA1;
        }

        PGPSecretKey pgpSecKey = PGPUtils.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), digest).setProvider("BC"));
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

        sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSecKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        InputStream fIn = new BufferedInputStream(new FileInputStream(fileName));
        ArmoredOutputStream aOut = new ArmoredOutputStream(out);

        aOut.beginClearText(digest);

        //
        // note the last \n/\r/\r\n in the file is ignored
        //
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, fIn);

        processLine(aOut, sGen, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, fIn);

                sGen.update((byte) '\r');
                sGen.update((byte) '\n');

                processLine(aOut, sGen, lineOut.toByteArray());
            }
            while (lookAhead != -1);
        }

        fIn.close();

        aOut.endClearText();

        BCPGOutputStream bOut = new BCPGOutputStream(aOut);

        sGen.generate().encode(bOut);

        aOut.close();
    }

    private static void processLine(PGPSignature sig, byte[] line)
            throws SignatureException, IOException {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    private static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line)
            throws SignatureException, IOException {
        // note: trailing white space needs to be removed from the end of
        // each line for signature calculation RFC 4880 Section 7.1
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sGen.update(line, 0, length);
        }

        aOut.write(line, 0, line.length);
    }

    private static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isLineEnding(byte b) {
        return b == '\r' || b == '\n';
    }

    private static int getLengthWithoutWhiteSpace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isWhiteSpace(byte b) {
        return isLineEnding(b) || b == '\t' || b == ' ';
    }

    /**
     * A simple utility class that creates clear signed files and verifies them.
     *
     * To sign a file: ClearSignedFileProcessor -s fileName secretKey passPhrase.
     *
     * To decrypt: ClearSignedFileProcessor -v fileName signatureFile publicKeyFile.
     */
//    public static void main(String[] args) throws Exception {
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
//                //-s fileName secretKey passPhrase
//                keyIn = PGPUtil.getDecoderStream(new FileInputStream(sign.SecretFile));
//                FileOutputStream   out = new FileOutputStream(sign.FileName + ".asc");
//                signFile(sign.FileName, keyIn, out, sign.PassPhrase.toCharArray(), sign.DigestMode);
//                break;
//
//            case "verify":
//                System.out.println("Signature Validation Command");
//                //-v fileName signatureFile publicKeyFile
//
//                if (verify.FileName.indexOf(".asc") < 0)
//                {
//                    System.err.println("file needs to end in \".asc\"");
//                    System.exit(1);
//                }
//                FileInputStream    in = new FileInputStream(verify.FileName);
//                keyIn = PGPUtil.getDecoderStream(new FileInputStream(verify.PublicKey));
//                verifyFile(in, keyIn, verify.FileName.substring(0, verify.FileName.length() - 4));
//                break;
//
//        }
//
//
//    }
}
