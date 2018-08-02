package com.beet.encrypt;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;

import org.apache.commons.cli.*;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;


// bcKeyGen
public class KeyGenerator {
    private static final String cmdName = "bcKeyGen";

    private static void PrintHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(cmdName, options, true);
    }

    private static void exportKeyPair(
            OutputStream secretOut,
            OutputStream publicOut,
            KeyPair pair,
            String identity,
            char[] passPhrase,
            boolean armor)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
        if (armor) {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
        PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        secretKey.encode(secretOut);

        secretOut.close();

        if (armor) {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        PGPPublicKey key = secretKey.getPublicKey();

        key.encode(publicOut);

        publicOut.close();
    }

    public static void main(String[] args) throws Exception {
        CommandLineParser parser = new DefaultParser();
        Options options = new Options();

        options.addOption(Option.builder("a").desc("Armored Output (asc)").build());
        options.addOption(Option.builder("i")
                .longOpt("identity").hasArg().desc("Key Identity Name").required().build());
        options.addOption(Option.builder("p")
                .longOpt("passphrase").hasArg().desc("Passphrase String Private Key").required().build());
        options.addOption(Option.builder("o")
                .longOpt("out").hasArg().desc("Output File Name").build());
        options.addOption(Option.builder().longOpt("help").build());

        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            PrintHelp(options);
            System.exit(100);
        }

        if (cmd.hasOption("help")) {
            PrintHelp(options);
            System.exit(0);
        }

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(1024);

        KeyPair kp = kpg.generateKeyPair();

        String secretFile = "secret";
        String publicFile = "pub";
        if (cmd.hasOption("out")) {
            String outputName = cmd.getOptionValue("out");
            secretFile = outputName + "_secret";
            publicFile = outputName + "_pub";
        }

        if (cmd.hasOption("a")) {
            FileOutputStream out1 = new FileOutputStream(secretFile + ".asc");
            FileOutputStream out2 = new FileOutputStream(publicFile + ".asc");

            exportKeyPair(out1, out2, kp, cmd.getOptionValue("i"), cmd.getOptionValue("p").toCharArray(), true);
        } else {
            FileOutputStream out1 = new FileOutputStream(secretFile + ".bpg");
            FileOutputStream out2 = new FileOutputStream(publicFile + ".bpg");

            exportKeyPair(out1, out2, kp, cmd.getOptionValue("i"), cmd.getOptionValue("p").toCharArray(), false);
        }

//        if (args.length < 2) {
//            System.out.println("RSAKeyPairGenerator [-a] identity passPhrase");
//            System.exit(0);
//        }

//        if (args[0].equals("-a")) {
//            if (args.length < 3) {
//                System.out.println("RSAKeyPairGenerator [-a] identity passPhrase");
//                System.exit(0);
//            }
//
//            FileOutputStream out1 = new FileOutputStream("secret.asc");
//            FileOutputStream out2 = new FileOutputStream("pub.asc");
//
//            exportKeyPair(out1, out2, kp, args[1], args[2].toCharArray(), true);
//        } else {
//            FileOutputStream out1 = new FileOutputStream("secret.bpg");
//            FileOutputStream out2 = new FileOutputStream("pub.bpg");
//
//            exportKeyPair(out1, out2, kp, args[0], args[1].toCharArray(), false);
//        }
    }


}
