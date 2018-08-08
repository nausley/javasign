package com.beet.encrypt;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;


// bcKeyGen
public class KeyGenerator {
    private static final String cmdName = "bcKeyGen";

    private static class CommonOptions {
        @Parameter(names = "-a", description = "Armored Output (asc)", order = 0)
        public boolean ArmoredOutput = false;

        @Parameter(names = {"-i", "--identity"}, description = "Key Identity Name", required = true, order = 1)
        public String Identity;

        @Parameter(names = {"-p", "--passphrase"}, required = true, description = "Passphrase String for Private Key", order = 2)
        public String PassPhrase;

        @Parameter(names = {"-o", "--output"}, description = "Output File Name",order = 3)
        public String OutputFileName = "";

        @Parameter(names = {"--help", "-h"}, help = true, description = "The help you are reading")
        public boolean help = false;
    }

    private static void exportKeyPair(
            OutputStream secretOut,
            OutputStream publicOut,
            KeyPair pair,
            String identity,
            char[] passPhrase,
            boolean armor)
            throws IOException, PGPException {
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
        CommonOptions commonOptions = new CommonOptions();
        JCommander jc = JCommander.newBuilder()
                .addObject(commonOptions)
                .args(args)
                .programName(cmdName)
                .build();

        if (commonOptions.help) {
            jc.usage();
            System.exit(0);
        }

        if (commonOptions.ArmoredOutput) System.out.println("ASC Output");

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();

        String secretFile = "secret";
        String publicFile = "pub";
        if (!commonOptions.OutputFileName.isEmpty()) {
            String outputName = commonOptions.OutputFileName;
            secretFile = outputName + "_secret";
            publicFile = outputName + "_pub";
        }

        System.out.println("secretFile: " + secretFile );
        System.out.println("publicFile: " + publicFile );

        if (commonOptions.ArmoredOutput) {
            FileOutputStream out1 = new FileOutputStream(secretFile + ".asc");
            FileOutputStream out2 = new FileOutputStream(publicFile + ".asc");

            exportKeyPair(out1, out2, kp, commonOptions.Identity, commonOptions.PassPhrase.toCharArray(), true);
        } else {
            FileOutputStream out1 = new FileOutputStream(secretFile + ".bpg");
            FileOutputStream out2 = new FileOutputStream(publicFile + ".bpg");

            exportKeyPair(out1, out2, kp, commonOptions.Identity, commonOptions.PassPhrase.toCharArray(), false);
        }


    }


}
