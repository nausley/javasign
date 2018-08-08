package com.beet.encrypt;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class Validate {
    private static String cmdName = "bcValidate";

    @Parameters(commandDescription = "Validation of File")
    private static class CommandVerify {
        @Parameter(names = {"-f", "--file"}, description = "File to Verify", required = true, order = 1)
        public String FileName;

        @Parameter(names = {"-s", "--sig"}, description = "Signature File", required = true, order = 2)
        public String SignatureFile;

        @Parameter(names = {"-k", "--publickey"}, description = "Public Key File", required = true, order = 3)
        public String PublicKey;

        @Parameter(names = {"--help","-h"}, help = true, description = "The help you are reading")
        public boolean help = false;
    }



    public static void main(String[] args) throws PGPException, GeneralSecurityException, IOException {
        CommandVerify commandVerify = new CommandVerify();

        JCommander jc = JCommander.newBuilder()
                .addObject(commandVerify)
                .args(args)
                .programName(cmdName)
                .build();

        if (commandVerify.help) {
            jc.usage();
            System.exit(0);
        }

        System.out.println("Verify Signature...");
        DetachedSignatureProcessor detachedSignatureProcessor = new DetachedSignatureProcessor();
        boolean results = detachedSignatureProcessor.verifySignature(commandVerify.FileName, commandVerify.SignatureFile,
                commandVerify.PublicKey);

        System.out.println("Signature Validation: " + results);

    }
}
