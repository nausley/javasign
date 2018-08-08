package com.beet.encrypt;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

public class Sign {
    private static String cmdName = "bcSign";

    private static class HelpArg {
        @Parameter(names = {"--help", "-h"}, help = true, description = "The help you are reading")
        public boolean help = false;
    }

    private static class CommonArgs {
        @Parameter(names = {"-f", "--file"}, description = "File to Sign", required = true, order = 0)
        public String FileName;

        @Parameter(names = {"-k", "--secretkey"}, description = "Secret Key File", required = true, order = 1)
        public String SecretFile;

        @Parameter(names = {"-p", "--passphrase"}, description = "Passphrase String for Secret Key", required = true, order = 2)
        public String PassPhrase;

        @Parameter(names = {"--help", "-h"}, help = true, description = "The help you are reading")
        public boolean help = false;

    }

    @Parameters(commandDescription = "Clear Sign File")
    private static class CommandClearSign extends CommonArgs {
        @Parameter(names = {"-d", "--digest"}, description = "Possible Values: SHA1,SHA256,SHA384,SHA512,MD5,RIPEMD160")
        public String DigestMode = "SHA1";
    }

    @Parameters(commandDescription = "Sign with Detached Signature File")
    private static class CommandDetachedSign extends CommonArgs {
        @Parameter(names = "-a", description = "Armored Output (asc)")
        public boolean ASCOutput = false;

        @Parameter(names = {"-d", "--digest"}, description = "Possible Values: SHA1,SHA256,SHA384,SHA512,MD5,RIPEMD160")
        public String DigestMode = "SHA1";
    }


    public static void main(String[] args) throws PGPException, GeneralSecurityException, IOException {
        HelpArg helpArg = new HelpArg();
        CommandDetachedSign commandDetachedSign = new CommandDetachedSign();
        CommandClearSign commandClearSign = new CommandClearSign();

        JCommander jc = JCommander.newBuilder()
                .addObject(helpArg)
                .addCommand("clear", commandClearSign, "c")
                .addCommand("detached", commandDetachedSign, "d")
                .args(args)
                .programName(cmdName)
                .build();


        if (helpArg.help | jc.getParsedCommand() == null) {
            jc.usage();
            System.exit(0);
        }

        String myCommand = jc.getParsedCommand();

        switch (myCommand) {
            case "clear":
                if (commandClearSign.help) {
                    jc.usage(myCommand);
                    System.exit(0);
                }
                System.out.println("Clear Signing...");
                ClearSignedProcessor clearSignedProcessor = new ClearSignedProcessor();
                InputStream keyIn = PGPUtil.getDecoderStream(new FileInputStream(commandClearSign.SecretFile));
                FileOutputStream out = new FileOutputStream(commandClearSign.FileName + ".asc");
                clearSignedProcessor.signFile(commandClearSign.FileName, keyIn, out,
                        commandClearSign.PassPhrase.toCharArray(), commandClearSign.DigestMode);
                break;

            case "detached":
            default:
                if (commandDetachedSign.help) {
                    jc.usage(myCommand);
                    System.exit(0);
                }
                System.out.println("Detached Signing...");
                DetachedSignatureProcessor detachedSignatureProcessor = new DetachedSignatureProcessor();
                String outputFile = commandDetachedSign.FileName;
                if (commandDetachedSign.ASCOutput) {
                    outputFile += ".asc";
                } else {
                    outputFile += ".bpg";
                }
                detachedSignatureProcessor.createSignature(commandDetachedSign.FileName, commandDetachedSign.SecretFile,
                        outputFile, commandDetachedSign.PassPhrase.toCharArray(),commandDetachedSign.DigestMode,
                        commandDetachedSign.ASCOutput);

        }


    }
}
