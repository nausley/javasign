package com.beet.encrypt;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

public class Sign {
    private static String cmdName = "bcSign";

    private static class HelpArg {
        @Parameter(names = {"--help","-h"}, help = true, description = "The help you are reading")
        public boolean help = false;
    }

    private static class CommonArgs {
        @Parameter(names = {"-f", "--file"}, description = "File to Sign", required = true)
        public String FileName;

        @Parameter(names = {"-k", "--secretKey"}, description = "Secret Key File", required = true)
        public String SecretFile;

        @Parameter(names = {"-p", "--passphrase"}, description = "Passphrase String for Secret Key", required = true)
        public String PassPhrase;

        @Parameter(names = {"--help","-h"}, help = true, description = "The help you are reading")
        public boolean help = false;

    }

    @Parameters(commandDescription = "Clear Sign File")
    private static class CommandClearSign extends CommonArgs {
        @Parameter(names = {"-d","--digest"})
        public String DigestMode = "SHA1";
    }

    @Parameters(commandDescription = "Sign with Detached Signature File")
    private static class CommandDetachedSign extends CommonArgs {
        @Parameter(names = "-a", description = "Armored Output (asc)")
        public boolean ASCOutput = false;
    }



    public static void main(String[] args) {

        HelpArg helpArg = new HelpArg();
        CommandDetachedSign commandDetachedSign = new CommandDetachedSign();
        CommandClearSign commandClearSign = new CommandClearSign();

        JCommander jc = JCommander.newBuilder()
                .addObject(helpArg)
                .addCommand("clear", commandClearSign,"c")
                .addCommand("detached", commandDetachedSign,"d")
                .args(args)
                .programName(cmdName)
                .build();

        if (helpArg.help | jc.getParsedCommand() == null) {
            jc.usage();
            System.exit(100);
        }

        String myCommand = jc.getParsedCommand();

        switch (myCommand) {
            case "clear":
                if (commandClearSign.help) {
                    jc.usage(myCommand);
                    System.exit(100);
                }
                System.out.println("Clear Signing...");
                // ToDO finish this section
                break;

            case "detached":
            default:
                if (commandDetachedSign.help) {
                    jc.usage(myCommand);
                    System.exit(100);
                }
                System.out.println("Detached Signing...");
                DetachedSignatureProcessor detachedSignatureProcessor = new DetachedSignatureProcessor();

        }


    }
}
