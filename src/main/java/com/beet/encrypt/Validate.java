package com.beet.encrypt;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

public class Validate {
    @Parameters(commandDescription = "Validation of File")
    private class CommandVerify {
        @Parameter(names = {"-f", "--file"}, description = "File to Verify", required = true)
        public String FileName;

        @Parameter(names = {"-s", "--sig"}, description = "Signature File", required = true)
        public String SignatureFile;

        @Parameter(names = {"-k", "--publickey"}, description = "Public Key File", required = true)
        public String PublicKey;
    }



    public static void main(String[] args) {

    }
}
