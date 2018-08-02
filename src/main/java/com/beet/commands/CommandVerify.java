package com.beet.commands;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

@Parameters(commandDescription = "Validate File")
public class CommandVerify {
//    @Parameter(names = "-a", description = "Armored Output (asc)")
//    public boolean ASCOutput = false;

    @Parameter(names = {"-f", "--file"}, description = "File to Verify", required = true)
    public String FileName;

    @Parameter(names = {"-s", "--sig"}, description = "Signature File", required = true)
    public String SignatureFile;

    @Parameter(names = {"-k", "--publickey"}, description = "Public Key File", required = true)
    public String PublicKey;
}
