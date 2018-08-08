package com.beet.commands;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

@Parameters(commandDescription = "Sign File")
public class CommandSign {
    @Parameter(names = "-a", description = "Armored Output (asc)")
    public boolean ASCOutput = false;

    @Parameter(names = {"-f", "--file"}, description = "File to Sign", required = true)
    public String FileName;

    @Parameter(names = {"-k", "--secretKey"}, description = "Secret Key File", required = true)
    public String SecretFile;

    @Parameter(names = {"-p", "--passphrase"}, description = "Passphrase String Private Key", required = true)
    public String PassPhrase;

    @Parameter(names = {"-d","--digest"})
    public String DigestMode = "SHA1";
}
