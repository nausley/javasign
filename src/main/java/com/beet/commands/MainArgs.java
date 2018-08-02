package com.beet.commands;


import com.beust.jcommander.Parameter;

public class MainArgs  {
    @Parameter(names = {"--help","-h"}, help = true)
    public boolean help = false;
}
