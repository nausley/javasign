package convert;

import java.text.SimpleDateFormat;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

import org.apache.commons.cli.*;
import org.apache.commons.lang3.StringUtils;


public class PT2Date {
    public static void main(String[] args)  {
        CommandLineParser parser = new DefaultParser();
        Options options = new Options();
        options.addOption(Option.builder().hasArg().required().longOpt("p1").build());
        options.addOption(Option.builder().hasArg().required().longOpt("p2").build());
        options.addOption(Option.builder("d").longOpt("debug").build());
        options.addOption(Option.builder("u").longOpt("unix").build());
        try {


		    CommandLine cmd = parser.parse(options, args);
            if (cmd.hasOption("help")) {
                PrintHelp(options);
                return;
            }
		    int p1 = Integer.parseInt(cmd.getOptionValue("p1"));
            String baseP1 = get32Bits(Integer.toBinaryString(p1));
            if (cmd.hasOption("d")) {
                System.out.println(p1);
                System.out.println(baseP1);
            }


		    String date = "";
		    String time = "";
		    for (int i=0; i<6; i++) {
		        String x = StringUtils.substring(baseP1,i*4,i*4+4);
		        date += Integer.parseInt(x, 2);
		    }

		    for (int i=6; i<8; i++) {
		        String x = StringUtils.substring(baseP1,i*4,i*4+4);
		        time += Integer.parseInt(x, 2);
		    }

            if (cmd.hasOption("d")) {
                System.out.println("YYMMDD: " + date);
                System.out.println();
            }

            date += "-";

		    int p2 = Integer.parseInt(cmd.getOptionValue("p2"));;
            String baseP2 = get32Bits(Integer.toBinaryString(p2));
            if (cmd.hasOption("d")) {
                System.out.println(p2);
                System.out.println(baseP2);
            }


		    for (int i=0; i<4; i++) {
		        String x = StringUtils.substring(baseP2,i*4,i*4+4);
		        time += Integer.parseInt(x, 2);
		    }

            // System.out.println("HHMMSS: " + time);
            time += ".";

		    for (int i=4; i<7; i++) {
		        String x = StringUtils.substring(baseP2,i*4,i*4+4);
		        time += Integer.parseInt(x, 2);
		    }
            if (cmd.hasOption("d"))  System.out.println("HHMMSS.sss: " + time);

            // String strDate = "Jun 13 2003 23:11:52.454 UTC";
            // DateTimeFormatter dtf  = DateTimeFormatter.ofPattern("MMM dd yyyy HH:mm:ss.SSS zzz");
            // 180724-061018.3330           
            if (cmd.hasOption("u")) {
                String strDate = date + time + " UTC";
                SimpleDateFormat df = new SimpleDateFormat("YYMMdd-HHmmss.SSS zzz");
                Date dateValue = df.parse(strDate);
                long epoch = dateValue.getTime();
                System.out.println(epoch);
            }
            else System.out.println(date + time);
            
	} catch (NumberFormatException e) {
        // TODO Auto-generated catch block
		e.printStackTrace();
	} catch (ParseException e) {
        System.out.println("Missing required options");
        PrintHelp(options);
		// e.printStackTrace();
	} catch (java.text.ParseException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}

    }

    private static String get32Bits(String inStr) {
        return StringUtils.leftPad(inStr,32,"0");
    }

    private static void PrintHelp (Options opt) {
        HelpFormatter formatter = new HelpFormatter();
//        String clsName = this.getClass().getName().toLowerCase();
        formatter.printHelp("pt2date", opt, true );
    }


}
