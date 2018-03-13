package haffenloher.signalbackuptools;

import org.thoughtcrime.securesms.util.Util;

import java.io.File;
import java.io.IOException;

public class Main {

    public static void main(String[] args) {
        if (args.length < 4) {
            printUsage();
        } else {
            if (Util.isStringEquals(args[0], "fixQuoteEscaping")) {
                File input  = new File(args[1]);
                File output = new File(args[2]);
                try {
                    BackupRepairer.replaceWronglyEscapedSingleQuotes(input, output, args[3]);
                } catch (IOException e) {
                    System.err.println("I/O Error: " + e.getMessage());
                }
            } else {
                System.err.println("Unrecognized option: " + args[0]);
                printUsage();
            }
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("java -jar Signal-Backup-Tools.jar fixQuoteEscaping input.backup output.backup 123456");
        System.out.println("123456 being your backup's passphrase.");
    }
}
