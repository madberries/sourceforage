package com.aarnolabs.haccs_ta2.phpexpgen;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
    name = "check",
    version = "check 1.0",
    description = "Checks the sanity of a docker image against it's .cve.properties file",
    mixinStandardHelpOptions = true
)
public class CodebaseChecker extends BaseCmd {
    
    private static final int MAX_WIDTH = 80;
    
    private File codebaseDir;

    private enum Check {
        README_md, config_yml, data, doit_sh
    }

    public boolean check() throws IOException {
        boolean passed = true;
        passed = passed && check(Check.data);
        passed = passed && check(Check.README_md);
        passed = passed && check(Check.config_yml);
        passed = passed && check(Check.doit_sh);
        return passed;
    }

    private boolean check(Check data) throws IOException {
        String dataStr = data.toString().replace('_', '.');
        String status = "passed";
        switch (data) {
        case data:
            File dataDir = new File("data");
            if (!dataDir.exists()) {
                status = "data directory does not exist";
            } else if (!dataDir.isDirectory()) {
                status = "data is not a directory";
            } else {
                for (File file : dataDir.listFiles()) {
                    String filename = file.getName();
                    if (filename.equals(".") || filename.equals(".."))
                        continue;
                    if (file.isDirectory()) {
                        if (codebaseDir != null) {
                            status = "codebase is already set";
                        } else {
                            codebaseDir = file;
                        }
                    }
                }
                if (status.equals("passed")) {
                    File fullpath = new File("data", vulnFile.getPath());
                    if (!fullpath.exists()) {
                        status = "vulnerable file does not exist";
                    } else if (!fullpath.isFile()) {
                        status = "vulnerable path is not a file";
                    }
                }
            }
            break;
        case README_md:
            status = checkLines("README.md", new int[] { 1, 3 }, new String[] {
                    String.format("# %s", cve.toUpperCase()),
                    String.format("PHP exploit for %s (%s)", cve.toUpperCase(), vulnFile.getPath()) });
            break;
        case config_yml:
            status = checkLines("config.yml", new int[] { 4, 16, 26 }, new String[] { "firmware_version: " + version,
                    "exploit_name: " + cve.toUpperCase(), "cpe_product: " + cpeProduct });
            break;
        case doit_sh:
            status = checkLines("data/doit.sh", new int[] { 9, 10 }, new String[] {
                    String.format("docker build -t aarno-%s . || exit_on_error \"Couldn't build docker container\"",
                                  cve.toLowerCase()),
                    String.format("docker run --rm --privileged -p 80:80 aarno-%s", cve.toLowerCase()) });
            break;
        }
//        System.out.printf("data=\"%s\" status=\"%s\"\n", dataStr, status);
        int toRepeat = MAX_WIDTH - (dataStr.length() + status.length());
        System.out.printf("%s%s%s\n", dataStr, repeat('.', toRepeat), status);
        return status.equals("passed");
    }

    private static String repeat(char c, int repeatCount) {
        if (repeatCount <= 0) {
            throw new IllegalArgumentException("repeat count is <= 0");
        }
        StringBuffer buf = new StringBuffer();
        while (--repeatCount >= 0) {
            buf.append(c);
        }
        return buf.toString();
    }
    
    public static boolean isSorted(int[] a) {
        for (int i = 0; i < a.length - 1; i++) { 
            if (a[i] >= a[i + 1]) {
                return false;
            }
        }
        return true;
    }

    private String checkLines(String filename, int[] lineNos, String[] expected) throws IOException {
        if (!isSorted(lineNos)) {
            throw new RuntimeException("Lines are not sorted: " + Arrays.toString(lineNos));
        }
        if (lineNos.length != expected.length) {
            throw new IllegalArgumentException(
                    String.format("Line numbers and corresponding string values do not line up: %d != %d",
                                  lineNos.length, expected.length));
        }
        List<String> lines = Files.readAllLines(new File(filename).toPath());
        int curLine = 1;
        int checkLine = lineNos[0];
        int k = 0;
        for (String line : lines) {
            if (curLine == checkLine) {
                if (!line.trim().equals(expected[k++])) {
                    return "failed to match line " + curLine + ": '" + line.trim() + "' != '" + expected[k-1] + "'";
                }
                if (k >= lineNos.length)
                    return "passed";
                checkLine = lineNos[k];
            }
            curLine++;
        }
        return "passed";
    }
    
    @Override
    public Integer call() throws Exception {
        int result = super.call();
        if (result != 0)
            return result;

        if (check()) {
            System.out.println("\npassed!");
            return 0;
        } else {
            System.out.println("\nfailed!");
            return 1;
        }
    }

    // this example implements Callable, so parsing, error handling and handling user
    // requests for usage help or version help can be done with one line of code.
    public static void main(String... args) throws Exception {
        int exitCode = new CommandLine(new CodebaseChecker()).execute(args);
        System.exit(exitCode);
    }
    
}
