package com.aarnolabs.haccs_ta2.phpexpgen;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(
    name = "run",
    version = "run 1.0",
    description = "Generate and run an exploit (end-to-end) according to the .cve.properties file",
    mixinStandardHelpOptions = true
)
public class RunEndToEnd extends BaseCmd {

    private static final int PORT = 5679;
    private static final String IP = "127.0.0.1";
    private static final String USER = "haccs";

    @Option(names = {"--cve-dir"},
            description = "The path (directory) to the CVE docker image",
            paramLabel = "cve-directory",
            required = true)
    private File cveDir;

    @Parameters(paramLabel = "<gaaphp-arg>", description = "Optional arguments to pass to gaaphp")
    private String[] gaaphpArgs = {};

    private String pathPrefix, sqlarityStr;
    private String[] args;
    private File codebaseDir;
    private Runtime rt;
    private int seed;
    private boolean registerGlobals, sqlarity, sqlarityHack, skip;

    private class StreamGobbler extends Thread {
        InputStream is;
        String type, out;

        private StreamGobbler(InputStream is, String type) {
            this.is = is;
            this.type = type;
        }

        public String getOutput() {
            return out;
        }

        @Override
        public void run() {
            StringBuilder buf = new StringBuilder();
            try {
                InputStreamReader isr = new InputStreamReader(is);
                BufferedReader br = new BufferedReader(isr);
                String line = null;
                while ((line = br.readLine()) != null) {
                    System.out.println(type + "> " + line);
                    buf.append(line + "\n");
                }
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
            out = buf.toString();
        }
    }

    public void run() throws IOException, InterruptedException {
        if (skip) {
            System.out.println("Skipping exploits for " + cve);
            return;
        }
        File userHome = getDirOrError(System.getProperty("user.home"));
        File gaaphpDir = getDirOrError(userHome, "haccs/gaaphp/StrangerTool");
        File outputJson = getFileAndDeleteIfExists(gaaphpDir, "output-egen.json");
        //File outputTxt =
        getFileAndDeleteIfExists(gaaphpDir, "output-egen.txt");

        // Run gaaphp on CVE
        List<String> gaaphpCmdArgs = new LinkedList<String>();
        gaaphpCmdArgs.add("python3");
        gaaphpCmdArgs.add("extract-attacks.py");
        gaaphpCmdArgs.add("--via-php");
        gaaphpCmdArgs.add(vulnFile.getAbsolutePath());
        gaaphpCmdArgs.add("--egen");
        gaaphpCmdArgs.add("--analysis=sql");
        for (int i = 0; i < args.length; i++) {
            gaaphpCmdArgs.add(args[i]);
        }
        if (seed >= 0) {
            gaaphpCmdArgs.add("--seed=" + seed);
        }
        if (pathPrefix != null){
            gaaphpCmdArgs.add("--pathprefix=" + pathPrefix);
        }
        if (registerGlobals) {
            gaaphpCmdArgs.add("--newtool-flags='--register_globals'");
        }
        if (sqlarity) {
            if (sqlarityStr != null) {
                gaaphpCmdArgs.add("--sqlarity");
                gaaphpCmdArgs.add(sqlarityStr);
            } else {
                String sqlarityStr = codebaseDir.getAbsolutePath();
                if (sqlarityHack)
                    sqlarityStr = sqlarityStr + "/hack";
                String sqlarityOut = runCmdReturnOut("python3 %s/sqlarity.py %s", gaaphpDir.getAbsolutePath(),
                                                     sqlarityStr);
                gaaphpCmdArgs.add("--sqlarity");
                gaaphpCmdArgs.add(sqlarityOut);
            }
        }
        runCmdInDir(gaaphpDir, 0, true, gaaphpCmdArgs.toArray(new String[0]));

        if (!outputJson.exists()) {
            throw new RuntimeException("No json output found!");
        }

        // Make sure we have json output
        boolean isValid = false;
        for (String line : Files.readAllLines(outputJson.toPath())) {
            line = line.trim();
            if (line.equals("") || line.equals("[]"))
                continue;
            isValid = true;
            break;
        }

        if (!isValid) {
            throw new RuntimeException("No valid json output found!");
        }

        // Send over json output, run comfortfuzz, and build exploit.
        String fullAddr = String.format("%s@%s", USER, IP);

        /*
         *  TODO: Remove hardcoded path, but I'll leave it for now since this code is
         *        probably going to go away at some point
         */
        File toDir = new File("/home/jeikenberry/Projects/java/haccscmd/comfortfuzz/json_out");
        Files.copy(new File(gaaphpDir, "output-egen.json").toPath(),
                   new File(toDir, String.format("egen-%s.json", cveDir.getName())).toPath(),
                   StandardCopyOption.REPLACE_EXISTING);

        //runCmd("ssh -t -p %s %s /home/%s/run_cfuzz.sh %s", 0, true, Integer.toString(PORT), fullAddr, USER, cve.toLowerCase());

        // run flask server thread
        // run docker container thread

        //waitForKeyboardInput();

        // run exploit
    }

//    private void waitForKeyboardInput() throws IOException {
//        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
//        while (true) {
//            switch (in.readLine().trim().toLowerCase()) {
//            case "n":
//            case "no":
//                System.out.println("No");
//                break;
//            case "y":
//            case "yes":
//                System.out.println("Yes");
//                break;
//            default:
//                continue;
//            }
//            break;
//        }
//    }
//
//    private int runCmd(String fmt, String... args) throws IOException, InterruptedException {
//        return runCmd(fmt, 0, args);
//    }

    private int runCmd(String fmt, long timeoutInSecs, Object... args) throws IOException, InterruptedException {
        return runCmd(fmt, timeoutInSecs, false, args);
    }

    private int runCmd(String fmt, long timeoutInSecs, boolean printOut, Object... args)
            throws IOException, InterruptedException {
        String cmd = String.format(fmt, args);
        System.out.printf("Running command '%s'...\n", cmd);
        Process p = rt.exec(cmd);
        if (printOut) {
            StreamGobbler errorGobbler = new StreamGobbler(p.getErrorStream(), "ERROR");

            // any output?
            StreamGobbler outputGobbler = new StreamGobbler(p.getInputStream(), "OUTPUT");

            // start gobblers
            outputGobbler.start();
            errorGobbler.start();
        }
        if (timeoutInSecs > 0 && !p.waitFor(timeoutInSecs, TimeUnit.SECONDS)) {
            throw new RuntimeException("Command failed to exit: " + cmd);
        }
        int exitCode = p.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException(String.format("Failed to run command [exit code = %d]: %s", exitCode, cmd));
        }
        return exitCode;
    }

    private String runCmdReturnOut(String fmt, Object... args) throws IOException, InterruptedException {
        String cmd = String.format(fmt, args);
        System.out.printf("Running command '%s'...\n", cmd);
        Process p = rt.exec(cmd);

        // any output?
        StreamGobbler outputGobbler = new StreamGobbler(p.getInputStream(), "OUTPUT");

        // start gobblers
        outputGobbler.start();

        int exitCode = p.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException(String.format("Failed to run command [exit code = %d]: %s", exitCode, cmd));
        }

        try {
            outputGobbler.join();
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return outputGobbler.getOutput().trim();
    }

    private int runCmdInDir(File dir, long timeoutInSecs, boolean printOut, String... cmd)
            throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        StringBuilder buf = new StringBuilder(cmd[0]);
        for (int i = 1; i < cmd.length; i++) {
            buf.append(" ");
            buf.append(cmd[i]);
        }
        System.out.printf("RUNNING CMD: %s\n", buf);
        pb.directory(dir);
        Process p = pb.start();
        if (printOut) {
            StreamGobbler errorGobbler = new StreamGobbler(p.getErrorStream(), "ERROR");

            // any output?
            StreamGobbler outputGobbler = new StreamGobbler(p.getInputStream(), "OUTPUT");

            // start gobblers
            outputGobbler.start();
            errorGobbler.start();
        }
        if (timeoutInSecs > 0 && !p.waitFor(timeoutInSecs, TimeUnit.SECONDS)) {
            throw new RuntimeException("Command failed to exit: " + Arrays.toString(cmd));
        }
        int exitCode = p.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException(String.format("Failed to run command [exit code = %d]: %s", exitCode, Arrays.toString(cmd)));
        }
        return exitCode;
    }

    private static File getDirOrError(String dirname) {
        return getDirOrFileOrError(new File(dirname), true);
    }

    private static File getDirOrError(File dirSuffix, String dirPrefix) {
        return getDirOrFileOrError(new File(dirSuffix, dirPrefix), true);
    }

//    private static File getFileOrError(String dirname) {
//        return getDirOrFileOrError(new File(dirname), false);
//    }

    private static File getFileOrError(File dirSuffix, String dirPrefix) {
        return getDirOrFileOrError(new File(dirSuffix, dirPrefix), false);
    }

    private static File getDirOrFileOrError(File file, boolean isDir) {
        if (!file.exists()) {
            throw new RuntimeException(String.format("Specified path '%s' is not a directory!", file.getPath()));
        }

        if (isDir) {
            if (!file.isDirectory())
                throw new RuntimeException(String.format("Specified path '%s' is not a directory!", file.getPath()));
        } else {
            if (!file.isFile())
                throw new RuntimeException(String.format("Specified path '%s' is not a file!", file.getPath()));
        }

        return file;
    }

    private static File getFileAndDeleteIfExists(File dirSuffix, String dirPrefix) {
        File result = new File(dirSuffix, dirPrefix);
        if (result.exists()) {
            if (!result.delete())
                throw new RuntimeException("Unable to delete: " + result.getPath());
        }
        return result;
    }

    @Override
    public Integer call() throws Exception {
        int result = super.call();
        if (result != 0)
            return result;

        if (!cveDir.exists()) {
            throw new RuntimeException("cve directory does not exist: " + cveDir);
        }
        if (!cveDir.isDirectory()) {
            throw new RuntimeException("specified path is not a directory: " + cveDir);
        }

        File propFile = getFileOrError(cveDir, ".cve.properties");
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(propFile)) {
            props.load(in);
        }

        File dataDir = new File(cveDir, "data");
        String vulnFilePath = getProperty(props, "vuln.file");

        registerGlobals = Boolean.valueOf(props.getProperty("register.globals", "false"));
        skip = Boolean.valueOf(props.getProperty("skip", "false"));
        sqlarity = Boolean.valueOf(props.getProperty("sqlarity", "false"));
        sqlarityStr = props.getProperty("sqlarity.string");
        sqlarityHack = Boolean.valueOf(props.getProperty("sqlarity.hack", "false"));
        pathPrefix = props.getProperty("path.prefix");
        seed = Integer.parseInt(props.getProperty("seed", "-1"));
        args = gaaphpArgs;
        rt = Runtime.getRuntime();

        codebaseDir = new File(vulnFilePath);
        while (codebaseDir.getParentFile() != null) {
            codebaseDir = codebaseDir.getParentFile();
        }
        codebaseDir = getDirOrError(dataDir, codebaseDir.getPath());

        run();

        return 0;
    }

    // this example implements Callable, so parsing, error handling and handling user
    // requests for usage help or version help can be done with one line of code.
    public static void main(String... args) throws Exception {
        int exitCode = new CommandLine(new CodebaseChecker()).execute(args);
        System.exit(exitCode);
    }

}
