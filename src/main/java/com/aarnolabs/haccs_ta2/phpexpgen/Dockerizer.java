package com.aarnolabs.haccs_ta2.phpexpgen;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(
    name = "dockerize",
    version = "dockerize 1.0",
    description = "Creates a docker image from an existing codebase and .cve.properties file",
    mixinStandardHelpOptions = true
)
public class Dockerizer extends BaseCmd {

    @Parameters(index = "0", description = "The path (directory) of the codebase to dockerize", paramLabel = "directory")
    private File pathToCodebase;

    @Option(names = {"-o", "--old"}, description = "If specified, uses the older PHP template")
    private boolean oldTemplate;

    public void copyFolder(Path src, Path dest, CopyOption copyOpt) throws IOException {
        try (Stream<Path> stream = Files.walk(src)) {
            stream.forEach(source -> copy(source, dest.resolve(src.relativize(source)), copyOpt));
        }
    }

    private void copy(Path source, Path dest, CopyOption copyOpt) {
        try {
            Files.copy(source, dest, copyOpt);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private void dockerize() throws IOException {
        File vulnFilePath = new File(pathToCodebase.getParentFile(), vulnFile.getPath());
        if (!vulnFilePath.exists()) {
            throw new RuntimeException("Vulnerable file does not exist: " + vulnFilePath);
        }

        File template = new File(
                oldTemplate ? "/home/jeikenberry/haccs/baseline2" : "/home/jeikenberry/haccs/baseline");
        if (!template.exists() || !template.isDirectory()) {
            throw new RuntimeException("Couldn't locate template directory: " + template);
        }

        File cveDir = new File(cve.toLowerCase());
        if (cveDir.exists()) {
            throw new RuntimeException("CVE directory already exists: " + cveDir);
        }

        File dataDir = new File(cveDir, "data");
        File workingCodebase = new File(dataDir, pathToCodebase.getName());
        System.out.printf("Copying %s template (from %s) to %s...\n", oldTemplate ? "old" : "new", template, cveDir);
        copyFolder(template.toPath(), cveDir.toPath(), LinkOption.NOFOLLOW_LINKS);
        copyFolder(pathToCodebase.toPath(), workingCodebase.toPath(), LinkOption.NOFOLLOW_LINKS);
        Files.copy(new File(".cve.properties").toPath(), new File(cveDir, ".cve.properties").toPath(),
                   StandardCopyOption.REPLACE_EXISTING);

        replaceLines(new File(cveDir, "README.md"), new int[] { 1, 3 },
                     new String[] { String.format("# %s", cve.toUpperCase()),
                             String.format("PHP exploit for %s (%s)", cve.toUpperCase(), vulnFile.getPath()) });
        replaceLines(new File(cveDir, "config.yml"), new int[] { 4, 16, 26 }, new String[] {
                "firmware_version: " + version, "exploit_name: " + cve.toUpperCase(), "cpe_product: " + cpeProduct });
        replaceLines(new File(cveDir, "data/doit.sh"), new int[] { 9, 10 }, new String[] {
                String.format("docker build -t aarno-%s . || exit_on_error \"Couldn't build docker container\"",
                              cve.toLowerCase()),
                String.format("docker run --rm --privileged -p 80:80 aarno-%s", cve.toLowerCase()) });
        String dockerLine = "COPY " + pathToCodebase.getName();
        if (oldTemplate) {
            dockerLine += "/ /var/www/html";
        } else {
            dockerLine += "/ /app";
        }
        replaceLines(new File(cveDir, "data/Dockerfile"), new int[] { 3 }, new String[] { dockerLine });
    }

    public static boolean isSorted(int[] a) {
        for (int i = 0; i < a.length - 1; i++) {
            if (a[i] >= a[i + 1]) {
                return false;
            }
        }
        return true;
    }

    private void replaceLines(File file, int[] lineNos, String[] toReplace) throws IOException {
        if (!isSorted(lineNos)) {
            throw new RuntimeException("Lines are not sorted: " + Arrays.toString(lineNos));
        }
        if (lineNos.length != toReplace.length) {
            throw new IllegalArgumentException(
                    String.format("Line numbers and corresponding string values do not line up: %d != %d",
                                  lineNos.length, toReplace.length));
        }
        List<String> lines = Files.readAllLines(file.toPath());
        for (int i = 0; i < lineNos.length; i++) {
            lines.set(lineNos[i] - 1, toReplace[i]);
        }
        try (PrintWriter out = new PrintWriter(file)) {
            for (String line : lines)
                out.println(line);
        }
    }

    @Override
    public Integer call() throws Exception {
        int result = super.call();
        if (result != 0)
            return result;

        if (!pathToCodebase.exists())
            throw new RuntimeException("Codebase does not exist: " + pathToCodebase);
        if (!pathToCodebase.isDirectory())
            throw new RuntimeException("Codebase is not a directory: " + pathToCodebase);

        dockerize();

        return 0;
    }

    // this example implements Callable, so parsing, error handling and handling user
    // requests for usage help or version help can be done with one line of code.
    public static void main(String... args) throws Exception {
        int exitCode = new CommandLine(new Dockerizer()).execute(args);
        System.exit(exitCode);
    }

}
