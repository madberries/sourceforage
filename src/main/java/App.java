import java.util.concurrent.Callable;

import com.aarnolabs.haccs_ta2.phpexpgen.CodebaseChecker;
import com.aarnolabs.haccs_ta2.phpexpgen.Dockerizer;
import com.aarnolabs.haccs_ta2.phpexpgen.RunEndToEnd;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
    name = "haccscmd",
    version = "haccscmd 1.0",
    description = "Set of CLI tools for automatically generating PHP exploits",
    subcommands = { Dockerizer.class, RunEndToEnd.class, CodebaseChecker.class },
    mixinStandardHelpOptions = true
)
public class App implements Callable<Integer> {

    public static void main(String[] args) {
        int exitCode = new CommandLine(new App()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        // A no-args call should just print this usage (to be helpful!)
        CommandLine.usage(this, System.out);
        return 0;
    }

}
