import java.util.List;

public class Shell {
    private static final String LS = "ls -la";

    void run(String userArg) throws Exception {
        // ruleid: java.runtime-exec-nonconstant
        Runtime.getRuntime().exec("ping -c 1 " + userArg);
        // ruleid: java.runtime-exec-nonconstant
        new ProcessBuilder("sh", "-c", userArg).start();
        // ruleid: java.runtime-exec-nonconstant
        new ProcessBuilder(List.of("git", userArg)).start();
        // ok: java.runtime-exec-nonconstant
        Runtime.getRuntime().exec("uptime");
        // ok: java.runtime-exec-nonconstant
        Runtime.getRuntime().exec(LS);
        // ok: java.runtime-exec-nonconstant
        new ProcessBuilder("git", "status").start();
    }
}
