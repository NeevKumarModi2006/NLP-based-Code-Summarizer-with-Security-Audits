import java.lang.ProcessBuilder;
public class PB {
    public void start(String arg) throws Exception {
        // VULNERABLE: Command Injection
        new ProcessBuilder("ls", arg).start();
    }
}