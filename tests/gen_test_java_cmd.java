import java.io.*;
public class Cmd {
    public void run(String cmd) throws IOException {
        // VULNERABLE: Command Injection
        Runtime.getRuntime().exec(cmd);
    }
}