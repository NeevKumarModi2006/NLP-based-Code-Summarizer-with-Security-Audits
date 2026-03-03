import java.util.logging.Logger;
public class Log {
    private static final Logger logger = Logger.getLogger("Log");
    public void log(String msg) {
        // VULNERABLE: Log Injection
        logger.info("User input: " + msg);
    }
}