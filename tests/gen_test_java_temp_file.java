import java.io.File;
public class Temp {
    public void create() throws Exception {
        // VULNERABLE: Insecure Temp File
        File.createTempFile("temp", ".txt");
    }
}