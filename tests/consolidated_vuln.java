import java.io.*;
import java.sql.*;
import javax.servlet.http.*;
import java.util.logging.Logger;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;

public class VulnerableEnterpriseApp {
    private static final Logger logger = Logger.getLogger("AppLog");
    // VULN: Hardcoded Key
    private static final String AWS_KEY = "AKIAVGH213HJ12J3KH12";

    public void unsafeDBQuery(String inputUser) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://db:3306/users", "root", "root");
            Statement stmt = conn.createStatement();
            // VULN: SQL Injection
            String query = "SELECT * FROM accounts WHERE name = '" + inputUser + "'";
            stmt.execute(query);
        } catch (Exception e) { e.printStackTrace(); }
    }

    public void runSystemCmd(String cmd) {
        try {
            // VULN: Command Injection
            Runtime.getRuntime().exec(cmd);
        } catch (IOException e) { e.printStackTrace(); }
    }

    public void processXML(String pXml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // VULN: XXE
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.parse(new InputSource(new StringReader(pXml)));
        } catch (Exception e) { e.printStackTrace(); }
    }

    public Object deserializeData(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        // VULN: Insecure Deserialization
        return ois.readObject();
    }

    public void logInfo(String msg) {
        // VULN: Log Injection
        logger.info("User action: " + msg);
    }
}