
import java.io.*;
import javax.xml.parsers.*;
import org.w3c.dom.Document;

public class VulnerableApp {

    public void parseXML(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // VULNERABLE: XXE (External Entities not disabled)
        DocumentBuilder builder = factory.newDocumentBuilder();
        ByteArrayInputStream input = new ByteArrayInputStream(xmlInput.getBytes("UTF-8"));
        Document doc = builder.parse(input);
    }
    
    public Object deserialize(byte[] data) throws Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        
        // VULNERABLE: Unsafe Deserialization
        return is.readObject();
    }
}
