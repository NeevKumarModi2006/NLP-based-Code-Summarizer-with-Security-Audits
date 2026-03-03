import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.StringReader;
public class XML {
    public void parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // VULNERABLE: XXE (feature not disabled)
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xml)));
    }
}