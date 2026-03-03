import java.io.*;
public class Deser {
    public Object read(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        // VULNERABLE: Insecure Deserialization
        return ois.readObject();
    }
}