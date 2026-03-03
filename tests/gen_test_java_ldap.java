import javax.naming.directory.*;
public class LDAP {
    public void search(String user) throws Exception {
        DirContext ctx = new InitialDirContext();
        // VULNERABLE: LDAP Injection
        ctx.search("ou=users,dc=example,dc=com", "(uid=" + user + ")", null);
    }
}