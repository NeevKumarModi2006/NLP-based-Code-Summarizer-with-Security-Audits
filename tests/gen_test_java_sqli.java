import java.sql.*;
public class DB {
    public void query(String user) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "");
        Statement stmt = conn.createStatement();
        // VULNERABLE: SQL Injection
        String sql = "SELECT * FROM users WHERE name = '" + user + "'";
        stmt.execute(sql);
    }
}