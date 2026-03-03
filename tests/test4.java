import java.sql.*;

public class test4{
    public void findUser(String username, Connection conn) throws SQLException {
        // CRITICAL: SQL Injection vulnerability via string concatenation
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query); 
        
        while (rs.next()) {
            System.out.println("User found: " + rs.getString("email"));
        }
    }
}