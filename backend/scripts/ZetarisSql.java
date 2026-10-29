import java.sql.*;
import java.util.*;

/** Runs Zetaris Lightning SQL statements over JDBC, one statement per call. Credentials come from the environment. */
public class ZetarisSql {
    public static void main(String[] args) throws Exception {
        String url = System.getenv("ZURL"), user = System.getenv("ZUSER"), pass = System.getenv("ZPASS");
        Class.forName("com.zetaris.lightning.jdbc.LightningDriver");
        try (Connection c = DriverManager.getConnection(url, user, pass)) {
            for (String sql : args) {
                String shown = sql.replaceAll("\\s+", " ");
                shown = shown.length() > 110 ? shown.substring(0, 110) + "..." : shown;
                try (Statement st = c.createStatement()) {
                    boolean hasRows = st.execute(sql);
                    System.out.println("OK    " + shown);
                    if (hasRows) {
                        try (ResultSet rs = st.getResultSet()) {
                            ResultSetMetaData md = rs.getMetaData();
                            int shownRows = 0;
                            while (rs.next() && shownRows++ < 8) {
                                List<String> cols = new ArrayList<>();
                                for (int i = 1; i <= md.getColumnCount(); i++) cols.add(String.valueOf(rs.getObject(i)));
                                System.out.println("        " + String.join(" | ", cols));
                            }
                        }
                    }
                } catch (SQLException e) {
                    System.out.println("FAIL  " + shown + "\n        " + String.valueOf(e.getMessage()).split("\n")[0]);
                }
            }
        }
    }
}
