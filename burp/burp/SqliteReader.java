package burp;

import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SqliteReader {
    private Connection conn;
    private Writer writer;

    public SqliteReader(Writer writer) {
        this.writer = writer;
    }

    public void openConnection(String filepath) throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        }
        catch (ClassNotFoundException e) {
            writer.printlnOut("[SqliteReader] sendSqliteHistory(): See error log");
            writer.printlnErr(e.getMessage());
        }
        String url = "jdbc:sqlite:"+filepath;
        this.conn = DriverManager.getConnection(url);
    }

    private ResultSet executeSelectStatement(String statement) throws SQLException {
        if (this.conn == null) {
            throw new SQLException("conn==null");
        }
        Statement stmt = this.conn.createStatement();
        return stmt.executeQuery(statement);
    }

    public ResultSet selectSrcDstData() throws SQLException {
        return this.executeSelectStatement(
            "SELECT s.path AS srcPath, d.path AS dstPath, m.method AS method, sh.host AS srcHost,"
            +" dh.host AS dstHost, sp.protocol AS srcProtocol, dp.protocol AS dstProtocol FROM SrcDsts"
            +" LEFT JOIN Paths AS s ON srcPathId=s.id"
            +" LEFT JOIN Paths AS d ON dstPathid=d.id"
            +" LEFT JOIN Methods AS m ON methodId=m.id"
            +" LEFT JOIN Hosts AS sh ON s.HostId=sh.id"
            +" LEFT JOIN Hosts AS dh ON d.HostId=dh.id"
            +" LEFT JOIN Protocols AS sp ON sh.ProtocolId=sp.id"
            +" LEFT JOIN Protocols AS dp ON dh.ProtocolId=dp.id"
            // +" LEFT JOIN Headers AS shd ON requestHeadersId=shd.id"
            // +" LEFT JOIN Headers AS dhd ON responseHeadersId=dhd.id"
            // +" LEFT JOIN Queries as sq ON srcPathId=sq.PathId"
            // +" LEFT JOIN Queries as dq ON dstPathId=dq.PathId"
        );
    }

    public ResultSet selectHeaderData(String path, String host) throws SQLException {
        return this.executeSelectStatement(
            String.format(
                "SELECT h.reqHeaders, h.resHeaders FROM"
                +" (SELECT Paths.id FROM Paths JOIN Hosts ON Paths.HostId=(SELECT id FROM Hosts WHERE Host='%s') WHERE path='%s') AS p"
                +" LEFT JOIN Headers AS h ON h.PathId=p.id",
                host,
                path
            )
        );
    }

    public ResultSet selectQueryData(String path, String host) throws SQLException {
        return this.executeSelectStatement(
            String.format(
                "SELECT q.query FROM (SELECT Paths.id FROM Paths JOIN Hosts ON Paths.HostId=Hosts.id WHERE path='%s') AS p"
                +" LEFT JOIN Queries AS q ON q.PathId=p.id",
                path
            )
        );
    }

    public Connection getConnection() {
        return this.conn;
    }
    public void closeConnection() throws SQLException {
        if (this.conn!=null) {
            this.conn.close();
        }
    }
}
