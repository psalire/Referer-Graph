package burp;

import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.awt.Component;
import javax.swing.SwingUtilities;

import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    // private Pattern reHeader = Pattern.compile("^(.+): (.+)$");
    private Writer writer;
    private HttpHandler httpHandler;
    private BurpConfigUI burpUi;
    private final String extensionName = "Referer Graph";

    /**
    * implement IBurpExtender
    */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName(this.extensionName);
        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);

        this.callbacks = callbacks;
        this.burpHelpers = callbacks.getHelpers();
        this.writer = new Writer(callbacks.getStdout(), callbacks.getStderr());
        this.httpHandler = new HttpHandler(this.writer);
        this.burpUi = new BurpConfigUI(callbacks, BurpExtender.this, this.httpHandler, this.writer);

        // Setup Burp UI
        SwingUtilities.invokeLater(burpUi);
    }

    /**
    * implement ITab
    */
    @Override
    public String getTabCaption() {
        return this.extensionName;
    }
    @Override
    public Component getUiComponent() {
        return this.burpUi.getUiPanel();
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest || !this.burpUi.getIsTrafficForwarded()) {
            return; // Only record requests with responses & if forwarding is on
        }

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo);
        if (this.burpUi.getIsLimitInScope() && !this.callbacks.isInScope(requestInfo.getUrl())) {
            // this.writer.printlnOut("[BurpExtender] Ignoring, not in scope: "+requestInfo.getUrl());
            return;
        }
        IResponseInfo responseInfo = this.burpHelpers.analyzeResponse(messageInfo.getResponse());
        if (this.burpUi.getIsNo404TrafficForwaded() && responseInfo.getStatusCode()==404) {
            return;
        }

        String requestBody = this.writer.jsonToString(
            Json.createObjectBuilder().addAll(
                JsonHelper.getRequestJson(requestInfo, this.writer)
            ).addAll(
                JsonHelper.getResponseJson(responseInfo, this.writer)
            ).add(
                "save", this.burpUi.getIsSaveTraffic()
            ).build()
        );
        // this.writer.printlnOut(requestBody);
        this.httpHandler.postJson(requestBody);
        // this.writer.printlnOut("--------------------");
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        this.writer.printlnOut("[BurpExtender] Extension was unloaded");
    }

    /**
    * Call processHttpMessage() on getProxyHistory()
    */
    public void sendAllProxyHistory() {
        for (IHttpRequestResponse messageInfo: this.callbacks.getProxyHistory()) {
            this.processHttpMessage(0, false, messageInfo);
        }
    }
    /**
    * Send all SQLite records
    */
    public void sendSqliteHistory() {
        try {
            Class.forName("org.sqlite.JDBC");
        }
        catch (ClassNotFoundException e) {
            writer.printlnOut("[BurpExtender] sendSqliteHistory(): See error log");
            writer.printlnErr(e.getMessage());
        }
        String url = "jdbc:sqlite:"+this.burpUi.getFullFilepath();
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(url);
            if (conn == null) {
                throw new SQLException("conn==null");
            }
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT s.path AS srcPath, d.path AS dstPath, sh.host AS srcHost,"
                +" dh.host AS dstHost, sq.query AS srcQuery, dq.query AS dstQuery FROM SrcDsts"
                +" JOIN Paths AS s ON srcPathId=s.id"
                +" JOIN Paths AS d ON dstPathid=d.id"
                +" JOIN Hosts AS sh ON s.hostid=sh.id"
                +" JOIN Hosts AS dh ON d.hostid=dh.id"
                +" JOIN Queries as sq ON srcPathId=sq.PathId"
                +" JOIN Queries as dq ON dstPathId=dq.PathId"
            );
            while (rs.next()) {
                String requestBody = this.writer.jsonToString(
                    Json.createObjectBuilder().addAll(
                        JsonHelper.getRequestJson("GET", rs.getString("dstHost"), rs.getString("dstPath"), "https",
                        rs.getString("dstQuery"), "https://"+rs.getString("srcHost")+rs.getString("srcPath"), this.writer)
                    ).addAll(
                        JsonHelper.getResponseJson(200, this.writer)
                    ).add(
                        "save", this.burpUi.getIsSaveTraffic()
                    ).build()
                );
                this.writer.printlnOut(requestBody);
                this.httpHandler.postJson(requestBody);
                this.writer.printlnOut("--------------------");
            }
            conn.close();
        }
        catch (SQLException e) {
            writer.printlnOut("[BurpExtender] sendSqliteHistory(): See error log");
            writer.printlnErr(e.getMessage());
        }
    }

    public void updateSqliteOnOff(boolean isOn) {
        this.httpHandler.postIsSqliteOn(isOn);
    }
}
