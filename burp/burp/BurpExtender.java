package burp;

import java.sql.ResultSet;
import java.sql.SQLException;

import java.awt.Component;
import javax.swing.SwingUtilities;

import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    private Writer writer;
    private HttpHandler httpHandler;
    private BurpConfigUI burpUi;
    private SqliteReader sqliteReader;
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
        this.sqliteReader = new SqliteReader(this.writer);

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
        if (messageIsRequest || !this.burpUi.getIsTrafficForwarded() // Only record requests w/ responses
            || (toolFlag==IBurpExtenderCallbacks.TOOL_SCANNER && this.burpUi.getIsNoScannerTrafficForwarded())
            || (toolFlag==IBurpExtenderCallbacks.TOOL_REPEATER && this.burpUi.getIsNoRepeaterTrafficForwarded())
            ) {
            return;
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
            this.sqliteReader.openConnection(this.burpUi.getFullFilepath());
            ResultSet rs = this.sqliteReader.selectAllData();
            while (rs.next()) {
                String requestBody = this.writer.jsonToString(
                    Json.createObjectBuilder().addAll(
                        JsonHelper.getRequestJson(
                            "GET",
                            rs.getString("dstHost"),
                            rs.getString("dstPath"),
                            rs.getString("dstProtocol"),
                            rs.getString("dstQuery"),
                            rs.getString("srcProtocol")+"://"+rs.getString("srcHost")+rs.getString("srcPath"),
                            this.writer
                        )
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
            this.sqliteReader.closeConnection();
        }
        catch (SQLException e) {
            writer.printlnOut("[BurpExtender] sendSqliteHistory(): See error log");
            writer.printlnErr(e.getMessage());
        }
    }
    public void updateSqliteFilepath() {
        String requestBody = writer.jsonToString(
            JsonHelper.getSavejson(this.burpUi.getFilepath(), this.burpUi.getFilename(), writer).build()
        );
        httpHandler.postJson(requestBody, httpHandler.getUpdateFilepathEndpointURI());
    }
    public void updateSqliteOnOff(boolean isOn) {
        this.httpHandler.postJson("{}", this.httpHandler.getSqliteEndpointURI(isOn));
    }
}
