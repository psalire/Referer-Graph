package burp;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;
import java.net.MalformedURLException;

import java.awt.Component;
import javax.swing.SwingUtilities;

import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.json.JsonStructure;
import javax.json.JsonObject;
import javax.json.JsonArray;
import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    private Pattern reHeader = Pattern.compile("^(.+): (.+)$");
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
            this.writer.printlnOut("[BurpExtender] Ignoring, not in scope: "+requestInfo.getUrl());
            return;
        }
        IResponseInfo responseInfo = this.burpHelpers.analyzeResponse(messageInfo.getResponse());

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
}
