package burp;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;
import java.net.MalformedURLException;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.json.JsonStructure;
import javax.json.JsonObject;
import javax.json.JsonArray;
import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    private Pattern reHeader;
    private Writer writer;
    private HttpHandler httpHandler;

    /**
    * implement IBurpExtender
    */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Event listeners");
        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);

        this.callbacks = callbacks;
        this.burpHelpers = callbacks.getHelpers();
        this.reHeader = Pattern.compile("^(.+): (.+)$");
        this.writer = new Writer(callbacks.getStdout(), callbacks.getStderr());
        this.httpHandler = new HttpHandler(this.writer);
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            return; // Only record requests with responses
        }

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo);
        IResponseInfo responseInfo = this.burpHelpers.analyzeResponse(messageInfo.getResponse());

        String requestBody = this.writer.jsonToString(
            Json.createObjectBuilder().addAll(
                JsonHelper.getRequestJson(requestInfo, this.writer)
            ).addAll(
                JsonHelper.getResponseJson(responseInfo, this.writer)
            ).build()
        );
        this.writer.printlnOut(requestBody);
        this.httpHandler.postJson(requestBody);
        this.writer.printlnOut("--------------------");
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        this.writer.printlnOut("[BurpExtender] Extension was unloaded");
    }
}
