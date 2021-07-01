package burp;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URL;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.json.JsonStructure;
import javax.json.JsonObject;
import javax.json.JsonArray;
import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    private Pattern reHeader;
    private Writer logOutput;
    private HttpHandler httpHandler;

    /**
    * Json helper
    */
    private void addPotentialNullToJson(
        JsonObjectBuilder jsonObjectBuilder,
        String name,
        String value
    ) {
        if (value==null) {
            jsonObjectBuilder.addNull(name);
        }
        else {
            jsonObjectBuilder.add(name, value);
        }
    }
    /**
    * Json helper
    */
    private JsonObject getRequestJson(
        String referer,
        // JsonObject requestHeaders,
        URL requestURL,
        String rawRequest
    ) {
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        String requestQuery = requestURL.getQuery();
        jsonObjectBuilder.add(
            "path", requestURL.getPath()
        // ).add(
            // "headers", requestHeaders
        ).add(
            "raw", rawRequest
        );
        addPotentialNullToJson(jsonObjectBuilder, "query", requestQuery);
        addPotentialNullToJson(jsonObjectBuilder, "referer", referer);

        return jsonObjectBuilder.build();
    }

    /**
    * implement IBurpExtender
    */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Event listeners");
        callbacks.registerHttpListener(this);
        callbacks.registerScannerListener(this);
        callbacks.registerExtensionStateListener(this);

        this.callbacks = callbacks;
        this.burpHelpers = callbacks.getHelpers();
        this.reHeader = Pattern.compile("^(.+): (.+)$");
        this.logOutput = new Writer(callbacks.getStdout(), callbacks.getStderr());
        this.httpHandler = new HttpHandler(this.logOutput);
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        this.logOutput.printlnOut(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                messageInfo.getHttpService() +
                " [" + this.callbacks.getToolName(toolFlag) + "]");

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo);
        List<String> headersList = requestInfo.getHeaders();

        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        String referer = null;

        for (int i=1; i<headersList.size(); i++) {
            String headerStr = headersList.get(i);
            try {
                Matcher matchHeader = this.reHeader.matcher(headerStr);
                matchHeader.find();
                String name = matchHeader.group(1);
                String value = matchHeader.group(2);
                if (name.equals("Referer")) {
                    // jsonObjectBuilder.add(name, value);
                    referer = value;
                    break;
                }
            }
            catch (Exception e) {
                this.logOutput.printlnOut("[BurpExtender] See error log for details. Affected header: "+headerStr);
                this.logOutput.printlnErr(e.toString());
                this.logOutput.printlnErr(e.getStackTrace().toString());
            }
        }
        String requestBody = this.logOutput.jsonToString(
            getRequestJson(
                referer,
                // jsonObjectBuilder.build(),
                requestInfo.getUrl(),
                this.burpHelpers.bytesToString(messageInfo.getRequest())
            )
        );
        this.logOutput.printlnOut(requestBody);
        this.httpHandler.postJson(requestBody);
        this.logOutput.printlnOut("--------------------");

    }

    /**
    * implement IScannerListener
    */
    @Override
    public void newScanIssue(IScanIssue issue) {
        this.logOutput.printlnOut("New scan issue: " + issue.getIssueName());
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        this.logOutput.printlnOut("Extension was unloaded");
    }
}
