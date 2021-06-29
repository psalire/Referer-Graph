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
    private Writer output;
    private HttpHandler httpHandler;

    /**
    * Json helper
    */
    private JsonObject getRequestJson(
        JsonObject requestHeaders,
        URL requestURL,
        String rawRequest
    ) {
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        String requestQuery = requestURL.getQuery();
        jsonObjectBuilder.add(
            "headers", requestHeaders
        ).add(
            "path", requestURL.getPath()
        ).add(
            "raw", rawRequest
        );
        if (requestQuery==null) {
            jsonObjectBuilder.addNull("query");
        }
        else {
            jsonObjectBuilder.add("query", requestQuery);
        }

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
        this.output = new Writer(callbacks.getStdout(), callbacks.getStderr());
        this.httpHandler = new HttpHandler(this.output);
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        this.output.printlnOut(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                messageInfo.getHttpService() +
                " [" + this.callbacks.getToolName(toolFlag) + "]");

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo);
        List<String> headersList = requestInfo.getHeaders();

        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();

        for (int i=1; i<headersList.size(); i++) {
            String headerStr = headersList.get(i);
            try {
                Matcher matchHeader = this.reHeader.matcher(headerStr);
                matchHeader.find();
                jsonObjectBuilder.add(
                    matchHeader.group(1),
                    matchHeader.group(2)
                );
            }
            catch (Exception e) {
                this.output.printlnOut("[BurpExtender] See error log for stacktrace. Affected header: "+headerStr);
                this.output.printlnErr(e.toString());
                this.output.printlnErr(e.getStackTrace().toString());
            }
        }
        String requestBody = this.output.jsonToString(
            getRequestJson(
                jsonObjectBuilder.build(),
                requestInfo.getUrl(),
                this.burpHelpers.bytesToString(messageInfo.getRequest())
            )
        );
        this.output.printlnOut(requestBody);
        this.httpHandler.postJson(requestBody);
        this.output.printlnOut("--------------------");

    }

    /**
    * implement IScannerListener
    */
    @Override
    public void newScanIssue(IScanIssue issue) {
        this.output.printlnOut("New scan issue: " + issue.getIssueName());
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        this.output.printlnOut("Extension was unloaded");
    }
}
