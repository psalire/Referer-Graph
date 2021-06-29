package burp;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
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
    private JsonObject getRequestJson(JsonArray requestHeaders, String rawRequest) {
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        jsonObjectBuilder.add("headers", requestHeaders);
        jsonObjectBuilder.add("raw", rawRequest);

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

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo.getRequest());
        List<String> headersList = requestInfo.getHeaders();

        JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();

        this.output.printlnOut("Headers: ");
        this.output.printlnOut("(Size: "+headersList.size()+")");
        // this.output.printlnOut(headersList);
        for (int i=1; i<headersList.size(); i++) {
            String headerStr = headersList.get(i);
            // this.output.printlnOut(i+"\""+headerStr+"\"");
            try {
                Matcher matchHeader = this.reHeader.matcher(headerStr);
                matchHeader.find();
                jsonArrayBuilder.add(Json.createObjectBuilder().add(
                    matchHeader.group(1),
                    matchHeader.group(2)
                ));
            }
            catch (Exception e) {
                this.output.printlnOut("[BurpExtender] See error log. Affected header: "+headerStr);
                this.output.printlnErr(e.toString());
                this.output.printlnErr(e.getStackTrace().toString());
            }
        }
        String requestBody = this.output.jsonToString(
            getRequestJson(
                jsonArrayBuilder.build(),
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
