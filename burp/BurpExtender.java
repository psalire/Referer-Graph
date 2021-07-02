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

public class BurpExtender implements IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    private Pattern reHeader;
    private Writer writer;
    private HttpHandler httpHandler;

    /**
    * Json helper. Add a value that may be null
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
    private void addPotentialNullToJson(
        JsonObjectBuilder jsonObjectBuilder,
        String name,
        JsonObject jsonObj
    ) {
        if (jsonObj.isEmpty()) {
            jsonObjectBuilder.addNull(name);
        }
        else {
            jsonObjectBuilder.add(name, jsonObj);
        }
    }
    /**
    * Json helper. Build JSON with relevant request data
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
            "host", requestURL.getHost()
        ).add(
            "path", requestURL.getPath()
        ).add(
            "protocol", requestURL.getProtocol()
        // ).add(
            // "headers", requestHeaders
        // ).add(
        //     "raw", rawRequest
        );
        this.addPotentialNullToJson(jsonObjectBuilder, "query", requestQuery);

        JsonObjectBuilder refererObj = Json.createObjectBuilder();
        if (referer != null) {
            try {
                URL refererURL =  new URL(referer);
                refererObj.add("host", refererURL.getHost());
                refererObj.add("path", refererURL.getPath());
                refererObj.add("protocol", refererURL.getProtocol());
            }
            catch (MalformedURLException e) {
                this.writer.printlnOut(
                    "[BurpExtender] getRequestJson(): bad referer \""+referer+"\""+
                    ". See error log."
                );
                this.writer.printlnErr(e.toString());
                this.writer.printlnErr(e.getStackTrace().toString());
            }
        }
        this.addPotentialNullToJson(jsonObjectBuilder, "referer", refererObj.build());

        return Json.createObjectBuilder().add(
            "requestData",
            jsonObjectBuilder.build()
        ).build();
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
        this.writer = new Writer(callbacks.getStdout(), callbacks.getStderr());
        this.httpHandler = new HttpHandler(this.writer);
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        this.writer.printlnOut(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                messageInfo.getHttpService() +
                " [" + this.callbacks.getToolName(toolFlag) + "]");

        if (messageIsRequest) {
            return; // Only record requests with responses
        }

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo);
        IResponseInfo responseInfo = this.burpHelpers.analyzeResponse(messageInfo.getResponse());
        List<String> headersList = requestInfo.getHeaders();

        String referer = null;

        for (int i=1; i<headersList.size(); i++) {
            String headerStr = headersList.get(i);
            try {
                Matcher matchHeader = this.reHeader.matcher(headerStr);
                matchHeader.find();
                String name = matchHeader.group(1);
                String value = matchHeader.group(2);
                if (name.equals("Referer")) {
                    referer = value;
                    break;
                }
            }
            catch (Exception e) {
                this.writer.printlnOut("[BurpExtender] See error log for details. Affected header: "+headerStr);
                this.writer.printlnErr(e.toString());
                this.writer.printlnErr(e.getStackTrace().toString());
            }
        }
        String requestBody = this.writer.jsonToString(
            this.getRequestJson(
                referer,
                // jsonObjectBuilder.build(),
                requestInfo.getUrl(),
                this.burpHelpers.bytesToString(messageInfo.getRequest())
            )
        );
        this.writer.printlnOut(requestBody);
        this.httpHandler.postJson(requestBody);
        this.writer.printlnOut("--------------------");

    }

    /**
    * implement IScannerListener
    */
    @Override
    public void newScanIssue(IScanIssue issue) {
        this.writer.printlnOut("New scan issue: " + issue.getIssueName());
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        this.writer.printlnOut("Extension was unloaded");
    }
}
