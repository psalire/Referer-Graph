package burp;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.json.JsonArrayBuilder;
// import javax.json.JsonObjectBuilder;
import javax.json.JsonStructure;
// import javax.json.JsonObject;
// import javax.json.JsonArray;
import javax.json.JsonWriter;
import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private Pattern reHeader;
    private class Writer {
        private PrintWriter out;
        private PrintWriter err;

        public Writer(OutputStream stdout, OutputStream stderr) {
            this.out = new PrintWriter(stdout, true);
            this.err = new PrintWriter(stderr, true);
        }
        public void printlnOut(String str) {
            this.out.println(str);
        }
        public void printlnErr(String str) {
            this.err.println(str);
        }
        public String jsonToString(JsonStructure jsonVal) {
            StringWriter jsonStringWriter = new StringWriter();
            JsonWriter jsonWriter = Json.createWriter(jsonStringWriter);
            jsonWriter.write(jsonVal);
            jsonWriter.close();
            return jsonStringWriter.toString();
        }
    }
    private Writer output;

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
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        this.output.out.println(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                messageInfo.getHttpService() +
                " [" + callbacks.getToolName(toolFlag) + "]");

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo.getRequest());
        List<String> headersList = requestInfo.getHeaders();

        JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();

        this.output.out.println("Headers: ");
        this.output.out.println("(Size: "+headersList.size()+")");
        // this.output.out.println(headersList);
        for (int i=1; i<headersList.size(); i++) {
            String headerStr = headersList.get(i);
            // this.output.out.println(i+"\""+headerStr+"\"");
            // this.output.out.println("  Parsed:");
            try {
                Matcher matchHeader = this.reHeader.matcher(headerStr);
                matchHeader.find();
                // this.output.out.println("  "+matchHeader.group(1));
                // this.output.out.println("  "+matchHeader.group(2));
                jsonArrayBuilder.add(Json.createObjectBuilder().add(
                    matchHeader.group(1),
                    matchHeader.group(2)
                ));
            }
            catch (Exception e) {
                this.output.out.println("[ERROR] See error log. Affected header: "+headerStr);
                this.output.err.println(e);
                this.output.err.println(e.getStackTrace());
            }
        }
        this.output.out.println("--------------------");

        this.output.out.println(
            this.output.jsonToString(jsonArrayBuilder.build())
        );
    }

    /**
    * implement IScannerListener
    */
    @Override
    public void newScanIssue(IScanIssue issue) {
        this.output.out.println("New scan issue: " + issue.getIssueName());
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        this.output.out.println("Extension was unloaded");
    }
}
