package burp;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.json.JsonObject;
import javax.json.JsonArray;
import javax.json.JsonWriter;
import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers burpHelpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private Pattern reHeader;
    private class Log {
        private PrintWriter out;
        private PrintWriter err;

        public Log(OutputStream stdout, OutputStream stderr) {
            this.out = new PrintWriter(stdout, true);
            this.err = new PrintWriter(stderr, true);
        }
        public void printlnOut(String str) {
            this.out.println(str);
        }
        public void printlnErr(String str) {
            this.err.println(str);
        }
    }
    private Log logger;

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
        this.logger = new Log(callbacks.getStdout(), callbacks.getStderr());
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // this.logger.out.println(
        //         (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
        //         messageInfo.getHttpService() +
        //         " [" + callbacks.getToolName(toolFlag) + "]");

        IRequestInfo requestInfo = this.burpHelpers.analyzeRequest(messageInfo.getRequest());
        List<String> headersList = requestInfo.getHeaders();

        JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();

        this.logger.out.println("Headers: ");
        this.logger.out.println("(Size: "+headersList.size()+")");
        this.logger.out.println(headersList);
        for (int i=1; i<headersList.size(); i++) {
            String headerStr = headersList.get(i);
            this.logger.out.println(i+"\""+headerStr+"\"");
            // this.logger.out.println("  Parsed:");
            try {
                Matcher matchHeader = this.reHeader.matcher(headerStr);
                matchHeader.find();
                // this.logger.out.println("  "+matchHeader.group(1));
                // this.logger.out.println("  "+matchHeader.group(2));
                jsonArrayBuilder.add(Json.createObjectBuilder().add(
                    matchHeader.group(1),
                    matchHeader.group(2)
                ));
            }
            catch (Exception e) {
                this.logger.out.println("[ERROR] See error log. Affected header: "+headerStr);
                this.logger.err.println(e);
                this.logger.err.println(e.getStackTrace());
            }
        }
        this.logger.out.println("--------------------");

        StringWriter jsonStringWriter = new StringWriter();
        JsonWriter jsonWriter = Json.createWriter(jsonStringWriter);
        jsonWriter.writeArray(jsonArrayBuilder.build());
        jsonWriter.close();
        this.logger.out.println(jsonStringWriter.toString());
    }

    /**
    * implement IScannerListener
    */
    @Override
    public void newScanIssue(IScanIssue issue) {
        this.logger.out.println("New scan issue: " + issue.getIssueName());
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        this.logger.out.println("Extension was unloaded");
    }
}
