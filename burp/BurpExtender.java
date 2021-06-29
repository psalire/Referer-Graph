package burp;

import java.io.PrintWriter;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.json.Json;

public class BurpExtender implements IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private Pattern reHeader;

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

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.helpers = callbacks.getHelpers();
        this.reHeader = Pattern.compile("^(.+): (.+)$");
    }

    /**
    * implement IHttpListener
    */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // stdout.println(
        //         (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
        //         messageInfo.getHttpService() +
        //         " [" + callbacks.getToolName(toolFlag) + "]");

        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo.getRequest());
        List<String> headersList = requestInfo.getHeaders();

        stdout.println("Headers: ");
        stdout.println("(Size: "+headersList.size()+")");
        stdout.println(headersList);
        for (int i=1; i<headersList.size(); i++) {
            String headerStr = headersList.get(i);
            stdout.println(i+"\""+headerStr+"\"");
            // stdout.println("  Parsed:");
            try {
                Matcher matchHeader = this.reHeader.matcher(headerStr);
                matchHeader.find();
                stdout.println("  "+matchHeader.group(1));
                stdout.println("  "+matchHeader.group(2));
            }
            catch (Exception e) {
                stdout.println("Error on matching: "+headerStr);
                stderr.println(e);
                stderr.println(e.getStackTrace());
            }
        }
        stdout.println("--------------------");
    }

    /**
    * implement IScannerListener
    */
    @Override
    public void newScanIssue(IScanIssue issue) {
        stdout.println("New scan issue: " + issue.getIssueName());
    }

    /**
    * implement IExtensionStateListener
    */
    @Override
    public void extensionUnloaded() {
        stdout.println("Extension was unloaded");
    }
}
