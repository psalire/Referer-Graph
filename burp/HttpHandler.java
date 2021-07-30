package burp;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

public class HttpHandler {
    private HttpClient client = HttpClient.newHttpClient();
    private Writer logOutput;
    private URI requestEndpoint;
    private URI updateFilepathEndpoint;
    private String serverAddress = "localhost";
    private String serverPort = "8000";

    public HttpHandler(Writer logOutput, String address, String port) {
        this.logOutput = logOutput;
        this.serverAddress = address;
        this.serverPort = port;
        this.setRequestEndpoint(address, port);
    }
    public HttpHandler(Writer logOutput) {
        this.logOutput = logOutput;
        this.setRequestEndpoint(this.serverAddress, this.serverPort);
    }

    /**
    * Forward request to Node server
    * @param jsonStr String raw string of JSON to POST
    */
    public void postJson(String jsonStr) {
        this.postJson(jsonStr, this.requestEndpoint);
    }
    public void postJson(String jsonStr, URI endpoint) {
        HttpRequest request = HttpRequest.newBuilder().version(HttpClient.Version.HTTP_1_1).uri(
            endpoint
        ).POST(
            HttpRequest.BodyPublishers.ofString(jsonStr)
        ).header(
            "Content-Type", "application/json"
        ).build();

        // this.logOutput.printlnOut(request.toString());
        this.client.sendAsync(
            request,
            HttpResponse.BodyHandlers.ofString()
        ).thenApply(
            HttpResponse::statusCode
        ).thenAccept((code) -> {
            if (code != 204) {
                this.logOutput.printlnOut("[HTTPHandler] Got non-200 statuscode. See error log.");
                this.logOutput.printlnErr(
                    "[HTTPHandler] Got status code ("+code+") for JSON POST:\n"+jsonStr
                );
            }
        }).whenComplete((result, exception) -> {
            if (exception != null) {
                this.logOutput.printlnOut("[HTTPHandler] Exception. See error log.");
                this.logOutput.printlnErr("[HTTPHandler] Affected request: " + jsonStr);
                this.logOutput.printlnErr(exception.toString());
                exception.printStackTrace(this.logOutput.getErr());
                this.logOutput.printlnErr("\n");
            }
        });
    }

    public void setRequestEndpoint(String address, String port) {
        this.serverAddress = address;
        this.serverPort = port;
        String url = "http://"+address+":"+port;
        this.requestEndpoint = URI.create(url+"/request");
        this.updateFilepathEndpoint = URI.create(url+"/updateFilepath");
    }
    public String getServerAddress() {
        return this.serverAddress;
    }
    public String getServerPort() {
        return this.serverPort;
    }
    public URI getRequestEndpointURI() {
        return this.requestEndpoint;
    }
    public URI getUpdateFilepathEndpointURI() {
        return this.updateFilepathEndpoint;
    }
}
