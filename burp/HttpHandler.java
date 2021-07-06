package burp;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

public class HttpHandler {
    private HttpClient client;
    private Writer logOutput;
    private URI requestEndpoint;

    public HttpHandler(Writer logOutput) {
        this.client = HttpClient.newHttpClient();
        this.logOutput = logOutput;
        this.requestEndpoint = URI.create("http://localhost:8000/request");
    }

    public void postJson(String jsonStr) {
        HttpRequest request = HttpRequest.newBuilder().version(HttpClient.Version.HTTP_1_1).uri(
            this.requestEndpoint
        ).POST(
            HttpRequest.BodyPublishers.ofString(jsonStr)
        ).header(
            "Content-Type", "application/json"
        ).build();

        this.logOutput.printlnOut(request.toString());
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
}
