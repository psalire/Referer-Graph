package burp;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

public class HttpHandler {
    private HttpClient client;
    private Writer output;

    public HttpHandler(Writer output) {
        this.client = HttpClient.newHttpClient();
        this.output = output;
    }

    public void postJson(String jsonStr) {
        HttpRequest request = HttpRequest.newBuilder().uri(
            URI.create("http://localhost:8000/request")
        ).POST(
            HttpRequest.BodyPublishers.ofString(jsonStr)
        ).header(
            "Content-Type", "application/json"
        ).build();

        this.client.sendAsync(
            request,
            HttpResponse.BodyHandlers.ofString()
        ).thenApply(
            HttpResponse::statusCode
        ).thenAccept(code -> {
            if (code != 200) {
                this.output.printlnErr(
                    "[HTTP] Got status code ("+code+") for JSON POST: "+jsonStr
                );
            }
        });
    }
}
