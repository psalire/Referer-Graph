package burp;

import javax.json.JsonObjectBuilder;
import javax.json.JsonObject;
import javax.json.Json;
import java.net.URL;
import java.net.MalformedURLException;

public class JsonHelper {
    private JsonHelper() {}

    public static void addPotentialNullToJson(
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
    public static void addPotentialNullToJson(
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

    public static void addURLInformationToJson(
        JsonObjectBuilder jsonObjectBuilder,
        URL url
    ) {
        jsonObjectBuilder.add(
            "host", url.getHost()
        ).add(
            "path", url.getPath()
        ).add(
            "protocol", url.getProtocol()
        // ).add(
            // "headers", requestHeaders
        // ).add(
        //     "raw", rawRequest
        );
    }
    /**
    * Json helper. Build JSON with relevant request data
    */
    public static JsonObject getRequestJson(
        String referer,
        // JsonObject requestHeaders,
        URL requestURL,
        String rawRequest,
        Writer writer
    ) {
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        addURLInformationToJson(jsonObjectBuilder, requestURL);
        addPotentialNullToJson(jsonObjectBuilder, "query", requestURL.getQuery());

        JsonObjectBuilder refererObj = Json.createObjectBuilder();
        if (referer != null) {
            try {
                URL refererURL =  new URL(referer);
                addURLInformationToJson(refererObj, refererURL);
                addPotentialNullToJson(refererObj, "query", refererURL.getQuery());
            }
            catch (MalformedURLException e) {
                writer.printlnOut(
                    "[BurpExtender] getRequestJson(): bad referer \""+referer+"\""+
                    ". See error log."
                );
                writer.printlnErr(e.toString());
                writer.printlnErr(e.getStackTrace().toString());
            }
        }
        addPotentialNullToJson(jsonObjectBuilder, "referer", refererObj.build());

        return Json.createObjectBuilder().add(
            "requestData",
            jsonObjectBuilder.build()
        ).build();
    }
}
