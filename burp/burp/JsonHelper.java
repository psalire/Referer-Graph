package burp;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.json.JsonObjectBuilder;
import javax.json.JsonObject;
import javax.json.Json;
import java.net.URL;
import java.net.MalformedURLException;

public class JsonHelper {
    private static Pattern reHeader = Pattern.compile("^(.+): (.+)$");
    private JsonHelper() {}

    public static void addPotentialNullToJson(
        JsonObjectBuilder jsonObjectBuilder,
        String name,
        String value
    ) {
        jsonObjectBuilder.add(name, value==null ? "" : value);
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
    public static JsonObject getRefererJson(String referer, Writer writer) {
        JsonObjectBuilder refererObj = Json.createObjectBuilder();
        if (referer != null) {
            try {
                URL refererURL =  new URL(referer);
                addURLInformationToJson(refererObj, refererURL);
                addPotentialNullToJson(refererObj, "query", refererURL.getQuery());
            }
            catch (MalformedURLException e) {
                writer.printlnOut(
                    "[JsonHelper] getRefererJson(): bad referer \""+referer+"\""+
                    ". See error log."
                );
                writer.printlnErr(e.toString());
                writer.printlnErr(e.getStackTrace().toString());
            }
        }
        return refererObj.build();
    }
    private static String getRefererString(List<String> headersList, Writer writer) {
        for (int i=1; i<headersList.size(); i++) {
            String headerStr = headersList.get(i);
            try {
                Matcher matchHeader = reHeader.matcher(headerStr);
                matchHeader.find();
                String name = matchHeader.group(1);
                String value = matchHeader.group(2);
                if (name.equals("Referer")) {
                    return value;
                }
            }
            catch (Exception e) {
                writer.printlnOut("[BurpExtender] See error log for details. Affected header: "+headerStr);
                writer.printlnErr(e.toString());
                writer.printlnErr(e.getStackTrace().toString());
            }
        }
        return null;
    }
    /**
    * Json helper. Build JSON with relevant request data
    */
    public static JsonObjectBuilder getRequestJson(
        IRequestInfo requestInfo,
        Writer writer
    ) {
        URL requestURL = requestInfo.getUrl();
        List<String> headers = requestInfo.getHeaders();

        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        jsonObjectBuilder.add(
            "method", requestInfo.getMethod()
        ).add(
            "headers", String.join("\r\n", headers)
        );
        addURLInformationToJson(jsonObjectBuilder, requestURL);
        addPotentialNullToJson(jsonObjectBuilder, "query", requestURL.getQuery());
        addPotentialNullToJson(jsonObjectBuilder, "referer", getRefererJson(
            getRefererString(headers, writer),
            writer
        ));

        return Json.createObjectBuilder().add(
            "requestData",
            jsonObjectBuilder.build()
        );
    }
    /**
    * Json helper. Build JSON with relevant request data
    */
    public static JsonObjectBuilder getRequestJson(
        String method, String host, String path, String protocol,
        String query, String referer, Writer writer
    ) {
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        jsonObjectBuilder.add(
            "method", method
        ).add(
            "host", host
        ).add(
            "path", path
        ).add(
            "protocol", protocol
        );
        addPotentialNullToJson(jsonObjectBuilder, "query", query);
        addPotentialNullToJson(jsonObjectBuilder, "referer", getRefererJson(referer, writer));

        return Json.createObjectBuilder().add(
            "requestData",
            jsonObjectBuilder.build()
        );
    }
    /**
    * Json helper. Build JSON with relevant request data
    */
    public static JsonObjectBuilder getResponseJson(
        IResponseInfo responseInfo,
        Writer writer
    ) {
        return Json.createObjectBuilder().add(
            "responseData",
            Json.createObjectBuilder().add(
                "statusCode", responseInfo.getStatusCode()
            ).add(
                "headers", String.join("\r\n", responseInfo.getHeaders())
            )
        );
    }
    /**
    * Json helper. Build JSON with relevant request data
    */
    public static JsonObjectBuilder getResponseJson(int statusCode, Writer writer) {
        return Json.createObjectBuilder().add(
            "responseData",
            Json.createObjectBuilder().add("statusCode", statusCode)
        );
    }
    /**
    * Json helper. Build JSON with save data
    */
    public static JsonObjectBuilder getSavejson(
        String path,
        String filename,
        Writer writer
    ) {
        return Json.createObjectBuilder().add(
            "path", path
        ).add(
            "filename", filename
        );
    }
}
