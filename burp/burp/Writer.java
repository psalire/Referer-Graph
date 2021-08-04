package burp;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import javax.json.Json;
import javax.json.JsonWriter;
import javax.json.JsonStructure;

public class Writer {
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
    public PrintWriter getOut() {
        return this.out;
    }
    public PrintWriter getErr() {
        return this.err;
    }
}
