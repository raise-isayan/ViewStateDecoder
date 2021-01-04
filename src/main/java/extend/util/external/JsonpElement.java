package extend.util.external;

import com.google.gson.JsonElement;
import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class JsonpElement {

    private JsonpElement() {    
    }
    
    private final static Pattern JSONP_TYPE = Pattern.compile("\\s*([\\w\\$\\.]+)\\s*\\(\\s*(\\{.*?\\}|\\[.*?\\])\\s*\\)([;]*)", Pattern.DOTALL);
    
    public static JsonpElement parseJsonp(String jsonpString) throws JsonSyntaxException {
        Matcher m = JSONP_TYPE.matcher(jsonpString);
        if (m.lookingAt()) {
            JsonpElement jsonp = new JsonpElement();    
            jsonp.raw = m.group(0);
            jsonp.callbackName = m.group(1);
            jsonp.jsonElement = JsonUtil.parse(m.group(2));
            return jsonp;
        }        
        throw new JsonSyntaxException("jsonp invalid format");
    }

    private String raw;

    public String getRaw() {
        return raw;
    }

    private String callbackName;
    
    public String getCallbackName() {
        return callbackName;
    }

    private JsonElement jsonElement;
    
    public JsonElement getJsonElement() {
        return jsonElement;
    }

    public String pretty() throws IOException {
        StringBuilder buff = new StringBuilder();
        buff.append(callbackName);
        buff.append("(\n");
        buff.append(JsonUtil.prettyJson(jsonElement, true));
        buff.append("\n)");
        return buff.toString();
    }
    
}
