package aspx.viewstate;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * Base Code
 *
 * @see
 * https://github.com/mono/mono/blob/master/mcs/class/referencesource/System.Web/UI/ObjectStateFormatter.cs
 * @licenses MIT license
 */
public class ViewStateParser {

    private final static Logger logger = Logger.getLogger(ViewStateParser.class.getName());

    private final static boolean DEBUG_MODE = false;

    private Charset encoding = StandardCharsets.UTF_8;

    // Optimized type tokens
    private final static byte Token_Int16 = 0x01;
    private final static byte Token_Int32 = 0x02;
    private final static byte Token_Byte = 0x03;
    private final static byte Token_Char = 0x04;
    private final static byte Token_String = 0x05;
    private final static byte Token_DateTime = 0x06;
    private final static byte Token_Double = 0x07;
    private final static byte Token_Single = 0x08;
    private final static byte Token_Color = 0x09;
    private final static byte Token_KnownColor = 0x0a;
    private final static byte Token_IntEnum = 0x0b;
    private final static byte Token_EmptyColor = 0x0c;
    private final static byte Token_Pair = 0x0f;
    private final static byte Token_Triplet = 0x10;
    private final static byte Token_Array = 0x14;
    private final static byte Token_StringArray = 0x15;
    private final static byte Token_ArrayList = 0x16;
    private final static byte Token_Hashtable = 0x17;
    private final static byte Token_HybridDictionary = 0x18;
    private final static byte Token_Type = 0x19;

    private final static byte Token_Unit = 0x1b;
    private final static byte Token_EmptyUnit = 0x1c;
    private final static byte Token_EventValidationStore = 0x1d;

    // String-table optimized strings
    private final static byte Token_IndexedStringAdd = 0x1e;
    private final static byte Token_IndexedString = 0x1f;

    // Semi-optimized (TypeConverter-based)
    private final static byte Token_StringFormatted = 0x28;

    // Semi-optimized (Types)
    private final static byte Token_TypeRefAdd = 0x29;
    private final static byte Token_TypeRefAddLocal = 0x2a;
    private final static byte Token_TypeRef = 0x2b;

    // Un-optimized (Binary serialized) types
    private final static byte Token_BinarySerialized = 0x32;

    // Optimized for sparse arrays
    private final static byte Token_SparseArray = 0x3c;

    // Constant values
    private final static byte Token_Null = 0x64;
    private final static byte Token_EmptyString = 0x65;
    private final static byte Token_ZeroInt32 = 0x66;
    private final static byte Token_True = 0x67;
    private final static byte Token_False = 0x68;

    // Format and Version
    private final static byte Marker_Format = (byte) 0xFF;
    private final static byte Marker_Version_1 = 0x01;

    private final int HASH_SIZE_IN_BYTES = 128 / 8;

    private boolean detail = false;

    public boolean getDetailMode() {
        return detail;
    }

    public void setDetailMode(boolean detail) {
        this.detail = detail;
    }

    public ViewState parse(String viewStateEncode) {
        ByteBuffer decodeBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(viewStateEncode));
        decodeBuffer.order(ByteOrder.LITTLE_ENDIAN); // Change Endian
        byte formatMarker = decodeBuffer.get();
        byte versionMarker = decodeBuffer.get();
        if (formatMarker == Marker_Format && versionMarker == Marker_Version_1) {
            JsonElement jsonRoot = decodeJsonObject(decodeBuffer);
            // hmac
            int hmac_len = decodeBuffer.remaining();
            if (hmac_len > 0) {
                byte[] hmac = new byte[hmac_len];
                decodeBuffer.get(hmac);
                ViewState viewState = new ViewState(jsonRoot, hmac);
                return viewState;
            } else {
                ViewState viewState = new ViewState(jsonRoot);
                return viewState;
            }
        } else {
            // Encrypted
            ViewState viewState = new ViewState();
            return viewState;
        }
    }

    public JsonElement decodeJsonObject(ByteBuffer bbf) {
        JsonElement decodeNode = JsonNull.INSTANCE;
        byte token = bbf.get();
        if (DEBUG_MODE) {
            System.out.println(String.format("Type:0x%02x", token));
        }
        try {
            switch (token) {
                case Token_Int16: { //?
                    if (DEBUG_MODE) {
                        System.out.println("Token_Int16");
                    }
                    short value = bbf.getShort();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Int16", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Int32: { //?
                    if (DEBUG_MODE) {
                        System.out.println("Token_Int32");
                    }
                    int value = readEncodedInt32(bbf);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Int32", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Byte: { //
                    byte value = bbf.get();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("byte", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Char: { //??
                    if (DEBUG_MODE) {
                        System.out.println("Token_Char");
                    }
                    // 2byteのケースが存在
                    //char value = bbf.getChar();
                    byte value = bbf.get();
                    if (DEBUG_MODE) {
                        System.out.println(String.format("\tchar:%c, \\u%04x", value, (int) value));
                    }
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("char", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_String: { //?
                    String value = readString(bbf);
                    if (DEBUG_MODE) {
                        System.out.println("string:" + value);
                    }
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("string", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_DateTime: { //?
                    long date_binary = bbf.getLong();
                    if (DEBUG_MODE) {
                        System.out.println("DateTime:" + date_binary);
                    }
//                    LocalDateTime value = LocalDateTime.ofInstant(Instant.ofEpochSecond(date_binary), ZoneOffset.UTC);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("DateTime", date_binary);
//                    jsonNode.addProperty("DateTime",  DateTimeFormatter.RFC_1123_DATE_TIME.format(value));
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Double: { //?
                    double value = bbf.getDouble();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Double", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Single: { //?
                    float value = bbf.getFloat();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Single", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Color: { //?
                    int value = bbf.getInt() & 0xffffffff;
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Color", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_KnownColor: { //?
                    int value = readEncodedInt32(bbf) & 0xffffffff;
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("KnownColor", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_IntEnum: { //?
                    String enumType = readTypeIdent(bbf);
                    int enumValue = readEncodedInt32(bbf);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Type", enumType);
                    jsonNode.addProperty("Value", enumValue);
                    JsonObject jsonEnum = new JsonObject();
                    jsonEnum.add("IntEnum", jsonNode);
                    decodeNode = jsonEnum;
                    break;
                }
                case Token_EmptyColor: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("Color", JsonNull.INSTANCE);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Pair: { //?
                    if (DEBUG_MODE) {
                        System.out.println("Token_Pair");
                    }
                    JsonElement jsonNode = JsonNull.INSTANCE;
                    if (detail) {
                        JsonObject jsonPairObject = new JsonObject();
                        JsonElement jsonPairFirst = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonPairFirst)) {
                            jsonPairObject.add("First", jsonPairFirst);

                        }
                        JsonElement jsonPairSecond = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonPairSecond)) {
                            jsonPairObject.add("Second", jsonPairSecond);
                        }
                        JsonObject jsonPair = new JsonObject();
                        jsonPair.add("Pair", jsonPairObject);
                        jsonNode = jsonPair;
                    } else {
                        JsonArray jsonPairArray = new JsonArray();
                        jsonPairArray.add(decodeJsonObject(bbf));
                        jsonPairArray.add(decodeJsonObject(bbf));
                        JsonObject jsonPair = new JsonObject();
                        jsonPair.add("Pair", jsonPairArray);
                        jsonNode = jsonPair;
                    }
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Triplet: { //?
                    if (DEBUG_MODE) {
                        System.out.println("Token_Triplet");
                    }
                    JsonElement jsonNode = JsonNull.INSTANCE;
                    if (detail) {
                        JsonObject jsonTripletObject = new JsonObject();
                        JsonElement jsonTripletFirst = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonTripletFirst)) {
                            jsonTripletObject.add("First", jsonTripletFirst);
                        }
                        JsonElement jsonTripletSecond = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonTripletSecond)) {
                            jsonTripletObject.add("Second", jsonTripletSecond);
                        }
                        JsonElement jsonTripletThird = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonTripletThird)) {
                            jsonTripletObject.add("Third", jsonTripletThird);
                        }
                        JsonObject jsonTriplet = new JsonObject();
                        jsonTriplet.add("Triplet", jsonTripletObject);
                        jsonNode = jsonTriplet;
                    } else {
                        JsonArray jsonTripletArray = new JsonArray();
                        JsonElement jsonTripletFirst = decodeJsonObject(bbf);
                        jsonTripletArray.add(jsonTripletFirst);
                        JsonElement jsonTripletSecond = decodeJsonObject(bbf);
                        jsonTripletArray.add(jsonTripletSecond);
                        JsonElement jsonTripletThird = decodeJsonObject(bbf);
                        jsonTripletArray.add(jsonTripletThird);
                        JsonObject jsonTriplet = new JsonObject();
                        jsonTriplet.add("Triplet", jsonTripletArray);
                        jsonNode = jsonTriplet;
                    }
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Array: {
                    String enumType = readTypeIdent(bbf);
                    int count = readEncodedInt32(bbf);
                    if (DEBUG_MODE) {
                        System.out.println("Token_Array.type:" + enumType);
                    }
                    if (DEBUG_MODE) {
                        System.out.println("Token_Array.count:" + count);
                    }
                    JsonArray jsonArray = new JsonArray();
                    for (int i = 0; i < count; i++) {
                        jsonArray.add(decodeJsonObject(bbf));
                    }
                    JsonObject jsonList = new JsonObject();
                    jsonList.add("Array" + " " + enumType, jsonArray);
                    decodeNode = jsonList;
                    break;
                }
                case Token_StringArray: {
                    int count = readEncodedInt32(bbf);
                    if (DEBUG_MODE) {
                        System.out.println("Token_StringArray.count:" + count);
                    }
                    JsonArray jsonArray = new JsonArray();
                    String[] array = new String[count];
                    for (int i = 0; i < count; i++) {
                        jsonArray.add(readString(bbf));
                    }
                    JsonObject jsonList = new JsonObject();
                    jsonList.add("StringArray", jsonArray);
                    decodeNode = jsonList;
                    break;
                }
                case Token_ArrayList: { //?
                    int count = readEncodedInt32(bbf);
                    if (DEBUG_MODE) {
                        System.out.println("Token_ArrayList.count:" + count);
                    }
                    JsonArray jsonArray = new JsonArray();
                    for (int i = 0; i < count; i++) {
                        jsonArray.add(decodeJsonObject(bbf));
                    }
                    JsonObject jsonList = new JsonObject();
                    jsonList.add("ArrayList", jsonArray);
                    decodeNode = jsonList;
                    break;
                }
                case Token_Hashtable:
                case Token_HybridDictionary: {
                    int count = readEncodedInt32(bbf);
                    if (DEBUG_MODE) {
                        System.out.println("Token_Hashtable.count:" + count);
                    }
                    JsonArray jsonArray = new JsonArray();
                    for (int i = 0; i < count; i++) {
                        JsonObject jsonMap = new JsonObject();
                        jsonMap.add("Key", decodeJsonObject(bbf));
                        jsonMap.add("Value", decodeJsonObject(bbf));
                        jsonArray.add(jsonMap);
                    }
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("Hashtable", jsonArray);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Type: {
                    String elementType = readTypeIdent(bbf);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Type", elementType);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Unit: {
                    if (DEBUG_MODE) {
                        System.out.println("Token_Unit");
                    }
                    JsonObject jsonUnit = new JsonObject();
                    int b = bbf.remaining();
                    double value = bbf.getDouble();
                    int type = bbf.getInt();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Unit", String.format("%.2f %s", value, ViewState.getUnitType(type)));
                    decodeNode = jsonNode;
                    break;
                }
                case Token_EmptyUnit: {
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("Unit", JsonNull.INSTANCE);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_EventValidationStore: {
                    byte versionHeader = bbf.get();
                    if (versionHeader != 0) {
                        throw new IllegalArgumentException("Invalid Serialized Data");
                    }
                    JsonArray jsonEvent = new JsonArray();
                    int count = readEncodedInt32(bbf);
                    for (int i = 0; i < count; i++) {
                        byte[] entry = new byte[HASH_SIZE_IN_BYTES];
                        if (bbf.remaining() >= HASH_SIZE_IN_BYTES) {
                            bbf.get(entry);
                            jsonEvent.add(ConvertUtil.toHexString(entry, true));
                        } else { // EOF
                            throw new IllegalArgumentException("Invalid Serialized Data");
                        }
                    }
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("EventValidationStore", jsonEvent);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_IndexedStringAdd: //
                case Token_IndexedString: {  //?
                    String value = readIndexedString(bbf, token);
                    if (DEBUG_MODE) {
                        System.out.println("\tindexString:" + value);
                    }
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("IndexedString", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_StringFormatted: {
                    String elementType = readTypeIdent(bbf);
                    String formattedValue = readString(bbf);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Type", elementType);
                    jsonNode.addProperty("Formatted", formattedValue);
                    JsonObject jsonFormat = new JsonObject();
                    jsonFormat.add("StringFormatted", jsonNode);
                    decodeNode = jsonFormat;
                    break;
                }
                case Token_BinarySerialized: { //?
                    int count = readEncodedInt32(bbf);
                    if (DEBUG_MODE) {
                        System.out.println("Token_BinarySerialized.count:" + count);
                    }
                    byte[] array = new byte[count];
                    bbf.get(array);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("object", new String(array, encoding));
                    decodeNode = jsonNode;
                    break;
                }
                case Token_SparseArray: { //?
                    String elementType = readTypeIdent(bbf);
                    int count = readEncodedInt32(bbf);
                    int itemCount = readEncodedInt32(bbf);
                    if (itemCount > count) {
                        throw new IllegalArgumentException("Invalid Serialized Data");
                    }
                    if (DEBUG_MODE) {
                        System.out.println("Token_SparseArray.type:" + elementType);
                    }
                    if (DEBUG_MODE) {
                        System.out.println("Token_SparseArray.count:" + count);
                    }
                    if (DEBUG_MODE) {
                        System.out.println("Token_SparseArray.itemCount:" + itemCount);
                    }
                    ArrayList<JsonElement> list = new ArrayList<>();
                    for (int i = 0; i < count; i++) {
                        list.add(JsonNull.INSTANCE);
                    }
                    for (int i = 0; i < itemCount; i++) {
                        int nextPos = readEncodedInt32(bbf);
                        if (nextPos >= count || nextPos < 0) {
                            throw new IllegalArgumentException("Invalid Serialized Data:" + nextPos);
                        }
                        list.set(nextPos, decodeJsonObject(bbf));
                    }
                    JsonArray jsonArray = new JsonArray();
                    for (int i = 0; i < list.size(); i++) {
                        jsonArray.add(list.get(i));
                    }
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("SparseArray" + " " + elementType + "[]", jsonArray);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Null: { //
                    JsonElement jsonNode = JsonNull.INSTANCE;
                    decodeNode = jsonNode;
                    break;
                }
                case Token_EmptyString: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("String", "");
                    decodeNode = jsonNode;
                    break;
                }
                case Token_ZeroInt32: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Int32", 0);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_True: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("bool", true);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_False: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("bool", false);
                    decodeNode = jsonNode;
                    break;
                }
                default: {
                    if (DEBUG_MODE) {
                        System.out.println("Mismatch token:" + String.format("0x%02x len=%d", token, bbf.remaining()));
                    }
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Unknown token", String.format("0x%02x", token));
                    decodeNode = jsonNode;
                    break;
                }
            }
            return decodeNode;
        } catch (RuntimeException ex) {
            if (DEBUG_MODE) {
                System.out.println(ex.getMessage() + ":" + StringUtil.getStackTrace(ex));
            }
        }
        return decodeNode;
    }

    private int readEncodedInt32(ByteBuffer bbf) {
        int value = 0;
        int shift = 0;
        byte readByte = 0;
        do {
            readByte = bbf.get();
            value |= (readByte & 0x7F) << shift;
            shift += 7;
        } while ((readByte & 0x80) != 0);
        return value;
    }

    public String readString(ByteBuffer bbf) {
        return readString(bbf, StandardCharsets.UTF_8);
    }

    public String readString(ByteBuffer bbf, Charset charset) {
        StringBuilder sb = new StringBuilder();
        int stringLength = readEncodedInt32(bbf);
        if (stringLength < 0) {
            throw new IllegalArgumentException("Invalid String Length");
        }
        // isEmpty
        if (stringLength == 0) {
            return "";
        }
        byte[] byteBuff = new byte[stringLength];
        ByteBuffer b = bbf.get(byteBuff, 0, stringLength);
        sb.append(new String(byteBuff, 0, stringLength, charset));
        return sb.toString();
    }

    private String readIndexedString(ByteBuffer bbf, byte token) {
        String value = "";
        switch (token) {
            case Token_IndexedString: {
                byte tableIndex = bbf.get();
                value = new String("stringReference:" + tableIndex);
                break;
            }
            default: {
                value = readString(bbf);
                break;
            }
        }
        return value;
    }

    private JsonObject readType(ByteBuffer bbf) {
        final String[] KnownTypes = new String[]{"Object", "int", "string", "bool"};
        JsonObject decodeNode = new JsonObject();
        byte token = bbf.get();
        switch (token) {
            case Token_TypeRef: {
                int typeID = readEncodedInt32(bbf);
                JsonObject jsonType = new JsonObject();
                if (typeID < KnownTypes.length) {
                    jsonType.addProperty("Type", KnownTypes[typeID]);
                } else {
                    jsonType.addProperty("Type", "Enum");
                }
                decodeNode = jsonType;
                break;
            }
            case Token_TypeRefAddLocal:
            case Token_TypeRefAdd: {
                String typeName = readString(bbf);
                JsonObject jsonType = new JsonObject();
                jsonType.addProperty("TypeRef", typeName);
                decodeNode = jsonType;
                break;
            }
            default: {
                break;
            }
        }
        return decodeNode;
    }

    private String readTypeIdent(ByteBuffer bbf) {
        JsonObject ident = readType(bbf);
        if (ident.has("Type")) {
            return ident.get("Type").getAsString();
        } else if (ident.has("TypeRef")) {
            return ident.get("TypeRef").getAsString();
        }
        return "Unknown";
    }

}
