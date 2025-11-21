package aspx.viewstate;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import extension.helpers.ConvertUtil;

/**
 *
 * @author isayan
 */
public class ViewState {

    public static final ViewState ENCRYPTED_VIEW_STATE;
    public static final ViewState EXCEPTION_VIEW_STATE;
    public static final ViewState ILL_FORMAT_VIEW_STATE;

    static {
        // Encrypted
        JsonObject encryptedJson = new JsonObject();
        encryptedJson.addProperty("Encrypted", true);
        ENCRYPTED_VIEW_STATE = new ViewState(encryptedJson);

        // Exception
        JsonObject exceptionJson = new JsonObject();
        exceptionJson.addProperty("Exception", true);
        EXCEPTION_VIEW_STATE = new ViewState(exceptionJson);

        // Illegal Format
        JsonObject illegalFormatJson = new JsonObject();
        illegalFormatJson.addProperty("Illegal Format", true);
        ILL_FORMAT_VIEW_STATE = new ViewState(illegalFormatJson);
    }

    public static enum Algorithm {
        HMAC_UNKNOWN,
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512;

        @Override
        public String toString() {
            String value = name().toLowerCase();
            return value.replace('_', '-');
        }
    }

    private final static String[] UNIT_TYPE = {
        "pixel", // 1
        "point", // 2
        "pica", // 3
        "inch", // 4
        "mm", // 5
        "cm", // 6
        "percentage", // 7
        "em", // 8
        "ex", // 9
    };

    ViewState() {
        this.jsonRoot = JsonNull.INSTANCE;
        this.digest = new byte[0];
        this.encrypt = true;
    }

    ViewState(final JsonElement jsonRoot) {
        this(jsonRoot, new byte[0]);
    }

    ViewState(final JsonElement jsonRoot, byte[] digest) {
        this.jsonRoot = jsonRoot;
        this.digest = digest;
        this.encrypt = false;
    }

    public static String getUnitType(int unitType) {
        if (0 < unitType && unitType <= UNIT_TYPE.length) {
            return UNIT_TYPE[unitType - 1];
        }
        return "Unkown-UnitType";
    }

    private boolean encrypt;

    public boolean isEncrypted() {
        return this.encrypt;
    }

    private final JsonElement jsonRoot;

    public JsonElement toJson() {
        return jsonRoot;
    }

    public boolean isMacEnabled() {
        return this.digest.length > 0 && (getMacAlgorithm() != Algorithm.HMAC_UNKNOWN);
    }

    public Algorithm getMacAlgorithm() {
        Algorithm algorithm = Algorithm.HMAC_UNKNOWN;
        switch (digest.length) {
            case 0x20:
                algorithm = Algorithm.HMAC_SHA256;
                break;
            case 0x30:
                algorithm = Algorithm.HMAC_SHA384;
                break;
            case 0x40:
                algorithm = Algorithm.HMAC_SHA512;
                break;
        }
        return algorithm;
    }

    private final byte[] digest;

    public String getDigest() {
        return ConvertUtil.toHexString(this.digest, true);
    }

}
