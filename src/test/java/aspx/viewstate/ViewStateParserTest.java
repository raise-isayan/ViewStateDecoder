package aspx.viewstate;

import aspx.viewstate.ViewState.Algorithm;
import com.google.gson.JsonElement;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author isayan
 */
public class ViewStateParserTest {

    public ViewStateParserTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of parse method, of class ViewStatePaser
     * http://viewstatedecoder.azurewebsites.net/
     */
    @Test
    public void testParser() {
        System.out.println("Parser");
        System.out.println("Testcase1");
        {
            String viewState = "/wFn";
            ViewStateParser instance = new ViewStateParser();
            ViewState vs = instance.parse(viewState);
            JsonElement rootJson = vs.toJson();
            System.out.println(JsonUtil.prettyJson(rootJson, true));
            boolean result = rootJson.getAsJsonObject().get("bool").getAsBoolean();
            assertEquals(Algorithm.HMAC_UNKNOWN, vs.getMacAlgorithm());
            assertEquals(true, result);
        }
        System.out.println("Testcase2");
        {
            String viewState = "/wECiAE=";
            ViewStateParser instance = new ViewStateParser();
            ViewState vs = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(vs.toJson(), true));
            JsonElement rootJson = vs.toJson();
            int result = rootJson.getAsJsonObject().get("Int32").getAsInt();
            assertEquals(136, result);
            assertEquals(Algorithm.HMAC_UNKNOWN, vs.getMacAlgorithm());
            assertEquals(false, vs.isMacEnabled());
        }
        System.out.println("Testcase3");
        {
            byte[] bvs = new byte[]{(byte) 0xff, 0x01, 0x05, 0x0a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a};
            String viewStateB64 = new String(Base64.getEncoder().encode(bvs), StandardCharsets.UTF_8);
            ViewStateParser instance = new ViewStateParser();
            System.out.println("VewState3:" + viewStateB64);
            ViewState vs = instance.parse(viewStateB64);
            System.out.println(JsonUtil.prettyJson(vs.toJson(), true));
            assertEquals("/wEFCmFiY2RlZmdoaWo=", viewStateB64);
            assertEquals(Algorithm.HMAC_UNKNOWN, vs.getMacAlgorithm());
            assertEquals(false, vs.isMacEnabled());
        }
        System.out.println("Testcase4");
        {
            byte[] bvs = new byte[]{(byte) 0xff, 0x01, 0x18, 0x02, 0x05, 0x1a, 0x05, 0x1b, 0x05, 0x1c, 0x05, 0x1d};
            String viewStateB64 = new String(Base64.getEncoder().encode(bvs), StandardCharsets.UTF_8);
            System.out.println("VewState4:" + viewStateB64);
            ViewStateParser instance = new ViewStateParser();
            ViewState vs = instance.parse(viewStateB64);
            System.out.println(JsonUtil.prettyJson(vs.toJson(), true));
            assertEquals("/wEYAgUaBRsFHAUd", viewStateB64);
            assertEquals(Algorithm.HMAC_UNKNOWN, vs.getMacAlgorithm());
            assertEquals(false, vs.isMacEnabled());
        }

    }

    /**
     * Test of ViewState method, of class ViewStatePaser.
     */
    @Test
    public void testViewState() {
        System.out.println("ViewState");
        System.out.println("Parser01");
        {
            String viewState = "/wEPDwUKLTM0MjUyMzM2OWRkmW75zyss5UROsLtrTEuOq7AGUDk=";
            ViewStateParser instance = new ViewStateParser();
            ViewState vs = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(vs.toJson(), true));
            JsonElement rootJson = vs.toJson();
            String result = rootJson.getAsJsonObject().get("Pair").getAsJsonArray().get(0).getAsJsonObject().get("Pair").getAsJsonArray().get(0).getAsJsonObject().get("string").getAsString();
            assertEquals("-342523369", result);
            assertEquals("996EF9CF2B2CE5444EB0BB6B4C4B8EABB0065039", vs.getDigest());
            assertEquals(Algorithm.HMAC_SHA256, vs.getMacAlgorithm());
            assertEquals(true, vs.isMacEnabled());
        }
        System.out.println("Parser02");
        {
            String viewState = "/wEPDwUENTM4MWRkhsjF+62gWnhYUcEyuRwTHxGDVzA=";
            ViewStateParser instance = new ViewStateParser();
            instance.setDetailMode(true);
            ViewState vs = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(vs.toJson(), true));
            assertEquals("86C8C5FBADA05A785851C132B91C131F11835730", vs.getDigest());
            assertEquals(Algorithm.HMAC_SHA256, vs.getMacAlgorithm());
            assertEquals(true, vs.isMacEnabled());
        }
        System.out.println("Parser03");
        {
            String viewState = "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";
            ViewStateParser instance = new ViewStateParser();
            ViewState vs = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(vs.toJson(), true));
            System.out.println("Digest:" + vs.getDigest());
            assertEquals(Algorithm.HMAC_UNKNOWN, vs.getMacAlgorithm());
//            assertEquals(false, vs.isMacEnabled());
        }

        System.out.println("Parser20");
        {
            try {
                String viewStateB64 = "/wEPDwUENTM4MWRkhsjF+62gWnhYUcEyuRwTHxGDVzA=&__EVENT=xxxxx";
                ViewStateParser instance = new ViewStateParser();
                ViewState vs = instance.parse(viewStateB64);
                System.out.println(JsonUtil.prettyJson(vs.toJson(), true));
                assertEquals(true, vs.isEncrypted());
                assertEquals(Algorithm.HMAC_UNKNOWN, vs.getMacAlgorithm());
                fail();
            } catch (IllegalArgumentException ex) {
                System.out.println(StringUtil.getStackTrace(ex));
            }
        }
        System.out.println("Parser21");
        {
            try {
                String viewStateB64 = "ZU1VanBjYUFOWGlGcElTcGtwQ3dWSndXY3NtZ05XNEZscWtsOUlWcjlxV01iYUFOYW92eTJOSkh6MnNadmNCTG9kRGdBbTVrUWNhQ2ZKdnh0d0t0eUtLMmwzY29GMTY5UzR6WnpLY1JWUTEzaWhVNW12VG44YkllZmlGUjZSZTJ4ZDVkcEp2VVp5bDBpVEVucUdDaFVwdUlteTJsZ1VMRkpCRnZjWGRnUDJqTXRIdWsxVkJoZ0NSM01aQWd5NW5KUnVlbDlJbDF6Y1M3R21rS05ZV241bHhkOEJDSU1yVHJIRlBTSEl5SFVaWjhLNFFMRVF2QzZ5MmdvWG1STDBaRg==";
                ViewStateParser instance = new ViewStateParser();
                ViewState vs = instance.parse(viewStateB64);
                System.out.println(JsonUtil.prettyJson(vs.toJson(), true));
                assertEquals(true, vs.isEncrypted());
                assertEquals(Algorithm.HMAC_UNKNOWN, vs.getMacAlgorithm());
            } catch (IllegalArgumentException ex) {
                System.out.println(StringUtil.getStackTrace(ex));
            }
        }

    }

}
