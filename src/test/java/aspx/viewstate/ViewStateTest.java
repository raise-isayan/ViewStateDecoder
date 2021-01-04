package aspx.viewstate;

import extend.util.external.JsonUtil;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author isayan
 */
public class ViewStateTest {

    public ViewStateTest() {
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
     * Test of parse method, of class ViewStatePaser.
     */
    @Test
    public void testParser() {
        System.out.println("Parser");
        System.out.println("Testcase1");
        {
            String viewState = "/wFn";
            ViewStateParser instance = new ViewStateParser();
            ViewState result = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(result.toJson(), true));
            
        }
        System.out.println("Testcase2");
        {
            String viewState = "/wECiAE=";
            ViewStateParser instance = new ViewStateParser();
            ViewState result = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(result.toJson(), true));
        }
        System.out.println("Testcase3");
        {
            byte[] bvs = new byte[]{(byte) 0xff, 0x01, 0x05, 0x0a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a};
            String viewState = new String(Base64.getEncoder().encode(bvs), StandardCharsets.UTF_8);
            ViewStateParser instance = new ViewStateParser();
            ViewState result = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(result.toJson(), true));
        }
        System.out.println("Testcase4");
        {
            byte[] bvs = new byte[]{(byte) 0xff, 0x01, 0x18, 0x02, 0x05, 0x1a, 0x05, 0x1b, 0x05, 0x1c, 0x05, 0x1d};
            String viewState = new String(Base64.getEncoder().encode(bvs), StandardCharsets.UTF_8);
            System.out.println("VewState:" + viewState);
            ViewStateParser instance = new ViewStateParser();
            ViewState result = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(result.toJson(), true));
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
            ViewState result = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(result.toJson(), true));
    //        assertEquals(expResult, result);        
        }
        System.out.println("Parser02");
        {
            String viewState = "/wEPDwUENTM4MWRkhsjF+62gWnhYUcEyuRwTHxGDVzA=";
            ViewStateParser instance = new ViewStateParser();
            instance.setDetailMode(true);
            ViewState result = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(result.toJson(), true));
    //        assertEquals(expResult, result);        
        }
        System.out.println("Parser03");
        {
            String viewState = "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";
            ViewStateParser instance = new ViewStateParser();
            ViewState result = instance.parse(viewState);
            System.out.println(JsonUtil.prettyJson(result.toJson(), true));        
        }

    }

}
