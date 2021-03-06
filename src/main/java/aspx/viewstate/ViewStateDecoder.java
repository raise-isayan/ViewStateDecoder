package aspx.viewstate;

import extension.helpers.json.JsonUtil;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import static yagura.view.ViewStateMainFrame.mainGUI;

/**
 *
 * @author isayan
 */
public class ViewStateDecoder {
    private final static Logger logger = Logger.getLogger(ViewStateDecoder.class.getName());

    private final static java.util.ResourceBundle RELEASE = java.util.ResourceBundle.getBundle("burp/resources/release");

    private static String getVersion() {
       return RELEASE.getString("version");
    }

    /**
     * @param args the command line arguments
     */
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        String viewStateValue = null;
        boolean debug = false;
        try {
            for (String arg : args) {
                // single parameter
                if ("-v".equals(arg)) {
                    System.out.println("Version: " + getVersion());
                    System.out.println("Language: " + Locale.getDefault().getLanguage());
                    System.exit(0);
                }
                if ("-h".equals(arg)) {
                    usage();
                    System.exit(0);
                }
                if ("-gui".equals(arg)) {
                    mainGUI(args);
                    return;
                }
                String[] param = arg.split("=", 2);
                if (param.length < 2) {
                    // single parameter
                    if ("-d".equals(arg)) {
                        debug = true;
                    }
                }
                else {
                    // multi parameter
                    if ("-vs".equals(param[0])) {
                        viewStateValue = param[1];
                    }
                }
            }

            // 必須チェック
            if (viewStateValue == null) {
                System.out.println("-vs argument err ");
                usage();
                return;
            }
            else {
                if (ViewStateParser.isUrlencoded(viewStateValue)) {
                    viewStateValue = URLDecoder.decode(viewStateValue, StandardCharsets.ISO_8859_1);
                }
                ViewStateParser vs = new ViewStateParser();
                final ViewState viewState = vs.parse(viewStateValue);
                if (viewState.isEncrypted()) {
                    System.out.println("probably encrypted");
                }
                else {
                    if (viewState.isMacEnabled()) {
                        System.out.println("MAC: " + viewState.isMacEnabled());
                        System.out.println("digest: " + viewState.getDigest());
                    }
                    System.out.println(JsonUtil.prettyJson(viewState.toJson(), true));
                }
                return;
            }
        } catch (Exception ex) {
            String errmsg = String.format("%s: %s", ex.getClass().getName(), ex.getMessage());
            System.out.println(errmsg);
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            usage();
        }
    }

    private static void usage() {
        System.out.println("");
        System.out.println(String.format("Usage: java -jar %s.jar [option] -vs=viewstate", ViewStateDecoder.class.getSimpleName()));
        System.out.println("[option]");
        System.out.println("\t-h: output help.");
        System.out.println("\t-v: output version.");
        System.out.println("\t-gui: stand alone GUI mode.");
        System.out.println("\t-d: output debug log.");
        System.out.println("[command]");
        System.out.println("\t-vs=<viewState>: viewstate string");
        System.out.println("");
    }

}
