package burp;

import extension.burp.BurpExtenderImpl;
import java.util.logging.Logger;
import yagura.view.ViewStateDecoderTab;
import yagura.view.ViewStateTab;

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl {
    private final static Logger logger = Logger.getLogger(BurpExtender.class.getName());

    public BurpExtender() {
    }

    private final java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    @SuppressWarnings("unchecked")
    public static BurpExtender getInstance() {
        return BurpExtenderImpl.<BurpExtender>getInstance();
    }

    private final ViewStateTab viewStateTab = new ViewStateTab();
    private final ViewStateDecoderTab viewStateDecoderTab = new ViewStateDecoderTab();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        super.registerExtenderCallbacks(callbacks);
        callbacks.setExtensionName(String.format("%s v%s", BUNDLE.getString("projname"), BUNDLE.getString("version")));
        callbacks.addSuiteTab(this.viewStateDecoderTab);
        callbacks.registerMessageEditorTabFactory(this.viewStateTab);
    }

}
