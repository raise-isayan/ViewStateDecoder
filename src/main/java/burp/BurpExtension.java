package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import extension.burp.BurpExtensionImpl;
import java.util.logging.Logger;
import yagura.view.ViewStateDecoderTab;
import yagura.view.ViewStateTabEditor;

/**
 *
 * @author isayan
 */
public class BurpExtension extends BurpExtensionImpl {

    private final static Logger logger = Logger.getLogger(BurpExtension.class.getName());

    public BurpExtension() {
    }

    private final java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    private final ViewStateDecoderTab viewStateDecoderTab = new ViewStateDecoderTab();

    private final HttpRequestEditorProvider requestViewStateTab = new HttpRequestEditorProvider() {
        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
            final ViewStateTabEditor tab = new ViewStateTabEditor(editorCreationContext);
            return tab;
        }
    };

    @Override
    public void initialize(MontoyaApi api) {
        super.initialize(api);
        api.userInterface().registerHttpRequestEditorProvider(this.requestViewStateTab);
        api.userInterface().registerSuiteTab(this.viewStateDecoderTab.getTabCaption(), this.viewStateDecoderTab);

    }

}
