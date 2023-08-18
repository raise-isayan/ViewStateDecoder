package yagura.view;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import java.awt.Component;

/**
 *
 * @author isayan
 */
public class ViewStateTabEditor implements ExtensionProvidedHttpRequestEditor {

    private final ViewStateTab tabViewState;

    public ViewStateTabEditor(EditorCreationContext editorCreationContext) {
        this.tabViewState = new ViewStateTab();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabViewState.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabViewState.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.tabViewState.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabViewState.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabViewState.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabViewState.isModified();
    }

    @Override
    public HttpRequest getRequest() {
        HttpRequestResponse http = this.tabViewState.getHttpRequestResponse();
        return http.request();
    }

}
