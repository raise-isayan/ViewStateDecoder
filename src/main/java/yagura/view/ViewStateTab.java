package yagura.view;

import aspx.viewstate.ViewState;
import aspx.viewstate.ViewStateParser;
import burp.BurpExtender;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import burp.IRequestInfo;
import extension.helpers.ConvertUtil;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import extension.helpers.json.JsonUtil;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.Icon;
import javax.swing.SwingWorker;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
//import yagura.model.UniversalViewProperty;

/**
 *
 * @author isayan
 */
public class ViewStateTab extends javax.swing.JPanel implements IMessageEditorTabFactory, IMessageEditorTab {

    private IMessageEditorController controller = null;
    
    /**
     * Creates new form ViewStateTab
     */
    public ViewStateTab() {
        initComponents();
        customizeComponents();
    }
    
    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        popMenu = new javax.swing.JPopupMenu();
        popCopyMenu = new javax.swing.JMenuItem();
        jSeparator1 = new javax.swing.JPopupMenu.Separator();
        popExpandMenu = new javax.swing.JMenuItem();
        popCollapseMenu = new javax.swing.JMenuItem();
        tabViewStateView = new javax.swing.JTabbedPane();
        pnlViewState = new javax.swing.JPanel();
        scrollViewState = new javax.swing.JScrollPane();
        treeViewState = new javax.swing.JTree();
        pnlHeader = new javax.swing.JPanel();
        btnExpand = new javax.swing.JButton();
        btnCollapse = new javax.swing.JButton();
        scrollJSON = new javax.swing.JScrollPane();
        txtJSON = new javax.swing.JTextArea();

        popCopyMenu.setText("Copy");
        popCopyMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popCopyMenuActionPerformed(evt);
            }
        });
        popMenu.add(popCopyMenu);
        popMenu.add(jSeparator1);

        popExpandMenu.setText("expand");
        popExpandMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popExpandMenuActionPerformed(evt);
            }
        });
        popMenu.add(popExpandMenu);

        popCollapseMenu.setText("collapse");
        popCollapseMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                popCollapseMenuActionPerformed(evt);
            }
        });
        popMenu.add(popCollapseMenu);

        setLayout(new java.awt.BorderLayout());

        pnlViewState.setLayout(new java.awt.BorderLayout());

        javax.swing.tree.DefaultMutableTreeNode treeNode1 = new javax.swing.tree.DefaultMutableTreeNode("root");
        treeViewState.setModel(new javax.swing.tree.DefaultTreeModel(treeNode1));
        scrollViewState.setViewportView(treeViewState);

        pnlViewState.add(scrollViewState, java.awt.BorderLayout.CENTER);

        pnlHeader.setLayout(new javax.swing.BoxLayout(pnlHeader, javax.swing.BoxLayout.LINE_AXIS));

        btnExpand.setText("expand");
        btnExpand.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnExpandActionPerformed(evt);
            }
        });
        pnlHeader.add(btnExpand);

        btnCollapse.setText("collapse");
        btnCollapse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCollapseActionPerformed(evt);
            }
        });
        pnlHeader.add(btnCollapse);

        pnlViewState.add(pnlHeader, java.awt.BorderLayout.PAGE_START);

        tabViewStateView.addTab("ViewState", pnlViewState);

        txtJSON.setEditable(false);
        txtJSON.setColumns(20);
        txtJSON.setRows(5);
        scrollJSON.setViewportView(txtJSON);

        tabViewStateView.addTab("Raw JSON", scrollJSON);

        add(tabViewStateView, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents
    
    @SuppressWarnings("unchecked")
    private void customizeComponents() {
        //this.txtJSON.setComponentPopupMenu(this.popMenu);
        this.treeViewState.setComponentPopupMenu(this.popMenu);
        this.treeViewState.getActionMap().put("copy", copyAction);
        Icon emptyIcon = SwingUtil.createEmptyIcon();
        DefaultTreeCellRenderer renderer = (DefaultTreeCellRenderer) this.treeViewState.getCellRenderer();
        renderer.setOpenIcon(emptyIcon);
        renderer.setClosedIcon(emptyIcon);
        renderer.setLeafIcon(emptyIcon);
        this.clearViewState();
    }
    
    private final Action copyAction = new AbstractAction() {
        public void actionPerformed(ActionEvent evt) {
            TreePath selectionPath = treeViewState.getSelectionPath();
            if (selectionPath != null) {
                Object[] paths = selectionPath.getPath();
                Object x = paths[paths.length - 1];
                SwingUtil.systemClipboardCopy(x.toString());                        
            }
        }
    };
        
    private void btnExpandActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExpandActionPerformed
        this.expandJsonTree();
    }//GEN-LAST:event_btnExpandActionPerformed

    private void btnCollapseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCollapseActionPerformed
        this.collapseJsonTree();
    }//GEN-LAST:event_btnCollapseActionPerformed

    private void popCopyMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_popCopyMenuActionPerformed
        this.copyAction.actionPerformed(evt);
    }//GEN-LAST:event_popCopyMenuActionPerformed

    private void popExpandMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_popExpandMenuActionPerformed
        this.expandJsonTree();
    }//GEN-LAST:event_popExpandMenuActionPerformed

    private void popCollapseMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_popCollapseMenuActionPerformed
        this.collapseJsonTree();
    }//GEN-LAST:event_popCollapseMenuActionPerformed

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        this.controller = controller;
        return this;
    }

    @Override
    public String getTabCaption() {
        return "ViewState";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isMessageRequest) {
        if (!isMessageRequest) {
            return false;
        }        
        if (content == null || content.length == 0) {
            return false;
        }
//        UniversalViewProperty viewProperty = BurpExtender.getInstance().getProperty().getEncodingProperty();	
//        EnumSet<UniversalViewProperty.UniversalView> view = viewProperty.getMessageView();	
//        if (!view.contains(UniversalViewProperty.UniversalView.VIEW_STATE)) {	
//            return false;	
//        }	
//        // パラメータ値のサイズではなく全体のサイズで判断する	
//        if ( content.length > viewProperty.getDispayMaxLength() && viewProperty.getDispayMaxLength() != 0) {	
//            return false;	
//        }
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(content);
        List<IParameter> parameters = reqInfo.getParameters();
        for (IParameter p : parameters) {
            if (p.getType() == IParameter.PARAM_BODY) {
                if ("__VIEWSTATE".equals(p.getName()) && !"".equals(p.getValue())) {                  
                    return true;
                }
            }
        }        
        return false;
    }

    private byte [] message = null;
    
    @Override
    public void setMessage(byte[] content, boolean isMessageRequest) {
        this.message = content;
        if (content != null) {
            String viewStateValue = null;
            IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(content);
            List<IParameter> parameters = reqInfo.getParameters();
            for (IParameter p : parameters) {
                if (p.getType() == IParameter.PARAM_BODY) {
                    if ("__VIEWSTATE".equals(p.getName()) && !"".equals(p.getValue())) {
                        viewStateValue = p.getValue();
                        break;
                    }
                }
            }        
            setViewState(viewStateValue);
        }
    }

    @Override
    public byte[] getMessage() {
        if (this.message != null) {
            return this.message;
        } else {
            return new byte[]{};
        }
    }

    private final ViewStateModel ILL_FORMAT_VIEW_STATE_MODEL = new ViewStateModel(ViewState.ILL_FORMAT_VIEW_STATE, "viewState");
    private final ViewStateModel EXCEPTION_VIEW_STATE_MODEL = new ViewStateModel(ViewState.EXCEPTION_VIEW_STATE, "viewState");

    public void setViewState(String viewStateValue) {
        if (viewStateValue == null) {
            return ;
        }
        try {
            this.clearViewState();
            if (ViewStateParser.isUrlencoded(viewStateValue)) {
                viewStateValue = URLDecoder.decode(viewStateValue, StandardCharsets.ISO_8859_1);
            }
            final ViewStateParser vs = new ViewStateParser();
            final String viewStateDecode = viewStateValue;
            // Tree View
            final SwingWorker swTree = new SwingWorker<ViewStateModel, Object>() {
                @Override
                protected ViewStateModel doInBackground() {
                    try {
                        publish("...");
                        final ViewState viewState = vs.parse(viewStateDecode);
                        publish("...", "...");
                        if (viewState.isEncrypted()) {
                            return EXCEPTION_VIEW_STATE_MODEL;
                        }
                        else {
                            String enabled = viewState.isMacEnabled() ? "[MAC enabled]" :  "[MAC disnabled]";
                            return new ViewStateModel(viewState, "viewState" + " - " + enabled);
                        }
                    } catch (IllegalArgumentException ex) {
                        Logger.getLogger(ViewStateTab.class.getName()).log(Level.INFO, ex.getMessage(), ex);
                        return ILL_FORMAT_VIEW_STATE_MODEL;
                    } catch (Exception ex) {
                        Logger.getLogger(ViewStateTab.class.getName()).log(Level.WARNING, ex.getMessage(), ex);
                        return EXCEPTION_VIEW_STATE_MODEL;
                    }                    
                }

                protected void process(List<Object> chunks) {
                    treeViewState.setModel(JsonUtil.toTreeNodeModel("Heavy Processing" + StringUtil.repeat("...", chunks.size())));
                }

                protected void done() {
                    try {
                        final ViewStateModel vsm = get();
                        setViewStateModel(vsm);
                    } catch (IllegalArgumentException ex) {
                        Logger.getLogger(ViewStateTab.class.getName()).log(Level.INFO, ex.getMessage(), ex);
                        setViewStateModel(ILL_FORMAT_VIEW_STATE_MODEL);
                    } catch (Exception ex) {
                        Logger.getLogger(ViewStateTab.class.getName()).log(Level.WARNING, ex.getMessage(), ex);
                        setViewStateModel(EXCEPTION_VIEW_STATE_MODEL);
                    }                    
                }
            };
            swTree.execute();
        } catch (IllegalArgumentException ex) {
            setViewStateModel(ILL_FORMAT_VIEW_STATE_MODEL);
            Logger.getLogger(ViewStateTab.class.getName()).log(Level.INFO, ex.getMessage(), ex);
        } catch (Exception ex) {
            Logger.getLogger(ViewStateTab.class.getName()).log(Level.WARNING, ex.getMessage(), ex);
            setViewStateModel(EXCEPTION_VIEW_STATE_MODEL);
        }
    }

    public void clearViewState() {
        this.treeViewState.setModel(JsonUtil.toTreeNodeModel("viewState"));
        this.txtJSON.setText("");
    }

    private void setViewStateModel(ViewStateModel vsm) {
        DefaultTreeModel modelJSON = vsm.getViewStateModel();
        this.treeViewState.setModel(modelJSON);
        SwingUtil.allNodesChanged(this.treeViewState);
        expandJsonTree();
        this.txtJSON.setText(JsonUtil.prettyJson(vsm.getViewState().toJson(), true));
        this.txtJSON.setCaretPosition(0);
    }
       
    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return null;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnCollapse;
    private javax.swing.JButton btnExpand;
    private javax.swing.JPopupMenu.Separator jSeparator1;
    private javax.swing.JPanel pnlHeader;
    private javax.swing.JPanel pnlViewState;
    private javax.swing.JMenuItem popCollapseMenu;
    private javax.swing.JMenuItem popCopyMenu;
    private javax.swing.JMenuItem popExpandMenu;
    private javax.swing.JPopupMenu popMenu;
    private javax.swing.JScrollPane scrollJSON;
    private javax.swing.JScrollPane scrollViewState;
    private javax.swing.JTabbedPane tabViewStateView;
    private javax.swing.JTree treeViewState;
    private javax.swing.JTextArea txtJSON;
    // End of variables declaration//GEN-END:variables

    public void expandJsonTree() {
        TreePath selectionPath = this.treeViewState.getSelectionPath();
        if (selectionPath == null) {
            TreeModel model = this.treeViewState.getModel();
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) model.getRoot();
            selectionPath = new TreePath(root.getPath());
        }
        SwingUtil.expandAll(this.treeViewState, selectionPath);
    }

    public void collapseJsonTree() {
        TreePath selectionPath = this.treeViewState.getSelectionPath();
        if (selectionPath == null) {
            TreeModel model = this.treeViewState.getModel();
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) model.getRoot();
            selectionPath = new TreePath(root.getPath());
        }
        SwingUtil.collapseAll(this.treeViewState, selectionPath);
    }
    
    private static class ViewStateModel {
    
        private final ViewState viewState;
        private final DefaultTreeModel model;
        
        public ViewStateModel(ViewState viewState, String rootName) {
            this.viewState = viewState;
            this.model = (DefaultTreeModel)JsonUtil.toJsonTreeModel(viewState.toJson(), rootName);
        }
        
        public ViewState getViewState() {
            return viewState;
        }

        public DefaultTreeModel getViewStateModel() {
            return model;
        }
        
    }
    
}
