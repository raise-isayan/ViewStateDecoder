package yagura.view;

import burp.ITab;
import java.awt.BorderLayout;
import java.awt.Component;

/**
 *
 * @author isayan
 */
public class ViewStateDecoderTab extends javax.swing.JPanel implements ITab {

    /**
     * Creates new form ViewStateView
     */
    public ViewStateDecoderTab() {
        initComponents();
        customizeComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        pnlViewStateDecoder = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtViewState = new javax.swing.JTextArea();
        btnDecode = new javax.swing.JButton();
        btnClear = new javax.swing.JButton();
        pnlViewStateTab = new javax.swing.JPanel();

        setLayout(new java.awt.BorderLayout());

        txtViewState.setColumns(20);
        txtViewState.setLineWrap(true);
        txtViewState.setRows(5);
        jScrollPane1.setViewportView(txtViewState);

        btnDecode.setText("Decode");
        btnDecode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecodeActionPerformed(evt);
            }
        });

        btnClear.setText("Clear");
        btnClear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnClearActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlViewStateDecoderLayout = new javax.swing.GroupLayout(pnlViewStateDecoder);
        pnlViewStateDecoder.setLayout(pnlViewStateDecoderLayout);
        pnlViewStateDecoderLayout.setHorizontalGroup(
            pnlViewStateDecoderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlViewStateDecoderLayout.createSequentialGroup()
                .addGap(5, 5, 5)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 549, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(pnlViewStateDecoderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(btnDecode, javax.swing.GroupLayout.PREFERRED_SIZE, 115, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnClear, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 115, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        pnlViewStateDecoderLayout.setVerticalGroup(
            pnlViewStateDecoderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlViewStateDecoderLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlViewStateDecoderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1)
                    .addGroup(pnlViewStateDecoderLayout.createSequentialGroup()
                        .addComponent(btnDecode)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnClear)
                        .addGap(0, 71, Short.MAX_VALUE)))
                .addContainerGap())
        );

        add(pnlViewStateDecoder, java.awt.BorderLayout.NORTH);

        pnlViewStateTab.setLayout(new java.awt.BorderLayout());
        add(pnlViewStateTab, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents

    public String getViewStateValue() {
        String viewState = this.txtViewState.getText().trim();
        return viewState;
    }
    
    
    private void btnDecodeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDecodeActionPerformed
        String viewStateValue = getViewStateValue();        
        if (viewStateValue.length() > 0) {
            this.viewStateTab.setViewState(viewStateValue);
        }
    }//GEN-LAST:event_btnDecodeActionPerformed

    private void btnClearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnClearActionPerformed
        this.viewStateTab.clearViewState();        
    }//GEN-LAST:event_btnClearActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnClear;
    private javax.swing.JButton btnDecode;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JPanel pnlViewStateDecoder;
    private javax.swing.JPanel pnlViewStateTab;
    private javax.swing.JTextArea txtViewState;
    // End of variables declaration//GEN-END:variables
    
    private final ViewStateTab viewStateTab = new ViewStateTab();
    
    private void customizeComponents() {
        this.txtViewState.setWrapStyleWord(false);
        this.pnlViewStateTab.add(this.viewStateTab, BorderLayout.CENTER);
    }

    @Override
    public String getTabCaption() {
        return "ViewStateDecoder";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }
}
