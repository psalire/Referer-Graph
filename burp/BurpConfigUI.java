package burp;

import java.awt.Component;
import java.awt.LayoutManager;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JFrame;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import java.io.File;

public class BurpConfigUI implements Runnable {
    private JPanel uiPanel = new JPanel();
    private GridBagConstraints uiGridConstraints = new GridBagConstraints();
    private Writer writer;
    private IBurpExtenderCallbacks callbacks;
    private HttpHandler httpHandler;
    private BurpExtender burpExtender;
    private String serverAddress = "localhost";
    private String serverPort = "8000";
    private String filename = "default.sqlite";
    private boolean isTrafficForwarded = false;
    private boolean isLimitInScope = true;
    private boolean isSaveTraffic = true;

    public BurpConfigUI(IBurpExtenderCallbacks callbacks, BurpExtender burpExtender, HttpHandler httpHandler, Writer writer) {
        this.callbacks = callbacks;
        this.burpExtender = burpExtender;
        this.httpHandler = httpHandler;
        this.writer = writer;
    }

    private void addComponentAtCoor(int x, int y, JComponent component) {
        this.uiGridConstraints.gridx = x;
        this.uiGridConstraints.gridy = y;
        this.uiPanel.add(component, this.uiGridConstraints);
    }

    @Override
    public void run() {
        GridBagLayout uiGridLayout = new GridBagLayout();
        uiPanel = new JPanel(uiGridLayout);

        JPanel uiAddressPortPanel = new JPanel(new FlowLayout());
        JTextField uiAddressText = new JTextField(this.httpHandler.getServerAddress(), 10);
        JTextField uiPortText = new JTextField(this.httpHandler.getServerPort(), 4);
        JLabel uiAddressLabel = new JLabel("Referer Graph Server (Address:Port):");
        uiAddressLabel.setLabelFor(uiAddressText);
        uiAddressPortPanel.add(uiAddressLabel);
        uiAddressPortPanel.add(uiAddressText);
        uiAddressPortPanel.add(uiPortText);

        JPanel uiFileChooserPanel = new JPanel(new FlowLayout());
        JLabel uiFileTextFieldLabel = new JLabel("Directory:");
        JTextField uiFileTextField = new JTextField(14);
        JButton uiFileChooserButton = new JButton("Browse...");
        uiFileTextFieldLabel.setLabelFor(uiFileTextField);
        uiFileTextField.setEditable(false);
        JFileChooser uiFileChooser = new JFileChooser();
        uiFileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        JFrame uiFrameFileChooser = new JFrame("Choose Directory");
        uiFrameFileChooser.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        uiFileChooserButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg) {
                writer.printlnOut("actionEvent: "+arg.paramString());
                int option = uiFileChooser.showDialog(uiFrameFileChooser, "Select");
                if (option == JFileChooser.APPROVE_OPTION) {
                    File file = uiFileChooser.getSelectedFile();
                    uiFileTextField.setText(file.getAbsolutePath());
                }
            }
        });
        uiFileTextField.setText(uiFileChooser.getCurrentDirectory().getAbsolutePath());
        uiFileChooserPanel.add(uiFileTextFieldLabel);
        uiFileChooserPanel.add(uiFileTextField);
        uiFileChooserPanel.add(uiFileChooserButton);

        // JPanel uiFilenamePanel = new JPanel(new FlowLayout());
        JLabel uiFilenameTextFieldLabel = new JLabel("Filename:");
        JTextField uiFilenameTextField = new JTextField(8);
        uiFilenameTextFieldLabel.setLabelFor(uiFilenameTextField);
        uiFilenameTextField.setText(this.filename);
        uiFileChooserPanel.add(uiFilenameTextFieldLabel);
        uiFileChooserPanel.add(uiFilenameTextField);

        JCheckBox uiInScopeCheckbox = new JCheckBox("Limit forwarding to Burp scope", this.isLimitInScope);
        JCheckBox uiSaveToSqliteCheckbox = new JCheckBox("Save traffic to Sqlite file", this.isSaveTraffic);
        uiSaveToSqliteCheckbox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg) {
                writer.printlnOut("actionEvent: "+arg.paramString());
                uiFileTextFieldLabel.setEnabled(uiSaveToSqliteCheckbox.isSelected());
                uiFileTextField.setEnabled(uiSaveToSqliteCheckbox.isSelected());
                uiFileChooserButton.setEnabled(uiSaveToSqliteCheckbox.isSelected());
                uiFilenameTextFieldLabel.setEnabled(uiSaveToSqliteCheckbox.isSelected());
                uiFilenameTextField.setEnabled(uiSaveToSqliteCheckbox.isSelected());
            }
        });

        JButton uiApplyButton = new JButton();
        uiApplyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg) {
                writer.printlnOut("actionEvent: "+arg.paramString());
                writer.printlnOut("Address: "+uiAddressText.getText());
                writer.printlnOut("Port: "+uiPortText.getText());
                writer.printlnOut("Limit Scope: "+uiInScopeCheckbox.isSelected());
                isLimitInScope = uiInScopeCheckbox.isSelected();
                isSaveTraffic = uiSaveToSqliteCheckbox.isSelected();
                httpHandler.setRequestEndpoint(uiAddressText.getText(), uiPortText.getText());
            }
        });
        uiApplyButton.setText("Apply");

        JToggleButton uiOnOffButton = new JToggleButton();
        uiOnOffButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg) {
                writer.printlnOut("actionEvent: "+arg.paramString());
                isTrafficForwarded = !isTrafficForwarded;
                String forwardTrafficStatus = isTrafficForwarded ? "ON" : "OFF";
                uiOnOffButton.setText("Forward Traffic: "+forwardTrafficStatus);
                uiApplyButton.setEnabled(isTrafficForwarded);
            }
        });

        addComponentAtCoor(0, 0, uiOnOffButton);
        addComponentAtCoor(0, 1, uiAddressPortPanel);
        addComponentAtCoor(0, 2, uiInScopeCheckbox);
        addComponentAtCoor(0, 3, uiSaveToSqliteCheckbox);
        addComponentAtCoor(0, 4, uiFileChooserPanel);
        // addComponentAtCoor(0, 5, uiFilenamePanel);
        addComponentAtCoor(0, 6, uiApplyButton);

        callbacks.customizeUiComponent(uiPanel);

        // add the custom tab to Burp's UI
        callbacks.addSuiteTab(burpExtender);

        uiOnOffButton.doClick(); // Turn on forwarding
    }
    public JPanel getUiPanel() {
        return this.uiPanel;
    }
    public String getServerAddress() {
        return this.serverAddress;
    }
    public String getServerPort() {
        return this.serverPort;
    }
    public boolean getIsTrafficForwarded() {
        return this.isTrafficForwarded;
    }
    public boolean getIsLimitInScope() {
        return this.isLimitInScope;
    }
    public boolean getIsSaveTraffic() {
        return this.isSaveTraffic;
    }
}
