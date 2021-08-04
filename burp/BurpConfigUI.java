package burp;

import java.awt.Component;
import java.awt.LayoutManager;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.event.ActionListener;
import java.awt.event.KeyListener;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyAdapter;
import javax.swing.JFrame;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JSeparator;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileFilter;
import java.io.File;

public class BurpConfigUI implements Runnable {
    private JPanel uiPanel = new JPanel();
    private JButton uiApplyButton = new JButton("Apply");
    private GridBagConstraints uiGridConstraints = new GridBagConstraints();
    private Writer writer;
    private IBurpExtenderCallbacks callbacks;
    private HttpHandler httpHandler;
    private BurpExtender burpExtender;
    private String serverAddress = "localhost";
    private String serverPort = "8000";
    private File sqliteFile;
    private boolean isTrafficForwarded = false;
    private boolean isLimitInScope = true;
    private boolean isSaveTraffic = false;
    private boolean isNo404TrafficForwarded = false;

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
    protected void indicateChangesMade() {
        this.uiApplyButton.setText("*Apply");
    }
    protected void clearChangesMade() {
        this.uiApplyButton.setText("Apply");
    }

    // Helper classes, decorators
    class NotifyOnKeypress extends KeyAdapter {
        public void keyReleased(KeyEvent e) {
            indicateChangesMade();
        }
    }
    class LoggedActionListener extends ActionListenerDecorator {
        public LoggedActionListener(ActionListener actionListener) {
            super(actionListener);
        }
        @Override
        public void decorator(ActionEvent arg) {
            writer.printlnOut("actionEvent: "+arg.paramString());
        }
    }
    class InidcateChangesActionListener extends ActionListenerDecorator {
        public InidcateChangesActionListener(ActionListener actionListener) {
            super(actionListener);
        }
        @Override
        public void decorator(ActionEvent arg) {
            indicateChangesMade();
        }
    }

    @Override
    public void run() {
        GridBagLayout uiGridLayout = new GridBagLayout();
        uiPanel = new JPanel(uiGridLayout);

        // Address:Port fields
        JPanel uiAddressPortPanel = new JPanel(new FlowLayout());
        JTextField uiAddressText = new JTextField(this.httpHandler.getServerAddress(), 10);
        JTextField uiPortText = new JTextField(this.httpHandler.getServerPort(), 4);
        JLabel uiAddressLabel = new JLabel("Referer Graph Server:");
        uiAddressText.addKeyListener(new NotifyOnKeypress());
        uiPortText.addKeyListener(new NotifyOnKeypress());
        uiAddressLabel.setLabelFor(uiAddressText);
        uiAddressPortPanel.add(uiAddressLabel);
        uiAddressPortPanel.add(uiAddressText);
        uiAddressPortPanel.add(new JLabel(":"));
        uiAddressPortPanel.add(uiPortText);

        // SQLite file chooser
        JPanel uiFileChooserPanel = new JPanel(new FlowLayout());
        JLabel uiFileTextFieldLabel = new JLabel("Filepath:");
        JTextField uiFileTextField = new JTextField(14);
        JButton uiFileChooserButton = new JButton("Browse...");
        uiFileTextFieldLabel.setLabelFor(uiFileTextField);
        uiFileTextField.setEditable(false);
        JFileChooser uiFileChooser = new JFileChooser();
        JFrame uiFrameFileChooser = new JFrame("SQLite File Chooser");
        uiFrameFileChooser.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        uiFileChooserButton.addActionListener(
            new LoggedActionListener(
                new InidcateChangesActionListener(
                    new ActionListener() {
                        public void actionPerformed(ActionEvent arg) {
                            int option = uiFileChooser.showDialog(uiFrameFileChooser, "Select");
                            if (option == JFileChooser.APPROVE_OPTION) {
                                sqliteFile = uiFileChooser.getSelectedFile();
                                uiFileTextField.setText(getFilepath()+File.separator+getFilename());
                            }
                        }
                    }
                )
            )
        );
        String defaultSqliteFilepath = uiFileChooser.getCurrentDirectory().getAbsolutePath()+File.separator+"default.sqlite";
        uiFileTextField.setText(defaultSqliteFilepath);
        this.sqliteFile = new File(defaultSqliteFilepath);
        uiFileChooser.setFileFilter(new FileFilter() {
            public boolean accept(File pathname) {
                String absPath = pathname.getAbsolutePath();
                return absPath.endsWith(".sqlite");
            }
            public String getDescription() {
                return ".sqlite";
            }
        });
        uiFileChooserPanel.add(uiFileTextFieldLabel);
        uiFileChooserPanel.add(uiFileTextField);
        uiFileChooserPanel.add(uiFileChooserButton);

        // Send traffic buttons
        JButton uiSendSqliteTrafficButton = new JButton("Send SQLite history");
        JButton uiSendBurpTrafficButton = new JButton("Send ALL Burp Proxy history");
        uiSendSqliteTrafficButton.addActionListener(
            new LoggedActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent arg) {
                        burpExtender.sendSqliteHistory();
                    }
                }
            )
        );
        uiSendBurpTrafficButton.addActionListener(
            new LoggedActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent arg) {
                        burpExtender.sendAllProxyHistory();
                    }
                }
            )
        );

        // Checkboxes
        JCheckBox uiInScopeCheckbox = new JCheckBox("Limit forwarding to Burp scope", this.isLimitInScope);
        uiInScopeCheckbox.addActionListener(
            new LoggedActionListener(
                new InidcateChangesActionListener(
                    new ActionListener() {
                        public void actionPerformed(ActionEvent arg) {}
                    }
                )
            )
        );
        JCheckBox uiSaveToSqliteCheckbox = new JCheckBox("Save traffic to Sqlite file", this.isSaveTraffic);
        uiSaveToSqliteCheckbox.addActionListener(
            new LoggedActionListener(
                new InidcateChangesActionListener(
                    new ActionListener() {
                        public void actionPerformed(ActionEvent arg) {
                            boolean isCheckboxEnabled = uiSaveToSqliteCheckbox.isSelected();
                            uiFileTextFieldLabel.setEnabled(isCheckboxEnabled);
                            uiFileTextField.setEnabled(isCheckboxEnabled);
                            uiFileChooserButton.setEnabled(isCheckboxEnabled);
                        }
                    }
                )
            )
        );
        JCheckBox uiNoForward404Checkbox = new JCheckBox("Don't forward 404 traffic", this.isNo404TrafficForwarded);
        uiNoForward404Checkbox.addActionListener(
            new LoggedActionListener(
                new InidcateChangesActionListener(
                    new ActionListener() {
                        public void actionPerformed(ActionEvent arg) {}
                    }
                )
            )
        );
        uiFileTextFieldLabel.setEnabled(this.isSaveTraffic);
        uiFileTextField.setEnabled(this.isSaveTraffic);
        uiFileChooserButton.setEnabled(this.isSaveTraffic);
        uiSendSqliteTrafficButton.setEnabled(this.isSaveTraffic);

        // Apply button
        this.uiApplyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg) {
                clearChangesMade();
                writer.printlnOut("actionEvent: "+arg.paramString());
                writer.printlnOut("Address: "+uiAddressText.getText());
                writer.printlnOut("Port: "+uiPortText.getText());
                writer.printlnOut("Limit Scope: "+uiInScopeCheckbox.isSelected());
                writer.printlnOut("Filepath: "+getFullFilepath());
                isLimitInScope = uiInScopeCheckbox.isSelected();
                isNo404TrafficForwarded = uiNoForward404Checkbox.isSelected();
                isSaveTraffic = uiSaveToSqliteCheckbox.isSelected();
                httpHandler.setRequestEndpoint(uiAddressText.getText(), uiPortText.getText());
                if (uiSaveToSqliteCheckbox.isSelected()) {
                    uiSendSqliteTrafficButton.setEnabled(true);
                    String requestBody = writer.jsonToString(
                        JsonHelper.getSavejson(getFilepath(), getFilename(), writer).build()
                    );
                    httpHandler.postJson(requestBody, httpHandler.getUpdateFilepathEndpointURI());
                }
                else {
                    uiSendSqliteTrafficButton.setEnabled(false);
                }
            }
        });

        // Traffic on/off toggle button
        JToggleButton uiOnOffButton = new JToggleButton();
        uiOnOffButton.addActionListener(new LoggedActionListener(
            new ActionListener() {
                public void actionPerformed(ActionEvent arg) {
                    isTrafficForwarded = !isTrafficForwarded;
                    String forwardTrafficStatus = isTrafficForwarded ? "ON" : "OFF";
                    uiOnOffButton.setText("Forward Traffic: "+forwardTrafficStatus);
                    uiApplyButton.setEnabled(isTrafficForwarded);
                    uiSendSqliteTrafficButton.setEnabled(uiSaveToSqliteCheckbox.isSelected() && isTrafficForwarded);
                    uiSendBurpTrafficButton.setEnabled(isTrafficForwarded);
                }
            }
        ));

        JLabel uiDivider = new JLabel("------------------------------------------");
        uiDivider.setEnabled(false);
        JComponent[] componentsOrdered = {
            uiOnOffButton,
            uiAddressPortPanel,
            uiInScopeCheckbox,
            uiNoForward404Checkbox,
            uiSaveToSqliteCheckbox,
            uiFileChooserPanel,
            this.uiApplyButton,
            uiDivider,
            new JLabel("On-demand:"),
            uiSendSqliteTrafficButton,
            uiSendBurpTrafficButton
        };
        for (int i=0; i<componentsOrdered.length; i++) {
            addComponentAtCoor(0, i, componentsOrdered[i]);
        }

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
    public String getFilename() {
        return sqliteFile.getName();
    }
    public String getFilepath() {
        return sqliteFile.getParent();
    }
    public String getFullFilepath() {
        return getFilepath()+File.separator+getFilename();
    }
    public boolean getIsTrafficForwarded() {
        return this.isTrafficForwarded;
    }
    public boolean getIsLimitInScope() {
        return this.isLimitInScope;
    }
    public boolean getIsNo404TrafficForwaded() {
        return this.isNo404TrafficForwarded;
    }
    public boolean getIsSaveTraffic() {
        return this.isSaveTraffic;
    }
}
